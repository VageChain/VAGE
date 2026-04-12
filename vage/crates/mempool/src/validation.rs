use anyhow::{bail, Result};
use parking_lot::Mutex;
use primitive_types::U256;
use rayon::prelude::*;
use rayon::{ThreadPool, ThreadPoolBuilder};
use std::collections::HashSet;
use std::sync::Arc;
use vage_state::StateDb;
use vage_types::{Hash, Transaction};

pub const MAX_TX_SIZE: usize = 128 * 1024;

#[derive(Clone, Debug)]
pub struct TxValidationConfig {
    pub min_gas_price: U256,
    pub max_gas_limit: u64,
    pub max_transaction_size: usize,
    pub max_future_nonce_gap: u64,
    /// The expected chain_id for this network. Transactions with a different or absent
    /// chain_id are rejected to prevent cross-chain replay attacks.
    pub chain_id: u64,
    seen_transactions: Arc<Mutex<HashSet<Hash>>>,
}

impl Default for TxValidationConfig {
    fn default() -> Self {
        Self {
            min_gas_price: U256::from(1u64),
            max_gas_limit: 30_000_000,
            max_transaction_size: MAX_TX_SIZE,
            max_future_nonce_gap: 1024,
            chain_id: 1,
            seen_transactions: Arc::new(Mutex::new(HashSet::new())),
        }
    }
}

/// Validates transactions before they enter the mempool.
pub struct TxValidator {
    state: Arc<StateDb>,
    config: TxValidationConfig,
    /// Dedicated rayon pool for parallel signature / batch validation.
    rayon_pool: Arc<ThreadPool>,
}

impl TxValidator {
    pub fn new(state: Arc<StateDb>, config: TxValidationConfig) -> Self {
        let rayon_pool = ThreadPoolBuilder::new()
            .thread_name(|i| format!("mempool-validator-{}", i))
            .build()
            .expect("mempool validation rayon pool");
        Self {
            state,
            config,
            rayon_pool: Arc::new(rayon_pool),
        }
    }

    /// Full validation: structural checks + duplicate detection.
    /// Use this when a transaction first arrives at the mempool.
    pub fn validate_transaction(&self, tx: &Transaction) -> Result<()> {
        self.verify_chain_id(tx)?;
        self.reject_malformed_transactions(tx)?;
        self.verify_transaction_signature(tx)?;
        self.verify_sender_address(tx)?;
        self.verify_nonce_correctness(tx)?;
        self.verify_sufficient_balance(tx)?;
        self.verify_gas_limit(tx)?;
        self.verify_gas_price_threshold(tx)?;
        self.verify_transaction_size(tx)?;
        self.reject_expired_transactions(tx)?;
        self.reject_duplicate_transactions(tx)?;
        Ok(())
    }

    /// Subset of checks safe to repeat at block-selection time
    /// (skips duplicate detection so the same tx can be re-evaluated).
    pub fn validate_transaction_for_selection(&self, tx: &Transaction) -> Result<()> {
        self.reject_malformed_transactions(tx)?;
        self.verify_transaction_signature(tx)?;
        self.verify_sender_address(tx)?;
        self.verify_nonce_correctness(tx)?;
        self.verify_sufficient_balance(tx)?;
        self.verify_gas_limit(tx)?;
        self.verify_gas_price_threshold(tx)?;
        self.verify_transaction_size(tx)?;
        self.reject_expired_transactions(tx)?;
        Ok(())
    }

    /// Reject transactions whose chain_id does not match this network's chain_id.
    /// Prevents replay of transactions from other chains.
    fn verify_chain_id(&self, tx: &Transaction) -> Result<()> {
        match tx.chain_id {
            None => bail!("transaction missing chain_id (replay protection required)"),
            Some(id) if id != self.config.chain_id => bail!(
                "chain_id mismatch: expected {}, got {}",
                self.config.chain_id,
                id
            ),
            _ => Ok(()),
        }
    }

    /// Alias used by Mempool.
    pub fn validate(&self, tx: &Transaction) -> Result<()> {
        self.validate_transaction(tx)
    }

    /// Verify the signatures of a batch of transactions in parallel using the
    /// rayon thread pool.  Returns one `Result<()>` per input transaction.
    pub fn parallel_signature_verification(&self, txs: &[Transaction]) -> Vec<Result<()>> {
        self.rayon_pool.install(|| {
            txs.par_iter()
                .map(|tx| self.verify_transaction_signature(tx))
                .collect()
        })
    }

    /// Validate a batch of transactions with two phases:
    /// 1. Parallelisable pre-checks (signature, address, gas, size) via rayon.
    /// 2. Sequential state-dependent checks (nonce, balance, TTL, duplicates).
    ///
    /// Returns one `Result<()>` per input transaction.
    pub fn batch_transaction_validation(&self, txs: &[Transaction]) -> Vec<Result<()>> {
        // Phase 1: parallel structural pre-checks.
        let precheck: Vec<Result<()>> = self.rayon_pool.install(|| {
            txs.par_iter()
                .map(|tx| {
                    self.reject_malformed_transactions(tx)?;
                    self.verify_transaction_signature(tx)?;
                    self.verify_sender_address(tx)?;
                    self.verify_gas_limit(tx)?;
                    self.verify_gas_price_threshold(tx)?;
                    self.verify_transaction_size(tx)?;
                    Ok(())
                })
                .collect()
        });

        // Phase 2: sequential state-dependent checks.
        txs.iter()
            .zip(precheck)
            .map(|(tx, pre)| {
                pre?;
                self.verify_nonce_correctness(tx)?;
                self.verify_sufficient_balance(tx)?;
                self.reject_expired_transactions(tx)?;
                self.reject_duplicate_transactions(tx)?;
                Ok(())
            })
            .collect()
    }

    //  Individual checks

    /// Verify the ECDSA/BLS signature matches the declared sender.
    fn verify_transaction_signature(&self, tx: &Transaction) -> Result<()> {
        if !tx.verify_signature()? {
            bail!("invalid transaction signature");
        }
        Ok(())
    }

    /// Reject transactions whose `from` field is the zero address.
    fn verify_sender_address(&self, tx: &Transaction) -> Result<()> {
        if tx.from.is_zero() {
            bail!("sender address cannot be zero");
        }
        Ok(())
    }

    /// Reject nonces that are already used (too low) or unreachably far ahead.
    fn verify_nonce_correctness(&self, tx: &Transaction) -> Result<()> {
        let account = self.state.get_account(&tx.from)?.unwrap_or_default();
        if tx.nonce < account.nonce {
            bail!(
                "nonce too low (expected at least {}, got {})",
                account.nonce,
                tx.nonce
            );
        }
        let max_nonce = account
            .nonce
            .saturating_add(self.config.max_future_nonce_gap);
        if tx.nonce > max_nonce {
            bail!(
                "nonce too far in future (expected at most {}, got {})",
                max_nonce,
                tx.nonce
            );
        }
        Ok(())
    }

    /// Reject if the sender cannot cover `value + gas_price * gas_limit`.
    fn verify_sufficient_balance(&self, tx: &Transaction) -> Result<()> {
        let account = self.state.get_account(&tx.from)?.unwrap_or_default();
        let total_cost = tx.value.saturating_add(tx.gas_cost());
        if account.balance < total_cost {
            bail!("insufficient balance for transaction value and gas");
        }
        Ok(())
    }

    /// Reject zero gas limits and limits above the configured maximum.
    fn verify_gas_limit(&self, tx: &Transaction) -> Result<()> {
        if tx.gas_limit == 0 {
            bail!("gas limit must be greater than zero");
        }
        if tx.gas_limit > self.config.max_gas_limit {
            bail!(
                "gas limit exceeds configured maximum ({} > {})",
                tx.gas_limit,
                self.config.max_gas_limit
            );
        }
        Ok(())
    }

    /// Reject transactions whose gas price is below the configured floor.
    fn verify_gas_price_threshold(&self, tx: &Transaction) -> Result<()> {
        if tx.gas_price < self.config.min_gas_price {
            bail!("gas price below configured threshold");
        }
        Ok(())
    }

    /// Reject transactions whose serialised size exceeds the configured limit.
    fn verify_transaction_size(&self, tx: &Transaction) -> Result<()> {
        let size = tx.size_bytes();
        if size > self.config.max_transaction_size {
            bail!(
                "transaction size exceeds maximum ({} > {})",
                size,
                self.config.max_transaction_size
            );
        }
        Ok(())
    }

    /// Reject a transaction whose hash was already accepted in this session.
    fn reject_duplicate_transactions(&self, tx: &Transaction) -> Result<()> {
        let hash = tx.hash();
        let mut seen = self.config.seen_transactions.lock();
        if seen.contains(&hash) {
            bail!("duplicate transaction");
        }
        seen.insert(hash);
        Ok(())
    }

    /// Reject a transaction whose nonce is already behind the current account nonce.
    fn reject_expired_transactions(&self, tx: &Transaction) -> Result<()> {
        let account = self.state.get_account(&tx.from)?.unwrap_or_default();
        if tx.nonce < account.nonce {
            bail!("expired transaction nonce");
        }
        Ok(())
    }

    /// Reject transactions that fail basic structural invariants:
    /// - must pass `Transaction::validate_basic`
    /// - must carry a signature
    /// - contract-creation transactions must include init code
    fn reject_malformed_transactions(&self, tx: &Transaction) -> Result<()> {
        tx.validate_basic()?;
        if tx.signature.is_none() {
            bail!("transaction must be signed");
        }
        if tx.to.is_none() && tx.data.is_empty() {
            bail!("contract creation transaction must contain init code");
        }
        Ok(())
    }
}

pub type TransactionValidator = TxValidator;
