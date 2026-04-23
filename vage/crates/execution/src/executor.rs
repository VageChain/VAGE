use crate::gas::{self, GasMeter};
use crate::parallel::executor::{
    BlockExecutionPipeline, ParallelExecutorTask, PipelineConfig, RawOutcome,
};
use crate::runtime::ExecutionResult;
use anyhow::{bail, Result};
use primitive_types::U256;
use rayon::prelude::*;
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::info;
use vage_block::Block;
use vage_state::{ReadOnlyStateSnapshot, StateBatchOp, StateDB};
use vage_storage::{Schema, StorageEngine};
use vage_types::{Account, Log, Receipt, Transaction};

type AccessSet = (Vec<Vec<u8>>, Vec<Vec<u8>>);

#[derive(Clone, Debug, Default, Serialize)]
pub struct ExecutionMetrics {
    pub executed_transactions: usize,
    pub executed_blocks: usize,
    pub failed_transactions: usize,
    pub gas_used: u64,
    pub receipts_collected: usize,
}

#[derive(Clone, Debug)]
pub struct TransactionDependency {
    pub index: usize,
    pub read_set: Vec<Vec<u8>>,
    pub write_set: Vec<Vec<u8>>,
    pub depends_on: Vec<usize>,
}

#[derive(Clone, Debug)]
pub struct OptimisticExecutionResult {
    pub index: usize,
    pub tx_hash: [u8; 32],
    pub receipt: Option<Receipt>,
    pub execution_result: ExecutionResult,
    pub snapshot: ReadOnlyStateSnapshot,
    pub read_set: Vec<Vec<u8>>,
    pub write_set: Vec<Vec<u8>>,
    pub conflicted: bool,
}

pub trait TransactionSource {
    fn pull_transactions(&self, limit: usize) -> Result<Vec<Transaction>>;
    fn acknowledge_transactions(&self, hashes: &[[u8; 32]]) -> Result<()>;
}

pub trait ConsensusSink {
    fn submit_finalized_block(&self, block: Block) -> Result<()>;
}

pub struct Executor {
    state: Arc<StateDB>,
    gas_meter: Mutex<GasMeter>,
    receipts: Mutex<Vec<Receipt>>,
    metrics: Mutex<ExecutionMetrics>,
}

const EXECUTION_RESULT_PREFIX: &[u8] = b"execution:result:";
const BLOCK_RECEIPTS_ROOT_PREFIX: &[u8] = b"execution:block:receipts_root:";
const BLOCK_STATE_ROOT_PREFIX: &[u8] = b"execution:block:state_root:";

impl Executor {
    pub fn new(state_db: Arc<StateDB>) -> Self {
        Self {
            state: state_db,
            gas_meter: Mutex::new(GasMeter::default()),
            receipts: Mutex::new(Vec::new()),
            metrics: Mutex::new(ExecutionMetrics::default()),
        }
    }

    pub fn execute_transaction(&self, tx: &Transaction) -> Result<Receipt> {
        self.execute_pipeline(tx)
    }

    pub fn execute_transactions(&self, transactions: Vec<Transaction>) -> Result<Vec<Receipt>> {
        let mut receipts = Vec::with_capacity(transactions.len());
        for tx in transactions {
            receipts.push(self.execute_transaction(&tx)?);
        }
        Ok(receipts)
    }

    pub fn execute_block(&self, block: Block) -> Result<[u8; 32]> {
        self.execute_block_pipeline(block)
    }

    pub fn receive_transactions_from_mempool<T: TransactionSource>(
        &self,
        source: &T,
        limit: usize,
    ) -> Result<Vec<Transaction>> {
        source.pull_transactions(limit)
    }

    pub fn produce_block_from_transactions(
        &self,
        mut block: Block,
        transactions: Vec<Transaction>,
    ) -> Result<Block> {
        block.body.transactions = transactions;
        let receipts = self.execute_transactions(block.body.transactions.clone())?;
        block.body.receipts = receipts;
        block.header.tx_root = block.body.compute_tx_root();
        block.header.receipts_root = block.body.compute_receipt_root();
        block.header.state_root = self.state.update_state_root()?;
        Ok(block)
    }

    pub fn pass_finalized_block_to_consensus<C: ConsensusSink>(
        &self,
        sink: &C,
        block: Block,
    ) -> Result<()> {
        sink.submit_finalized_block(block)
    }

    pub fn execute_block_pipeline(&self, block: Block) -> Result<[u8; 32]> {
        self.validate_block_header(&block)?;
        let previous_root = self.load_previous_state_root();
        self.validate_block_transactions(&block)?;
        self.execute_system_transactions()?;

        let speculative_summary = self.run_isolated_parallel_analysis(&block)?;

        info!(
            height = block.header.height,
            tx_count = block.body.transactions.len(),
            speculative_conflicts = speculative_summary.0,
            speculative_rounds = speculative_summary.1,
            "block execution completed with isolated speculative analysis and canonical commit path"
        );

        // Use canonical execution results for block validation and persistence.
        // The parallel engine currently provides speculative scheduling and
        // conflict metrics, while final block artifacts must come from the
        // committed execution path to preserve deterministic receipts/state roots.
        let receipts = self.execute_transactions_sequentially(&block)?;
        let receipts_root = self.compute_receipts_merkle_root(&receipts);
        let computed_state_root = self.state.state_root();

        if block.header.receipts_root != receipts_root {
            bail!("computed receipts root does not match block header");
        }

        if block.header.state_root != computed_state_root {
            bail!("computed state root does not match block header");
        }

        let committed_root = self.commit_block_state()?;
        self.store_block_execution_results(
            block.header.height,
            &receipts,
            receipts_root,
            committed_root,
        )?;

        self.metrics.lock().unwrap().executed_blocks += 1;
        let _ = self.verify_state_root(previous_root)?;

        Ok(committed_root)
    }

    pub fn execute_from_mempool_to_consensus<T: TransactionSource, C: ConsensusSink>(
        &self,
        source: &T,
        sink: &C,
        block: Block,
        limit: usize,
    ) -> Result<Block> {
        let transactions = self.receive_transactions_from_mempool(source, limit)?;
        let finalized_block = self.produce_block_from_transactions(block, transactions)?;

        let tx_hashes: Vec<[u8; 32]> = finalized_block
            .body
            .transactions
            .iter()
            .map(Transaction::hash)
            .collect();

        self.pass_finalized_block_to_consensus(sink, finalized_block.clone())?;
        source.acknowledge_transactions(&tx_hashes)?;
        Ok(finalized_block)
    }

    pub fn apply_receipts(&self, receipts: Vec<Receipt>) -> Result<()> {
        let mut stored = self.receipts.lock().unwrap();
        stored.extend(receipts);
        self.metrics.lock().unwrap().receipts_collected = stored.len();
        Ok(())
    }

    pub fn reset_state(&self, snapshot: u64) -> Result<[u8; 32]> {
        self.state.load_snapshot(snapshot)
    }

    pub fn commit_state(&self) -> Result<[u8; 32]> {
        self.state.commit()
    }

    pub fn rollback_state(&self) -> Result<[u8; 32]> {
        self.state.rollback()
    }

    pub fn collect_receipts(&self) -> Vec<Receipt> {
        self.receipts.lock().unwrap().clone()
    }

    pub fn execute_system_transactions(&self) -> Result<Vec<Receipt>> {
        Ok(Vec::new())
    }

    pub fn validate_block_transactions(&self, block: &Block) -> Result<()> {
        block.validate_basic()?;
        for tx in &block.body.transactions {
            self.pre_execution_checks(tx)?;
        }
        Ok(())
    }

    pub fn verify_state_root(&self, previous_root: [u8; 32]) -> Result<bool> {
        self.state.verify_state_root(previous_root)
    }

    pub fn generate_block_receipts(&self, block: &Block) -> Result<Vec<Receipt>> {
        let mut receipts = Vec::with_capacity(block.body.transactions.len());
        for tx in &block.body.transactions {
            receipts.push(self.execute_transaction(tx)?);
        }
        Ok(receipts)
    }

    pub fn compute_block_state_root(&self) -> [u8; 32] {
        self.state.state_root()
    }

    pub fn execute_pipeline(&self, tx: &Transaction) -> Result<Receipt> {
        self.pre_execution_checks(tx)?;
        self.verify_transaction_signature(tx)?;

        let mut sender = self.load_sender_account_state(tx)?;
        let mut recipient = self.load_recipient_account_state(tx)?;

        self.check_nonce_correctness(tx, &sender)?;
        self.validate_gas_limit(tx)?;

        let upfront_gas_fee = self.deduct_upfront_gas_fee(&mut sender, tx)?;
        self.perform_transfer_or_contract_execution(tx, &mut sender, recipient.as_mut())?;
        self.update_sender_nonce(&mut sender);

        sender.validate()?;
        self.state.update_account(&tx.from, &sender)?;
        if let (Some(address), Some(account)) = (tx.to, recipient.as_ref()) {
            account.validate()?;
            self.state.update_account(&address, account)?;
        }

        let intrinsic_gas = gas::calculate_intrinsic_gas(&tx.data);
        let refund = self.refund_unused_gas(&tx.from, tx, upfront_gas_fee, intrinsic_gas)?;
        let mut receipt = self.generate_execution_receipt(tx, intrinsic_gas)?;
        let logs = self.emit_execution_logs(tx, intrinsic_gas, refund);
        receipt.logs = logs;

        self.post_execution_updates(tx)?;
        self.commit_state()?;

        {
            let mut gas_meter = self.gas_meter.lock().unwrap();
            gas_meter.gas_used = gas_meter.gas_used.saturating_add(intrinsic_gas);
            gas_meter.gas_limit = gas_meter.gas_limit.saturating_add(tx.gas_limit);
        }

        self.receipts.lock().unwrap().push(receipt.clone());
        let mut metrics = self.metrics.lock().unwrap();
        metrics.executed_transactions += 1;
        metrics.gas_used = metrics.gas_used.saturating_add(intrinsic_gas);
        metrics.receipts_collected = self.receipts.lock().unwrap().len();

        Ok(receipt)
    }

    pub fn pre_execution_checks(&self, tx: &Transaction) -> Result<()> {
        tx.validate_basic()?;
        let sender = self
            .state
            .get_account(&tx.from)?
            .ok_or_else(|| anyhow::anyhow!("sender account does not exist: {}", tx.from))?;
        self.check_nonce_correctness(tx, &sender)?;
        self.validate_account_existence(tx)?;
        self.validate_gas_limit(tx)?;
        Ok(())
    }

    pub fn post_execution_updates(&self, _tx: &Transaction) -> Result<()> {
        self.state.update_state_root()?;
        Ok(())
    }

    pub fn detect_execution_failure(&self) -> bool {
        self.metrics.lock().unwrap().failed_transactions > 0
    }

    pub fn parallel_execute_batch(&self, tx_batch: Vec<Transaction>) -> Result<Vec<Receipt>> {
        let prechecked: Result<Vec<Transaction>> = tx_batch
            .par_iter()
            .map(|tx| {
                self.pre_execution_checks(tx)?;
                Ok(tx.clone())
            })
            .collect();

        let transactions = prechecked?;
        let dependencies = self.detect_transaction_dependencies(&transactions);
        let optimistic_results =
            self.optimistic_execute_transactions(&transactions, &dependencies)?;
        self.commit_optimistic_results(&transactions, optimistic_results)
    }

    pub fn execution_metrics(&self) -> ExecutionMetrics {
        self.metrics.lock().unwrap().clone()
    }

    pub fn detect_transaction_dependencies(
        &self,
        transactions: &[Transaction],
    ) -> Vec<TransactionDependency> {
        let access_sets: Vec<AccessSet> = transactions
            .iter()
            .map(|tx| {
                let read_set = self.transaction_read_set(tx);
                let write_set = self.transaction_write_set(tx);
                (read_set, write_set)
            })
            .collect();

        access_sets
            .iter()
            .enumerate()
            .map(|(index, (read_set, write_set))| {
                let depends_on = access_sets
                    .iter()
                    .take(index)
                    .enumerate()
                    .filter_map(|(prior_index, (prior_reads, prior_writes))| {
                        if Self::sets_overlap(read_set, prior_writes)
                            || Self::sets_overlap(write_set, prior_writes)
                            || Self::sets_overlap(write_set, prior_reads)
                        {
                            Some(prior_index)
                        } else {
                            None
                        }
                    })
                    .collect();

                TransactionDependency {
                    index,
                    read_set: read_set.clone(),
                    write_set: write_set.clone(),
                    depends_on,
                }
            })
            .collect()
    }

    pub fn detect_conflicts(
        &self,
        snapshot: &ReadOnlyStateSnapshot,
        keys: &[Vec<u8>],
    ) -> Result<bool> {
        self.state.detect_conflicts(snapshot, keys)
    }

    pub fn optimistic_execute_transactions(
        &self,
        transactions: &[Transaction],
        dependencies: &[TransactionDependency],
    ) -> Result<Vec<OptimisticExecutionResult>> {
        let results: Result<Vec<_>> = transactions
            .par_iter()
            .enumerate()
            .map(|(index, tx)| {
                let dependency = &dependencies[index];
                let snapshot = self.state.begin_read_only_snapshot();
                let _parallel_reads = self.parallel_state_reads(&dependency.read_set)?;
                let dry_run_receipt = self.simulate_transaction(tx, &snapshot)?;
                let mut conflict_keys = dependency.read_set.clone();
                conflict_keys.extend(dependency.write_set.clone());
                let conflicted = self.detect_conflicts(&snapshot, &conflict_keys)?;

                Ok(OptimisticExecutionResult {
                    index,
                    tx_hash: tx.hash(),
                    receipt: Some(dry_run_receipt.clone()),
                    execution_result: ExecutionResult {
                        status: dry_run_receipt.status,
                        gas_used: dry_run_receipt.gas_used,
                        logs: dry_run_receipt.logs.clone(),
                        return_data: dry_run_receipt.state_root.unwrap_or_default().to_vec(),
                    },
                    snapshot,
                    read_set: dependency.read_set.clone(),
                    write_set: dependency.write_set.clone(),
                    conflicted,
                })
            })
            .collect();

        results
    }

    pub fn parallel_state_reads(&self, keys: &[Vec<u8>]) -> Result<Vec<Option<Vec<u8>>>> {
        self.state.parallel_state_reads(keys)
    }

    pub fn rollback_on_conflict(&self) -> Result<[u8; 32]> {
        self.rollback_state()
    }

    fn verify_transaction_signature(&self, tx: &Transaction) -> Result<()> {
        if tx.signature.is_none() {
            bail!("transaction must be signed");
        }

        if !tx.verify_signature()? {
            bail!("transaction signature verification failed");
        }

        Ok(())
    }

    fn check_nonce_correctness(&self, tx: &Transaction, sender: &Account) -> Result<()> {
        if sender.nonce != tx.nonce {
            bail!(
                "nonce mismatch for {}: expected {}, got {}",
                tx.from,
                sender.nonce,
                tx.nonce
            );
        }
        Ok(())
    }

    fn validate_gas_limit(&self, tx: &Transaction) -> Result<()> {
        let intrinsic_gas = gas::calculate_intrinsic_gas(&tx.data);
        if tx.gas_limit < intrinsic_gas {
            bail!("gas limit too low for intrinsic gas");
        }
        Ok(())
    }

    fn validate_account_existence(&self, tx: &Transaction) -> Result<()> {
        if self.state.get_account(&tx.from)?.is_none() {
            bail!("sender account does not exist: {}", tx.from);
        }

        if let Some(address) = tx.to {
            if self.state.get_account(&address)?.is_none() {
                bail!("recipient account does not exist: {}", address);
            }
        }

        Ok(())
    }

    fn deduct_upfront_gas_fee(&self, sender: &mut Account, tx: &Transaction) -> Result<U256> {
        let upfront_fee = tx.gas_cost();
        sender.decrease_balance(upfront_fee)?;
        Ok(upfront_fee)
    }

    fn load_sender_account_state(&self, tx: &Transaction) -> Result<Account> {
        self.state
            .get_account(&tx.from)?
            .ok_or_else(|| anyhow::anyhow!("sender account does not exist: {}", tx.from))
    }

    fn load_recipient_account_state(&self, tx: &Transaction) -> Result<Option<Account>> {
        match tx.to {
            Some(address) => Ok(Some(
                self.state
                    .get_account(&address)?
                    .unwrap_or_else(|| Account::new(address)),
            )),
            None => Ok(None),
        }
    }

    fn perform_transfer_or_contract_execution(
        &self,
        tx: &Transaction,
        sender: &mut Account,
        recipient: Option<&mut Account>,
    ) -> Result<()> {
        self.validate_transfer_overflow(sender, tx, recipient.as_deref())?;
        sender.decrease_balance(tx.value)?;

        if tx.is_contract_creation() {
            // Ã¢â€â‚¬Ã¢â€â‚¬ Item 16: deploy contract via EvmRuntime Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬
            let evm = crate::evm_runtime::EvmRuntime::default_config();
            let evm_result = evm.deploy_contract(&self.state, tx)?;
            if !evm_result.success {
                bail!("contract deployment reverted");
            }
        } else if tx.is_contract_call() {
            if let Some(contract) = tx.to {
                self.update_contract_storage(contract, tx)?;
            }
        }

        if let Some(recipient) = recipient {
            self.update_balances(sender, recipient, tx.value)?;
        } else if tx.is_contract_creation() {
            // Value sent to the newly created contract.
            let contract_address = crate::evm_runtime::compute_contract_address(&tx.from, tx.nonce);
            let mut contract = self
                .state
                .get_account(&contract_address)?
                .unwrap_or_else(|| Account::new(contract_address));
            contract.increase_balance(tx.value);
            self.state.update_account(&contract_address, &contract)?;
        }
        Ok(())
    }

    fn update_balances(
        &self,
        _sender: &mut Account,
        recipient: &mut Account,
        amount: U256,
    ) -> Result<()> {
        recipient.increase_balance(amount);
        Ok(())
    }

    fn update_sender_nonce(&self, sender: &mut Account) {
        sender.increment_nonce();
    }

    fn update_contract_storage(
        &self,
        contract: vage_types::Address,
        tx: &Transaction,
    ) -> Result<()> {
        self.validate_storage_access_boundaries(&tx.data)?;
        let storage_key = vage_crypto::hash::sha256(&tx.data);
        self.state.set_storage(&contract, storage_key, tx.hash())
    }

    fn emit_execution_logs(&self, tx: &Transaction, gas_used: u64, refund: U256) -> Vec<Log> {
        let mut data = Vec::new();
        data.extend_from_slice(&gas_used.to_le_bytes());
        let mut refund_bytes = [0u8; 32];
        refund.to_big_endian(&mut refund_bytes);
        data.extend_from_slice(&refund_bytes);
        vec![Log::new(tx.from, vec![tx.hash()], data)]
    }

    fn generate_execution_receipt(&self, tx: &Transaction, gas_used: u64) -> Result<Receipt> {
        Ok(Receipt::new_success(
            tx.hash(),
            gas_used,
            Some(self.state.state_root()),
        ))
    }

    fn refund_unused_gas(
        &self,
        sender_address: &vage_types::Address,
        tx: &Transaction,
        upfront_fee: U256,
        gas_used: u64,
    ) -> Result<U256> {
        let used_fee = tx.gas_price.saturating_mul(U256::from(gas_used));
        let refund = upfront_fee.saturating_sub(used_fee);
        if refund > U256::zero() {
            let mut sender = self
                .state
                .get_account(sender_address)?
                .unwrap_or_else(|| Account::new(*sender_address));
            sender.increase_balance(refund);
            self.state.update_account(sender_address, &sender)?;
        }
        Ok(refund)
    }

    fn validate_block_header(&self, block: &Block) -> Result<()> {
        block.header.validate_basic()?;
        if block.body.compute_tx_root() != block.header.tx_root {
            bail!("computed transaction root does not match block header");
        }
        Ok(())
    }

    fn load_previous_state_root(&self) -> [u8; 32] {
        self.state.state_root()
    }

    fn execute_transactions_sequentially(&self, block: &Block) -> Result<Vec<Receipt>> {
        let mut receipts = Vec::with_capacity(block.body.transactions.len());
        for tx in &block.body.transactions {
            receipts.push(self.execute_transaction(tx)?);
        }
        Ok(receipts)
    }

    fn compute_receipts_merkle_root(&self, receipts: &[Receipt]) -> [u8; 32] {
        if receipts.is_empty() {
            return [0u8; 32];
        }

        let mut leaves: Vec<[u8; 32]> = receipts.iter().map(Receipt::hash).collect();
        while leaves.len() > 1 {
            if !leaves.len().is_multiple_of(2) {
                leaves.push(*leaves.last().unwrap());
            }

            let mut next = Vec::with_capacity(leaves.len() / 2);
            for pair in leaves.chunks(2) {
                let mut hasher = Sha256::new();
                hasher.update(pair[0]);
                hasher.update(pair[1]);
                let mut root = [0u8; 32];
                root.copy_from_slice(&hasher.finalize());
                next.push(root);
            }
            leaves = next;
        }

        leaves[0]
    }

    fn commit_block_state(&self) -> Result<[u8; 32]> {
        self.commit_state()
    }

    fn store_block_execution_results(
        &self,
        height: u64,
        receipts: &[Receipt],
        receipts_root: [u8; 32],
        state_root: [u8; 32],
    ) -> Result<()> {
        let mut operations = Vec::with_capacity(receipts.len() + 2);
        operations.push(StateBatchOp::Put(
            Self::block_receipts_root_key(height),
            receipts_root.to_vec(),
        ));
        operations.push(StateBatchOp::Put(
            Self::block_state_root_key(height),
            state_root.to_vec(),
        ));

        for receipt in receipts {
            let result = ExecutionResult {
                status: receipt.status,
                gas_used: receipt.gas_used,
                logs: receipt.logs.clone(),
                return_data: receipt.state_root.unwrap_or_default().to_vec(),
            };
            operations.push(StateBatchOp::Put(
                Self::execution_result_key(&receipt.tx_hash),
                result.encode(),
            ));
        }

        self.state.write_batch(operations)?;
        self.metrics.lock().unwrap().receipts_collected = self.receipts.lock().unwrap().len();
        Ok(())
    }

    fn commit_optimistic_results(
        &self,
        transactions: &[Transaction],
        mut results: Vec<OptimisticExecutionResult>,
    ) -> Result<Vec<Receipt>> {
        results.sort_by_key(|result| result.index);

        let mut committed_receipts = Vec::with_capacity(results.len());
        for result in results {
            let mut conflict_keys = result.read_set.clone();
            conflict_keys.extend(result.write_set.clone());

            let has_runtime_conflict =
                result.conflicted || self.detect_conflicts(&result.snapshot, &conflict_keys)?;
            if has_runtime_conflict {
                self.rollback_on_conflict()?;
                committed_receipts.push(self.execute_transaction(&transactions[result.index])?);
                continue;
            }

            committed_receipts.push(self.execute_transaction(&transactions[result.index])?);
        }

        Ok(committed_receipts)
    }

    /// Dry-run `tx` against the current state snapshot and return the estimated
    /// gas used. Used by the RPC `vage_estimateGas` endpoint so that callers
    /// get an execution-based estimate rather than a static formula.
    pub fn estimate_gas(&self, tx: &Transaction) -> Result<u64> {
        let receipt = self.simulate_transaction_on_temporary_state(tx)?;
        Ok(receipt.gas_used)
    }

    pub fn simulate_transaction_on_temporary_state(&self, tx: &Transaction) -> Result<Receipt> {
        let (_isolated_path, _isolated_storage, isolated_state) =
            self.create_isolated_state_copy()?;
        let isolated_executor = Executor::new(isolated_state);
        isolated_executor.execute_transaction(tx)
    }

    fn simulate_transaction(
        &self,
        tx: &Transaction,
        snapshot: &ReadOnlyStateSnapshot,
    ) -> Result<Receipt> {
        let sender = self
            .state
            .get_account(&tx.from)?
            .ok_or_else(|| anyhow::anyhow!("sender account does not exist: {}", tx.from))?;
        self.check_nonce_correctness(tx, &sender)?;
        self.validate_account_existence(tx)?;
        self.validate_gas_limit(tx)?;

        let gas_used = gas::calculate_intrinsic_gas(&tx.data);
        let logs = self.emit_execution_logs(tx, gas_used, U256::zero());
        let mut receipt = Receipt::new_success(tx.hash(), gas_used, Some(snapshot.root));
        receipt.logs = logs;
        Ok(receipt)
    }

    fn transaction_read_set(&self, tx: &Transaction) -> Vec<Vec<u8>> {
        let mut keys = vec![Self::account_state_key(&tx.from)];
        if let Some(to) = tx.to {
            keys.push(Self::account_state_key(&to));
            if tx.is_contract_call() {
                keys.push(Self::contract_storage_key(&to, tx));
            }
        }
        keys
    }

    fn transaction_write_set(&self, tx: &Transaction) -> Vec<Vec<u8>> {
        let mut keys = vec![Self::account_state_key(&tx.from)];
        if let Some(to) = tx.to {
            keys.push(Self::account_state_key(&to));
            if tx.is_contract_call() {
                keys.push(Self::contract_storage_key(&to, tx));
            }
        } else {
            let contract_address = vage_types::Address::from(vage_crypto::hash::sha256(&tx.hash()));
            keys.push(Self::account_state_key(&contract_address));
            keys.push(Self::contract_code_key(&vage_crypto::hash::sha256(
                &tx.data,
            )));
        }
        keys
    }

    fn account_state_key(address: &vage_types::Address) -> Vec<u8> {
        let mut key = b"account:".to_vec();
        key.extend_from_slice(address.as_bytes());
        key
    }

    fn contract_storage_key(address: &vage_types::Address, tx: &Transaction) -> Vec<u8> {
        let mut key = b"storage:".to_vec();
        key.extend_from_slice(address.as_bytes());
        key.extend_from_slice(&vage_crypto::hash::sha256(&tx.data));
        key
    }

    fn contract_code_key(code_hash: &[u8; 32]) -> Vec<u8> {
        let mut key = b"contract:code:".to_vec();
        key.extend_from_slice(code_hash);
        key
    }

    fn sets_overlap(left: &[Vec<u8>], right: &[Vec<u8>]) -> bool {
        let right_set: HashSet<&[u8]> = right.iter().map(Vec::as_slice).collect();
        left.iter().any(|key| right_set.contains(key.as_slice()))
    }

    fn validate_transfer_overflow(
        &self,
        sender: &Account,
        tx: &Transaction,
        recipient: Option<&Account>,
    ) -> Result<()> {
        let (total_cost, overflowed) = tx.value.overflowing_add(tx.gas_cost());
        if overflowed {
            bail!("transaction total cost overflow");
        }

        if sender.balance < total_cost {
            bail!("insufficient balance for transfer");
        }

        if let Some(recipient) = recipient {
            let (_, recipient_overflowed) = recipient.balance.overflowing_add(tx.value);
            if recipient_overflowed {
                bail!("recipient balance overflow");
            }
        }

        Ok(())
    }

    fn validate_storage_access_boundaries(&self, input: &[u8]) -> Result<()> {
        if input.len() > 4096 {
            bail!("storage access exceeds 4096 byte boundary");
        }
        Ok(())
    }

    fn run_isolated_parallel_analysis(&self, block: &Block) -> Result<(usize, usize)> {
        if block.body.transactions.is_empty() {
            return Ok((0, 0));
        }

        let (isolated_path, isolated_storage, isolated_state) =
            self.create_isolated_state_copy()?;
        let tasks: Vec<ParallelExecutorTask> = block
            .body
            .transactions
            .iter()
            .enumerate()
            .map(|(idx, tx)| ParallelExecutorTask {
                tx_index: idx,
                tx_bytes: bincode::serialize(tx).unwrap_or_default(),
                tx_hash: tx.hash(),
                gas_limit: tx.gas_limit,
            })
            .collect();

        let state_mutex = Arc::new(Mutex::new(StateDB::new(isolated_storage.clone())));
        let pipeline = BlockExecutionPipeline::new(PipelineConfig::default())?;
        let result =
            pipeline.speculative_execute(tasks, state_mutex, |task, _snapshot_id, _mv_memory| {
                let tx: Transaction = match bincode::deserialize(&task.tx_bytes) {
                    Ok(tx) => tx,
                    Err(error) => {
                        return RawOutcome {
                            tx_index: task.tx_index,
                            tx_hash: task.tx_hash,
                            gas_limit: task.gas_limit,
                            gas_used: 0,
                            success: false,
                            revert_reason: Some(format!("deserialize tx: {error}")),
                            write_set: Vec::new(),
                            read_set: Vec::new(),
                            events: Vec::new(),
                            return_data: Vec::new(),
                            execution_status: false,
                        };
                    }
                };

                RawOutcome {
                    tx_index: task.tx_index,
                    tx_hash: task.tx_hash,
                    gas_limit: task.gas_limit,
                    gas_used: gas::calculate_intrinsic_gas(&tx.data),
                    success: true,
                    revert_reason: None,
                    write_set: self
                        .transaction_write_set(&tx)
                        .into_iter()
                        .map(|key| (key, Vec::new()))
                        .collect(),
                    read_set: self.transaction_read_set(&tx),
                    events: Vec::new(),
                    return_data: Vec::new(),
                    execution_status: true,
                }
            });

        drop(isolated_state);
        drop(isolated_storage);
        let _ = std::fs::remove_file(&isolated_path);

        let output = result?;
        Ok((output.conflict_count, output.rounds))
    }

    fn create_isolated_state_copy(&self) -> Result<(PathBuf, Arc<StorageEngine>, Arc<StateDB>)> {
        let path = self.temp_isolated_db_path("block-pipeline");
        Schema::init(&path)?;
        let storage = Arc::new(StorageEngine::new(&path)?);

        for (key, value) in self
            .state
            .storage()
            .state_prefix_scan(b"account:".to_vec())?
        {
            storage.state_put(key, value)?;
        }
        for (key, value) in self
            .state
            .storage()
            .state_prefix_scan(b"storage:".to_vec())?
        {
            storage.state_put(key, value)?;
        }
        if let Some(root) = self
            .state
            .storage()
            .state_get(b"metadata:state_root".to_vec())?
        {
            storage.state_put(b"metadata:state_root".to_vec(), root)?;
        }

        let state = Arc::new(StateDB::new(storage.clone()));
        Ok((path, storage, state))
    }

    fn temp_isolated_db_path(&self, name: &str) -> PathBuf {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time should be after unix epoch")
            .as_nanos();
        std::env::temp_dir().join(format!("vage-{name}-{unique}.redb"))
    }

    fn execution_result_key(tx_hash: &[u8; 32]) -> Vec<u8> {
        let mut key = Vec::with_capacity(EXECUTION_RESULT_PREFIX.len() + tx_hash.len());
        key.extend_from_slice(EXECUTION_RESULT_PREFIX);
        key.extend_from_slice(tx_hash);
        key
    }

    fn block_receipts_root_key(height: u64) -> Vec<u8> {
        let mut key = Vec::with_capacity(BLOCK_RECEIPTS_ROOT_PREFIX.len() + 20);
        key.extend_from_slice(BLOCK_RECEIPTS_ROOT_PREFIX);
        key.extend_from_slice(height.to_string().as_bytes());
        key
    }

    fn block_state_root_key(height: u64) -> Vec<u8> {
        let mut key = Vec::with_capacity(BLOCK_STATE_ROOT_PREFIX.len() + 20);
        key.extend_from_slice(BLOCK_STATE_ROOT_PREFIX);
        key.extend_from_slice(height.to_string().as_bytes());
        key
    }
}

#[cfg(test)]
mod tests {
    use super::{ConsensusSink, Executor, TransactionSource};
    use crate::gas;
    use crate::runtime::ExecutionResult;
    use anyhow::Result;
    use ed25519_dalek::SigningKey;
    use primitive_types::U256;
    use std::path::PathBuf;
    use std::sync::{Arc, Mutex};
    use std::time::{SystemTime, UNIX_EPOCH};
    use vage_block::{Block, BlockBody, BlockHeader};
    use vage_state::StateDB;
    use vage_storage::{Schema, StorageEngine};
    use vage_types::{Account, Address, Transaction};

    #[derive(Clone)]
    struct MockTransactionSource {
        transactions: Vec<Transaction>,
        acknowledged: Arc<Mutex<Vec<[u8; 32]>>>,
    }

    impl MockTransactionSource {
        fn new(transactions: Vec<Transaction>) -> Self {
            Self {
                transactions,
                acknowledged: Arc::new(Mutex::new(Vec::new())),
            }
        }
    }

    impl TransactionSource for MockTransactionSource {
        fn pull_transactions(&self, limit: usize) -> Result<Vec<Transaction>> {
            Ok(self.transactions.iter().take(limit).cloned().collect())
        }

        fn acknowledge_transactions(&self, hashes: &[[u8; 32]]) -> Result<()> {
            self.acknowledged.lock().unwrap().extend_from_slice(hashes);
            Ok(())
        }
    }

    #[derive(Clone, Default)]
    struct MockConsensusSink {
        submitted_blocks: Arc<Mutex<Vec<Block>>>,
    }

    impl ConsensusSink for MockConsensusSink {
        fn submit_finalized_block(&self, block: Block) -> Result<()> {
            self.submitted_blocks.lock().unwrap().push(block);
            Ok(())
        }
    }

    fn temp_db_path(name: &str) -> PathBuf {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time should be after unix epoch")
            .as_nanos();
        std::env::temp_dir().join(format!("vage-execution-{name}-{unique}.redb"))
    }

    fn test_executor(name: &str) -> (Arc<StorageEngine>, Arc<StateDB>, Executor, PathBuf) {
        let db_path = temp_db_path(name);
        Schema::init(&db_path).expect("schema should initialize");
        let storage = Arc::new(StorageEngine::new(&db_path).expect("storage should initialize"));
        let state = Arc::new(StateDB::new(storage.clone()));
        let executor = Executor::new(state.clone());
        (storage, state, executor, db_path)
    }

    fn cleanup(
        storage: Arc<StorageEngine>,
        state: Arc<StateDB>,
        executor: Executor,
        path: PathBuf,
    ) {
        drop(executor);
        drop(state);
        drop(storage);
        let _ = std::fs::remove_file(path);
    }

    fn signing_key(byte: u8) -> SigningKey {
        SigningKey::from_bytes(&[byte; 32])
    }

    fn signed_transfer(from_key: &SigningKey, to: Address, value: u64, nonce: u64) -> Transaction {
        let from = Address::from_public_key(&from_key.verifying_key().to_bytes());
        let mut tx = Transaction::new_transfer(from, to, U256::from(value), nonce);
        tx.sign(from_key)
            .expect("transaction signing should succeed");
        tx
    }

    fn funded_account(address: Address, balance: u64) -> Account {
        let mut account = Account::new(address);
        account.balance = U256::from(balance);
        account
    }

    fn signed_contract_call(
        from_key: &SigningKey,
        to: Address,
        value: u64,
        nonce: u64,
        data: Vec<u8>,
    ) -> Transaction {
        let from = Address::from_public_key(&from_key.verifying_key().to_bytes());
        let mut tx = Transaction::new_contract_call(from, to, U256::from(value), nonce, data);
        tx.sign(from_key)
            .expect("transaction signing should succeed");
        tx
    }

    #[test]
    fn new_initializes_executor_and_basic_helpers_work() {
        let (storage, state, executor, path) = test_executor("new");
        let committed_root = executor
            .commit_state()
            .expect("initial commit should succeed");

        assert_eq!(executor.collect_receipts().len(), 0);
        assert_eq!(executor.execution_metrics().executed_transactions, 0);
        assert_eq!(executor.compute_block_state_root(), state.state_root());
        assert!(executor
            .execute_system_transactions()
            .expect("system tx execution should succeed")
            .is_empty());
        assert!(executor
            .verify_state_root(committed_root)
            .expect("state root verification should succeed"));
        assert!(!executor.detect_execution_failure());

        cleanup(storage, state, executor, path);
    }

    #[test]
    fn execute_transaction_and_execute_transactions_update_state_receipts_and_metrics() {
        let (storage, state, executor, path) = test_executor("execute-transactions");
        let sender_key = signing_key(1);
        let sender = Address::from_public_key(&sender_key.verifying_key().to_bytes());
        let recipient = Address([9u8; 32]);

        state
            .update_account(&sender, &funded_account(sender, 500_000))
            .expect("sender update should succeed");
        state
            .update_account(&recipient, &funded_account(recipient, 100))
            .expect("recipient update should succeed");

        let tx = signed_transfer(&sender_key, recipient, 1_000, 0);
        executor
            .pre_execution_checks(&tx)
            .expect("pre-execution checks should succeed");
        let receipt = executor
            .execute_transaction(&tx)
            .expect("transaction execution should succeed");

        assert!(receipt.status);
        assert_eq!(receipt.tx_hash, tx.hash());
        assert_eq!(receipt.gas_used, gas::calculate_intrinsic_gas(&tx.data));
        assert_eq!(executor.collect_receipts().len(), 1);
        assert_eq!(executor.execution_metrics().executed_transactions, 1);

        let sender_account = state
            .get_account(&sender)
            .expect("sender lookup should succeed")
            .expect("sender should exist");
        let recipient_account = state
            .get_account(&recipient)
            .expect("recipient lookup should succeed")
            .expect("recipient should exist");
        let expected_sender_balance = U256::from(500_000u64)
            - tx.value
            - tx.gas_price * U256::from(gas::calculate_intrinsic_gas(&tx.data));
        assert_eq!(sender_account.balance, expected_sender_balance);
        assert_eq!(sender_account.nonce, 1);
        assert_eq!(recipient_account.balance, U256::from(1_100u64));

        let next_tx = signed_transfer(&sender_key, recipient, 500, 1);
        let receipts = executor
            .execute_transactions(vec![next_tx.clone()])
            .expect("batch execution should succeed");
        assert_eq!(receipts.len(), 1);
        assert_eq!(receipts[0].tx_hash, next_tx.hash());

        cleanup(storage, state, executor, path);
    }

    #[test]
    fn helper_steps_validate_signature_accounts_nonce_gas_and_refunds() {
        let (storage, state, executor, path) = test_executor("pipeline-helpers");
        let sender_key = signing_key(11);
        let sender = Address::from_public_key(&sender_key.verifying_key().to_bytes());
        let recipient = Address([66u8; 32]);

        state
            .update_account(&sender, &funded_account(sender, 300_000))
            .expect("sender update should succeed");
        state
            .update_account(&recipient, &funded_account(recipient, 10))
            .expect("recipient update should succeed");

        let tx = signed_transfer(&sender_key, recipient, 2_500, 0);
        let unsigned_tx = Transaction::new_transfer(sender, recipient, U256::from(1u64), 0);
        assert!(executor.verify_transaction_signature(&unsigned_tx).is_err());
        executor
            .verify_transaction_signature(&tx)
            .expect("signed transaction should verify");

        let sender_state = executor
            .load_sender_account_state(&tx)
            .expect("sender load should succeed");
        let recipient_state = executor
            .load_recipient_account_state(&tx)
            .expect("recipient load should succeed")
            .expect("recipient should exist");
        assert_eq!(sender_state.address, sender);
        assert_eq!(recipient_state.address, recipient);

        executor
            .check_nonce_correctness(&tx, &sender_state)
            .expect("nonce check should succeed");
        executor
            .validate_gas_limit(&tx)
            .expect("gas validation should succeed");

        let mut gas_sender = sender_state.clone();
        let upfront_fee = executor
            .deduct_upfront_gas_fee(&mut gas_sender, &tx)
            .expect("upfront gas deduction should succeed");
        assert_eq!(upfront_fee, tx.gas_cost());
        assert_eq!(gas_sender.balance, sender_state.balance - tx.gas_cost());

        let mut transfer_sender = sender_state.clone();
        let mut transfer_recipient = recipient_state.clone();
        executor
            .perform_transfer_or_contract_execution(
                &tx,
                &mut transfer_sender,
                Some(&mut transfer_recipient),
            )
            .expect("transfer step should succeed");
        assert_eq!(transfer_sender.balance, sender_state.balance - tx.value);
        assert_eq!(
            transfer_recipient.balance,
            recipient_state.balance + tx.value
        );

        executor.update_sender_nonce(&mut transfer_sender);
        assert_eq!(transfer_sender.nonce, sender_state.nonce + 1);

        let logs = executor.emit_execution_logs(
            &tx,
            gas::calculate_intrinsic_gas(&tx.data),
            U256::from(123u64),
        );
        assert_eq!(logs.len(), 1);
        assert_eq!(logs[0].address, tx.from);
        assert_eq!(logs[0].topics, vec![tx.hash()]);

        let receipt = executor
            .generate_execution_receipt(&tx, gas::calculate_intrinsic_gas(&tx.data))
            .expect("receipt generation should succeed");
        assert_eq!(receipt.tx_hash, tx.hash());
        assert!(receipt.status);

        let refund = executor
            .refund_unused_gas(
                &sender,
                &tx,
                tx.gas_cost(),
                gas::calculate_intrinsic_gas(&tx.data),
            )
            .expect("refund should succeed");
        assert_eq!(
            refund,
            tx.gas_cost() - U256::from(gas::calculate_intrinsic_gas(&tx.data))
        );
        assert_eq!(
            state
                .get_balance(&sender)
                .expect("sender balance read should succeed"),
            U256::from(300_000u64) + refund
        );

        cleanup(storage, state, executor, path);
    }

    #[test]
    fn execute_pipeline_contract_call_updates_storage_logs_receipt_and_commits() {
        let (storage, state, executor, path) = test_executor("pipeline-contract-call");
        let sender_key = signing_key(12);
        let sender = Address::from_public_key(&sender_key.verifying_key().to_bytes());
        let contract = Address([77u8; 32]);
        let call_data = vec![1u8, 2, 3, 4, 5];

        state
            .update_account(&sender, &funded_account(sender, 500_000))
            .expect("sender update should succeed");
        let mut contract_account = funded_account(contract, 0);
        contract_account.apply_contract_deploy([9u8; 32]);
        state
            .update_account(&contract, &contract_account)
            .expect("contract account update should succeed");

        let tx = signed_contract_call(&sender_key, contract, 750, 0, call_data.clone());
        let previous_root = state.state_root();
        let receipt = executor
            .execute_pipeline(&tx)
            .expect("contract call pipeline should succeed");

        let storage_key = vage_crypto::hash::sha256(&call_data);
        assert_eq!(
            state
                .get_storage(&contract, storage_key)
                .expect("storage read should succeed"),
            Some(tx.hash())
        );
        assert_eq!(
            state
                .get_balance(&contract)
                .expect("contract balance read should succeed"),
            U256::from(750u64)
        );
        assert_eq!(
            state
                .get_nonce(&sender)
                .expect("sender nonce read should succeed"),
            1
        );
        assert_eq!(receipt.logs.len(), 1);
        assert_eq!(receipt.logs[0].topics, vec![tx.hash()]);
        assert!(executor
            .verify_state_root(state.state_root())
            .expect("state root verification should succeed"));
        assert_ne!(state.state_root(), previous_root);

        cleanup(storage, state, executor, path);
    }

    #[test]
    fn pre_execution_checks_reject_missing_sender_bad_nonce_and_low_gas() {
        let (storage, state, executor, path) = test_executor("pre-execution-failures");
        let sender_key = signing_key(13);
        let sender = Address::from_public_key(&sender_key.verifying_key().to_bytes());
        let recipient = Address([88u8; 32]);

        state
            .update_account(&recipient, &funded_account(recipient, 0))
            .expect("recipient update should succeed");

        let missing_sender_tx = signed_transfer(&sender_key, recipient, 1, 0);
        assert!(executor.pre_execution_checks(&missing_sender_tx).is_err());

        state
            .update_account(&sender, &funded_account(sender, 100_000))
            .expect("sender update should succeed");
        let wrong_nonce_tx = signed_transfer(&sender_key, recipient, 1, 1);
        assert!(executor.pre_execution_checks(&wrong_nonce_tx).is_err());

        let mut low_gas_tx = signed_transfer(&sender_key, recipient, 1, 0);
        low_gas_tx.gas_limit = gas::calculate_intrinsic_gas(&low_gas_tx.data) - 1;
        assert!(executor.pre_execution_checks(&low_gas_tx).is_err());

        cleanup(storage, state, executor, path);
    }

    #[test]
    fn apply_receipts_commit_reset_and_rollback_round_trip_state() {
        let (storage, state, executor, path) = test_executor("state-round-trip");
        let address = Address([22u8; 32]);
        let receipt = vage_types::Receipt::new_success([7u8; 32], 21_000, Some(state.state_root()));

        executor
            .apply_receipts(vec![receipt.clone()])
            .expect("apply receipts should succeed");
        assert_eq!(executor.collect_receipts(), vec![receipt]);

        state
            .update_account(&address, &funded_account(address, 75))
            .expect("account update should succeed");
        let committed_root = executor.commit_state().expect("commit should succeed");
        assert!(executor
            .verify_state_root(committed_root)
            .expect("committed root verification should succeed"));

        state
            .set_balance(&address, U256::from(5u64))
            .expect("balance update should succeed");
        let rolled_back_root = executor.rollback_state().expect("rollback should succeed");
        assert_eq!(rolled_back_root, committed_root);
        assert_eq!(
            state
                .get_balance(&address)
                .expect("balance read should succeed"),
            U256::from(75u64)
        );

        state.snapshot_state(0).expect("snapshot should succeed");
        state
            .set_balance(&address, U256::from(125u64))
            .expect("balance update should succeed");
        let reset_root = executor.reset_state(0).expect("reset state should succeed");
        assert_eq!(reset_root, committed_root);
        assert_eq!(
            state
                .get_balance(&address)
                .expect("balance read should succeed"),
            U256::from(75u64)
        );

        cleanup(storage, state, executor, path);
    }

    #[test]
    fn generate_receipts_validate_block_and_execute_block_work_for_empty_and_non_empty_paths() {
        let (storage, state, executor, path) = test_executor("execute-block");
        let sender_key = signing_key(2);
        let sender = Address::from_public_key(&sender_key.verifying_key().to_bytes());
        let recipient = Address([33u8; 32]);
        state
            .update_account(&sender, &funded_account(sender, 500_000))
            .expect("sender update should succeed");
        state
            .update_account(&recipient, &funded_account(recipient, 0))
            .expect("recipient update should succeed");

        let tx = signed_transfer(&sender_key, recipient, 1_000, 0);
        let generated_receipts = executor
            .generate_block_receipts(&Block::new(
                BlockHeader::new([1u8; 32], 1),
                BlockBody {
                    transactions: vec![tx.clone()],
                    receipts: vec![vage_types::Receipt::new_success(
                        tx.hash(),
                        gas::calculate_intrinsic_gas(&tx.data),
                        Some(state.state_root()),
                    )],
                },
            ))
            .expect("receipt generation should succeed");
        assert_eq!(generated_receipts.len(), 1);

        let empty_root = state.state_root();
        let mut empty_block = Block::new(BlockHeader::new([0u8; 32], 1), BlockBody::empty());
        empty_block.compute_roots();
        empty_block.header.state_root = empty_root;

        executor
            .validate_block_transactions(&empty_block)
            .expect("empty block validation should succeed");
        let executed_root = executor
            .execute_block(empty_block)
            .expect("empty block execution should succeed");
        assert_eq!(executed_root, empty_root);

        cleanup(storage, state, executor, path);
    }

    #[test]
    fn execute_block_pipeline_validates_header_executes_transactions_and_persists_results() {
        let (storage, state, executor, path) = test_executor("execute-block-pipeline");
        let (preview_storage, preview_state, preview_executor, preview_path) =
            test_executor("execute-block-pipeline-preview");
        let sender_key = signing_key(21);
        let sender = Address::from_public_key(&sender_key.verifying_key().to_bytes());
        let recipient = Address([99u8; 32]);

        state
            .update_account(&sender, &funded_account(sender, 900_000))
            .expect("sender update should succeed");
        state
            .update_account(&recipient, &funded_account(recipient, 250))
            .expect("recipient update should succeed");
        executor
            .commit_state()
            .expect("initial commit should succeed");
        preview_state
            .update_account(&sender, &funded_account(sender, 900_000))
            .expect("preview sender update should succeed");
        preview_state
            .update_account(&recipient, &funded_account(recipient, 250))
            .expect("preview recipient update should succeed");
        preview_executor
            .commit_state()
            .expect("preview initial commit should succeed");

        let tx = signed_transfer(&sender_key, recipient, 2_000, 0);
        let mut header = BlockHeader::new([7u8; 32], 1);
        let mut body = BlockBody {
            transactions: vec![tx.clone()],
            receipts: vec![vage_types::Receipt::new_success(
                tx.hash(),
                gas::calculate_intrinsic_gas(&tx.data),
                Some(state.state_root()),
            )],
        };
        header.tx_root = body.compute_tx_root();

        let preview_receipts = preview_executor
            .execute_transactions_sequentially(&Block::new(header.clone(), body.clone()))
            .expect("preview execution should succeed");
        body.receipts = preview_receipts.clone();
        let receipts_root = preview_executor.compute_receipts_merkle_root(&preview_receipts);
        let computed_state_root = preview_state.state_root();
        header.receipts_root = receipts_root;
        header.state_root = computed_state_root;

        let block = Block::new(header.clone(), body);

        executor
            .validate_block_header(&block)
            .expect("block header validation should succeed");
        let previous_root = executor.load_previous_state_root();
        let committed_root = executor
            .execute_block_pipeline(block)
            .expect("block pipeline execution should succeed");

        assert_eq!(committed_root, computed_state_root);
        assert_ne!(previous_root, committed_root);
        assert_eq!(executor.collect_receipts().len(), 1);
        assert_eq!(executor.execution_metrics().executed_blocks, 1);
        assert!(executor
            .verify_state_root(committed_root)
            .expect("committed state root verification should succeed"));

        let stored_receipts_root = storage
            .state_get(Executor::block_receipts_root_key(header.height))
            .expect("stored receipts root read should succeed")
            .expect("stored receipts root should exist");
        assert_eq!(stored_receipts_root, receipts_root.to_vec());

        let stored_state_root = storage
            .state_get(Executor::block_state_root_key(header.height))
            .expect("stored state root read should succeed")
            .expect("stored state root should exist");
        assert_eq!(stored_state_root, committed_root.to_vec());

        let encoded_result = storage
            .state_get(Executor::execution_result_key(&tx.hash()))
            .expect("execution result read should succeed")
            .expect("execution result should exist");
        let decoded_result = ExecutionResult::decode(&encoded_result)
            .expect("execution result decode should succeed");
        assert!(decoded_result.status);
        assert_eq!(
            decoded_result.gas_used,
            gas::calculate_intrinsic_gas(&tx.data)
        );
        assert_eq!(decoded_result.logs.len(), 1);
        assert_eq!(decoded_result.return_data, committed_root.to_vec());

        cleanup(
            preview_storage,
            preview_state,
            preview_executor,
            preview_path,
        );
        cleanup(storage, state, executor, path);
    }

    #[test]
    fn post_execution_failure_parallel_batch_and_metrics_behave_as_expected() {
        let (storage, state, executor, path) = test_executor("parallel-batch");
        let sender_key = signing_key(3);
        let sender = Address::from_public_key(&sender_key.verifying_key().to_bytes());
        let other_sender_key = signing_key(4);
        let other_sender = Address::from_public_key(&other_sender_key.verifying_key().to_bytes());
        let recipient_a = Address([44u8; 32]);
        let recipient_b = Address([45u8; 32]);

        state
            .update_account(&sender, &funded_account(sender, 800_000))
            .expect("sender update should succeed");
        state
            .update_account(&other_sender, &funded_account(other_sender, 800_000))
            .expect("other sender update should succeed");
        state
            .update_account(&recipient_a, &funded_account(recipient_a, 0))
            .expect("recipient A update should succeed");
        state
            .update_account(&recipient_b, &funded_account(recipient_b, 0))
            .expect("recipient B update should succeed");

        let first = signed_transfer(&sender_key, recipient_a, 1_000, 0);
        let second = signed_transfer(&other_sender_key, recipient_b, 2_000, 0);

        let dependencies =
            executor.detect_transaction_dependencies(&[first.clone(), second.clone()]);
        assert_eq!(dependencies.len(), 2);
        assert!(dependencies[1].depends_on.is_empty());

        let committed = executor
            .parallel_execute_batch(vec![first.clone(), second.clone()])
            .expect("parallel batch execution should succeed");
        assert_eq!(committed.len(), 2);

        executor
            .post_execution_updates(&second)
            .expect("post execution updates should succeed");
        let metrics = executor.execution_metrics();
        assert_eq!(metrics.executed_transactions, 2);
        assert_eq!(metrics.receipts_collected, 2);
        assert_eq!(
            metrics.gas_used,
            gas::calculate_intrinsic_gas(&first.data) + gas::calculate_intrinsic_gas(&second.data)
        );

        executor.metrics.lock().unwrap().failed_transactions = 1;
        assert!(executor.detect_execution_failure());

        cleanup(storage, state, executor, path);
    }

    #[test]
    fn mempool_to_consensus_flow_receives_transactions_updates_state_and_submits_block() {
        let (storage, state, executor, path) = test_executor("mempool-to-consensus");
        let (preview_storage, preview_state, preview_executor, preview_path) =
            test_executor("mempool-to-consensus-preview");
        let sender_key = signing_key(41);
        let sender = Address::from_public_key(&sender_key.verifying_key().to_bytes());
        let recipient = Address([111u8; 32]);

        state
            .update_account(&sender, &funded_account(sender, 600_000))
            .expect("sender update should succeed");
        state
            .update_account(&recipient, &funded_account(recipient, 50))
            .expect("recipient update should succeed");
        preview_state
            .update_account(&sender, &funded_account(sender, 600_000))
            .expect("preview sender update should succeed");
        preview_state
            .update_account(&recipient, &funded_account(recipient, 50))
            .expect("preview recipient update should succeed");

        let tx = signed_transfer(&sender_key, recipient, 1_500, 0);
        let source = MockTransactionSource::new(vec![tx.clone()]);
        let sink = MockConsensusSink::default();
        let block = Block::new(BlockHeader::new([12u8; 32], 1), BlockBody::empty());

        let received = executor
            .receive_transactions_from_mempool(&source, 10)
            .expect("receiving transactions should succeed");
        assert_eq!(received, vec![tx.clone()]);

        let produced = preview_executor
            .produce_block_from_transactions(block.clone(), received)
            .expect("block production should succeed");
        assert_eq!(produced.body.transactions, vec![tx.clone()]);
        assert_eq!(produced.body.receipts.len(), 1);
        assert_eq!(produced.body.receipts[0].tx_hash, tx.hash());
        assert_eq!(produced.header.tx_root, produced.body.compute_tx_root());
        assert_eq!(
            produced.header.receipts_root,
            produced.body.compute_receipt_root()
        );
        assert_eq!(produced.header.state_root, preview_state.state_root());

        executor
            .pass_finalized_block_to_consensus(&sink, produced.clone())
            .expect("passing finalized block should succeed");
        assert_eq!(sink.submitted_blocks.lock().unwrap().len(), 1);
        assert_eq!(sink.submitted_blocks.lock().unwrap()[0], produced);

        let final_block = executor
            .execute_from_mempool_to_consensus(&source, &sink, block, 10)
            .expect("mempool to consensus flow should succeed");
        assert_eq!(final_block.body.transactions.len(), 1);
        assert_eq!(final_block.body.receipts.len(), 1);
        assert_eq!(
            final_block.header.tx_root,
            final_block.body.compute_tx_root()
        );
        assert_eq!(
            final_block.header.receipts_root,
            final_block.body.compute_receipt_root()
        );
        assert_eq!(sink.submitted_blocks.lock().unwrap().len(), 2);
        assert_eq!(source.acknowledged.lock().unwrap().as_slice(), &[tx.hash()]);
        assert_eq!(
            state
                .get_nonce(&sender)
                .expect("sender nonce read should succeed"),
            1
        );
        assert!(
            state
                .get_balance(&recipient)
                .expect("recipient balance read should succeed")
                > U256::from(50u64)
        );

        cleanup(
            preview_storage,
            preview_state,
            preview_executor,
            preview_path,
        );
        cleanup(storage, state, executor, path);
    }

    #[test]
    fn dependency_detection_identifies_read_write_and_write_write_overlaps() {
        let (storage, state, executor, path) = test_executor("dependency-detection");
        let sender_key = signing_key(31);
        let sender = Address::from_public_key(&sender_key.verifying_key().to_bytes());
        let receiver_a = Address([101u8; 32]);
        let receiver_b = Address([102u8; 32]);
        let contract = Address([103u8; 32]);

        state
            .update_account(&sender, &funded_account(sender, 1_000_000))
            .expect("sender update should succeed");
        state
            .update_account(&receiver_a, &funded_account(receiver_a, 0))
            .expect("receiver A update should succeed");
        state
            .update_account(&receiver_b, &funded_account(receiver_b, 0))
            .expect("receiver B update should succeed");
        let mut contract_account = funded_account(contract, 0);
        contract_account.apply_contract_deploy([55u8; 32]);
        state
            .update_account(&contract, &contract_account)
            .expect("contract update should succeed");

        let first = signed_transfer(&sender_key, receiver_a, 10, 0);
        let second = signed_transfer(&sender_key, receiver_b, 20, 1);
        let third = signed_contract_call(&sender_key, contract, 0, 2, vec![1u8, 2, 3]);

        let dependencies = executor.detect_transaction_dependencies(&[
            first.clone(),
            second.clone(),
            third.clone(),
        ]);
        assert_eq!(dependencies.len(), 3);
        assert!(dependencies[0].depends_on.is_empty());
        assert_eq!(dependencies[1].depends_on, vec![0]);
        assert_eq!(dependencies[2].depends_on, vec![0, 1]);

        cleanup(storage, state, executor, path);
    }

    #[test]
    fn conflict_detection_and_parallel_state_reads_use_snapshot_and_key_versions() {
        let (storage, state, executor, path) = test_executor("conflict-detection");
        let address = Address([104u8; 32]);
        let other = Address([105u8; 32]);
        state
            .update_account(&address, &funded_account(address, 10))
            .expect("address update should succeed");
        state
            .update_account(&other, &funded_account(other, 20))
            .expect("other update should succeed");
        state.commit().expect("initial commit should succeed");

        let snapshot = state.begin_read_only_snapshot();
        let keys = vec![
            b"account:"
                .iter()
                .copied()
                .chain(address.as_bytes().iter().copied())
                .collect::<Vec<u8>>(),
            b"account:"
                .iter()
                .copied()
                .chain(other.as_bytes().iter().copied())
                .collect::<Vec<u8>>(),
        ];
        let reads = executor
            .parallel_state_reads(&keys)
            .expect("parallel state reads should succeed");
        assert_eq!(reads.len(), 2);
        assert!(reads.iter().all(Option::is_some));
        assert!(!executor
            .detect_conflicts(&snapshot, &keys)
            .expect("conflict detection should succeed"));

        state
            .set_balance(&address, U256::from(99u64))
            .expect("balance update should succeed");
        assert!(executor
            .detect_conflicts(&snapshot, &keys)
            .expect("conflict detection should succeed"));

        cleanup(storage, state, executor, path);
    }

    #[test]
    fn optimistic_execution_produces_receipts_and_deterministic_commit_order() {
        let (storage, state, executor, path) = test_executor("optimistic-execution");
        let first_sender_key = signing_key(32);
        let second_sender_key = signing_key(33);
        let first_sender = Address::from_public_key(&first_sender_key.verifying_key().to_bytes());
        let second_sender = Address::from_public_key(&second_sender_key.verifying_key().to_bytes());
        let receiver_a = Address([106u8; 32]);
        let receiver_b = Address([107u8; 32]);

        state
            .update_account(&first_sender, &funded_account(first_sender, 500_000))
            .expect("first sender update should succeed");
        state
            .update_account(&second_sender, &funded_account(second_sender, 500_000))
            .expect("second sender update should succeed");
        state
            .update_account(&receiver_a, &funded_account(receiver_a, 0))
            .expect("receiver A update should succeed");
        state
            .update_account(&receiver_b, &funded_account(receiver_b, 0))
            .expect("receiver B update should succeed");

        let first = signed_transfer(&first_sender_key, receiver_a, 1_000, 0);
        let second = signed_transfer(&second_sender_key, receiver_b, 2_000, 0);
        let transactions = vec![first.clone(), second.clone()];
        let dependencies = executor.detect_transaction_dependencies(&transactions);
        let optimistic = executor
            .optimistic_execute_transactions(&transactions, &dependencies)
            .expect("optimistic execution should succeed");

        assert_eq!(optimistic.len(), 2);
        assert_eq!(optimistic[0].index, 0);
        assert_eq!(optimistic[1].index, 1);
        assert!(!optimistic[0].conflicted);
        assert!(!optimistic[1].conflicted);
        assert_eq!(
            optimistic[0]
                .receipt
                .as_ref()
                .expect("first receipt should exist")
                .tx_hash,
            first.hash()
        );
        assert_eq!(
            optimistic[1]
                .receipt
                .as_ref()
                .expect("second receipt should exist")
                .tx_hash,
            second.hash()
        );

        let committed = executor
            .commit_optimistic_results(
                &transactions,
                vec![optimistic[1].clone(), optimistic[0].clone()],
            )
            .expect("optimistic commit should succeed");
        assert_eq!(committed.len(), 2);
        assert_eq!(committed[0].tx_hash, first.hash());
        assert_eq!(committed[1].tx_hash, second.hash());
        assert_eq!(
            state
                .get_nonce(&first_sender)
                .expect("first sender nonce read should succeed"),
            1
        );
        assert_eq!(
            state
                .get_nonce(&second_sender)
                .expect("second sender nonce read should succeed"),
            1
        );

        cleanup(storage, state, executor, path);
    }

    #[test]
    fn rollback_on_conflict_restores_committed_state() {
        let (storage, state, executor, path) = test_executor("rollback-on-conflict");
        let address = Address([108u8; 32]);
        state
            .update_account(&address, &funded_account(address, 123))
            .expect("account update should succeed");
        let committed_root = state.commit().expect("commit should succeed");

        state
            .set_balance(&address, U256::from(456u64))
            .expect("balance mutation should succeed");
        let rolled_back_root = executor
            .rollback_on_conflict()
            .expect("rollback on conflict should succeed");

        assert_eq!(rolled_back_root, committed_root);
        assert_eq!(
            state
                .get_balance(&address)
                .expect("balance read should succeed"),
            U256::from(123u64)
        );

        cleanup(storage, state, executor, path);
    }
}
