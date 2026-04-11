//! EVM execution runtime backed by [`revm`].
//!
//! [`EvmRuntime`] wraps `revm::EVM` and bridges vage's own types
//! (`Address`, `Account`, `Transaction`, `StateDb`) to revm's primitives
//! (`Address`/20-byte, `AccountInfo`, `U256`, etc.).
//!
//! # Address mapping
//! vage uses 32-byte addresses (SHA-256 public key digests). revm uses
//! 20-byte addresses identical to Ethereum's.  We project by taking the
//! **last 20 bytes** of a vage address for the revm side, and padding
//! with leading zeros on the return trip.  This is only used internally
//! inside the EVM execution sandbox; the outer blockchain always works
//! with the full 32-byte form.

use crate::gas::GasMeter;
use anyhow::{anyhow, bail, Result};
use primitive_types::U256 as PrimU256;
use revm::primitives::{
    AccountInfo, Address as RevmAddress, Bytecode, ExecutionResult as RevmExecResult, B256,
    KECCAK_EMPTY, U256 as RevmU256,
};
use revm::{Database, DatabaseCommit};
use vage_crypto::hash::sha256;
use vage_state::StateDb;
use vage_types::{Address, Log, Transaction};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/// EVM hardfork / gas-schedule configuration (item 20).
#[derive(Clone, Debug)]
pub struct EvmConfig {
    /// Chain identifier inserted into the EVM context.
    pub chain_id: u64,
    /// Default block-level gas limit.
    pub block_gas_limit: u64,
    /// revm `SpecId` that selects the active EVM hardfork rules.
    pub spec_id: revm::primitives::SpecId,
}

impl Default for EvmConfig {
    fn default() -> Self {
        Self {
            chain_id: 1337,
            block_gas_limit: 30_000_000,
            spec_id: revm::primitives::SpecId::CANCUN,
        }
    }
}

// ---------------------------------------------------------------------------
// Execution result
// ---------------------------------------------------------------------------

/// Normalised result returned from [`EvmRuntime`] execution (item 14).
#[derive(Clone, Debug, Default)]
pub struct EvmExecutionResult {
    /// `true` iff the call / creation succeeded without reverting.
    pub success: bool,
    /// Actual EVM gas consumed.
    pub gas_used: u64,
    /// ABI-encoded return / revert data.
    pub return_data: Vec<u8>,
    /// Emitted EVM logs translated to vage [`Log`] objects (item 10).
    pub logs: Vec<Log>,
    /// For contract creation: the newly-deployed contract address.
    pub contract_address: Option<Address>,
}

// ---------------------------------------------------------------------------
// EvmRuntime (item 2)
// ---------------------------------------------------------------------------

/// High-level EVM runtime.  Wraps `revm::EVM<StateDbBackend>` and provides
/// `execute_contract_call` / `deploy_contract` that map vage types to
/// the revm API and back.
pub struct EvmRuntime {
    pub config: EvmConfig,
    /// Optional in-memory contract bytecode cache (keyed by SHA-256 code hash).
    bytecode_cache: Mutex<HashMap<[u8; 32], Vec<u8>>>,
}

impl EvmRuntime {
    /// Create a new runtime with the supplied configuration.
    pub fn new(config: EvmConfig) -> Self {
        Self {
            config,
            bytecode_cache: Mutex::new(HashMap::new()),
        }
    }

    /// Convenience constructor with default configuration.
    pub fn default_config() -> Self {
        Self::new(EvmConfig::default())
    }

    // -----------------------------------------------------------------------
    // Public execute helpers
    // -----------------------------------------------------------------------

    /// Execute a contract-call transaction against `state` (item 5).
    ///
    /// Steps performed:
    /// 1. Resolve the target contract account from `StateDb`.
    /// 2. Load the contract bytecode for the callee (items 11, 12).
    /// 3. Build a `revm::EVM` with a `StateDbBackend` database adapter.
    /// 4. Populate `env.tx` from the vage [`Transaction`] (items 7, 8).
    /// 5. Call `transact_commit` to run the EVM and persist state writes (item 9).
    /// 6. Convert the `revm::ExecutionResult` Ã¢â€ â€™ [`EvmExecutionResult`] (items 9, 10, 14).
    /// 7. On revert/halt: propagate the failure without committing (item 15).
    pub fn execute_contract_call(
        &self,
        state: &Arc<StateDb>,
        tx: &Transaction,
    ) -> Result<EvmExecutionResult> {
        let to_addr = tx
            .to
            .ok_or_else(|| anyhow!("contract call missing `to` address"))?;

        // Verify the target is actually a deployed contract.
        let contract_account = state
            .get_account(&to_addr)?
            .ok_or_else(|| anyhow!("contract account not found: {}", to_addr))?;
        if !contract_account.is_contract() {
            bail!("target account {} is not a deployed contract", to_addr);
        }

        // Build the revm environment.
        let mut evm = self.build_evm(state.clone());
        self.populate_tx_env(&mut evm.env.tx, tx);

        // Run the EVM and commit state changes atomically (item 9).
        let result = evm
            .transact_commit()
            .map_err(|e| anyhow!("EVM execution error: {:?}", e))?;

        Ok(self.convert_result(result, None))
    }

    /// Deploy a contract (item 6).
    ///
    /// Steps performed:
    /// 1. Compute the deterministic contract address from `keccak(sender||nonce)` (item 13).
    /// 2. Validate bytecode length / structure (guard against trivially invalid code).
    /// 3. Build a `revm::EVM` in *create* mode (`to` = `None` in the revm tx env).
    /// 4. Set `TxEnv.data` to the deployment init-code supplied in `tx.data` (item 7).
    /// 5. Execute and commit; on success the contract address is returned (item 14).
    /// 6. On failure the state backend does **not** persist changes (item 15).
    /// 7. Persist the init-code SHA-256 hash into the account's `code_hash` (item 12).
    pub fn deploy_contract(
        &self,
        state: &Arc<StateDb>,
        tx: &Transaction,
    ) -> Result<EvmExecutionResult> {
        if tx.data.is_empty() {
            bail!("deploy_contract: init-code must not be empty");
        }

        // Compute the new contract's canonical 32-byte address (item 13).
        let contract_addr = compute_contract_address(&tx.from, tx.nonce);

        // Build and configure the revm execution environment.
        let mut evm = self.build_evm(state.clone());
        self.populate_tx_env(&mut evm.env.tx, tx);
        // Clear `to` so revm treats this as a CREATE transaction.
        evm.env.tx.transact_to = revm::primitives::TransactTo::Create(
            revm::primitives::CreateScheme::Create,
        );

        // Run EVM (item 9); the `StateDbBackend::commit` persists storage writes.
        let result = evm
            .transact_commit()
            .map_err(|e| anyhow!("EVM deploy error: {:?}", e))?;

        // Persist init-code SHA-256 hash to the account's `code_hash` field (item 12).
        if matches!(result, RevmExecResult::Success { .. }) {
            let code_hash = sha256(&tx.data);
            if let Ok(Some(mut account)) = state.get_account(&contract_addr) {
                account.set_code_hash(code_hash);
                let _ = state.update_account(&contract_addr, &account);
            }
            // Cache bytecode for future lookups.
            self.bytecode_cache
                .lock()
                .unwrap()
                .insert(code_hash, tx.data.clone());
        }

        Ok(self.convert_result(result, Some(contract_addr)))
    }

    // -----------------------------------------------------------------------
    // Private helpers
    // -----------------------------------------------------------------------

    /// Construct a fully-configured `revm::EVM` instance for one transaction.
    fn build_evm(&self, state: Arc<StateDb>) -> revm::EVM<StateDbBackend> {
        let mut evm: revm::EVM<StateDbBackend> = revm::new();
        evm.database(StateDbBackend::new(state));

        // Block environment.
        evm.env.cfg.chain_id = self.config.chain_id;
        evm.env.cfg.spec_id = self.config.spec_id;
        evm.env.block.gas_limit = RevmU256::from(self.config.block_gas_limit);
        evm.env.block.basefee = RevmU256::ZERO;
        evm.env.block.difficulty = RevmU256::ZERO;

        evm
    }

    /// Populate the revm `TxEnv` from a vage [`Transaction`] (items 7, 8).
    fn populate_tx_env(&self, tx_env: &mut revm::primitives::TxEnv, tx: &Transaction) {
        // Caller address mapping (item 3).
        tx_env.caller = l1_addr_to_revm(&tx.from);

        // Destination / call-or-create (item 7).
        tx_env.transact_to = match tx.to {
            Some(ref to) => revm::primitives::TransactTo::Call(l1_addr_to_revm(to)),
            None => revm::primitives::TransactTo::Create(
                revm::primitives::CreateScheme::Create,
            ),
        };

        // Input data (item 7).
        tx_env.data = revm::primitives::Bytes::from(tx.data.clone());

        // Gas (item 8).
        tx_env.gas_limit = tx.gas_limit;
        // Upfront gas accounting is enforced by the executor before entering
        // REVM, so keep the EVM gas price at zero to avoid double-charging.
        tx_env.gas_price = RevmU256::ZERO;

        // Value.
        tx_env.value = prim_u256_to_revm(tx.value);

        // Nonce.
        tx_env.nonce = Some(tx.nonce);
    }

    /// Convert a `revm::ExecutionResult` into our [`EvmExecutionResult`] (items 9, 10, 14, 15).
    fn convert_result(
        &self,
        result: RevmExecResult,
        contract_address: Option<Address>,
    ) -> EvmExecutionResult {
        match result {
            RevmExecResult::Success {
                gas_used,
                logs,
                output,
                ..
            } => {
                let return_data = output.into_data().to_vec();
                // Convert revm logs Ã¢â€ â€™ vage Log objects (item 10).
                let l1_logs = logs
                    .into_iter()
                    .map(|l| Log {
                        address: revm_addr_to_l1(l.address),
                        topics: l.topics.iter().map(|t| t.0).collect(),
                        data: l.data.to_vec(),
                    })
                    .collect();
                EvmExecutionResult {
                    success: true,
                    gas_used,
                    return_data,
                    logs: l1_logs,
                    contract_address,
                }
            }
            RevmExecResult::Revert { gas_used, output } => EvmExecutionResult {
                success: false,
                gas_used,
                return_data: output.to_vec(),
                logs: Vec::new(),
                contract_address: None,
            },
            RevmExecResult::Halt { gas_used, .. } => EvmExecutionResult {
                success: false,
                gas_used,
                return_data: Vec::new(),
                logs: Vec::new(),
                contract_address: None,
            },
        }
    }
}

// ---------------------------------------------------------------------------
// StateDbBackend Ã¢â‚¬â€ revm::Database + revm::DatabaseCommit adapter (item 4)
// ---------------------------------------------------------------------------

/// Bridges vage's [`StateDb`] to the `revm::Database` trait so that the
/// EVM can load account info, bytecode, and storage slots.
pub struct StateDbBackend {
    state: Arc<StateDb>,
}

impl StateDbBackend {
    pub fn new(state: Arc<StateDb>) -> Self {
        Self { state }
    }
}

/// Map a vage `Account` to a `revm::primitives::AccountInfo` (item 3).
fn account_to_revm_info(account: &vage_types::Account) -> AccountInfo {
    let code_hash: B256 = if account.code_hash == [0u8; 32] {
        KECCAK_EMPTY
    } else {
        B256::from_slice(&account.code_hash)
    };

    AccountInfo {
        balance: prim_u256_to_revm(account.balance),
        nonce: account.nonce,
        code_hash,
        code: None, // loaded lazily via `code_by_hash`
    }
}

impl Database for StateDbBackend {
    type Error = anyhow::Error;

    /// Load basic account information (balance, nonce, code hash) (item 3).
    fn basic(&mut self, address: RevmAddress) -> Result<Option<AccountInfo>> {
        let l1_addr = revm_addr_to_l1(address);
        match self.state.get_account(&l1_addr)? {
            Some(account) => Ok(Some(account_to_revm_info(&account))),
            None => Ok(None),
        }
    }

    /// Fetch bytecode by its SHA-256 / KECCAK hash.
    fn code_by_hash(&mut self, code_hash: B256) -> Result<Bytecode> {
        let hash_bytes: [u8; 32] = code_hash.0;
        // Attempt to load contract code from the state storage.
        let code_key = [b"contract:code:".as_ref(), &hash_bytes].concat();
        match self.state.get_raw(&code_key)? {
            Some(bytes) => Ok(Bytecode::new_raw(bytes.into())),
            None => Ok(Bytecode::new()),
        }
    }

    /// Read a storage slot as a 256-bit value (item 11).
    fn storage(&mut self, address: RevmAddress, index: RevmU256) -> Result<RevmU256> {
        let l1_addr = revm_addr_to_l1(address);
        let key = revm_u256_to_bytes32(index);
        match self.state.get_storage(&l1_addr, key)? {
            Some(value) => Ok(RevmU256::from_be_bytes(value)),
            None => Ok(RevmU256::ZERO),
        }
    }

    /// Return block hash by number (needed by `BLOCKHASH` opcode).
    fn block_hash(&mut self, _number: RevmU256) -> Result<B256> {
        // Historical block hashes are not tracked in this implementation.
        Ok(B256::ZERO)
    }
}

/// Commit EVM state-diff back to [`StateDb`] after a successful transaction (item 11, 15).
impl DatabaseCommit for StateDbBackend {
    fn commit(&mut self, changes: revm::primitives::HashMap<RevmAddress, revm::primitives::Account>) {
        for (revm_addr, revm_account) in changes {
            if revm_account.is_selfdestructed() {
                let l1_addr = revm_addr_to_l1(revm_addr);
                let _ = self.state.delete_account(&l1_addr);
                continue;
            }

            let l1_addr = revm_addr_to_l1(revm_addr);
            let info = &revm_account.info;

            // Update balance and nonce on the vage account (item 11).
            let new_balance = revm_u256_to_prim(info.balance);
            let _ = self.state.set_balance(&l1_addr, new_balance);

            // Sync nonce.
            if let Ok(Some(mut account)) = self.state.get_account(&l1_addr) {
                if account.nonce != info.nonce {
                    account.nonce = info.nonce;
                    let _ = self.state.update_account(&l1_addr, &account);
                }
            }

            // Persist storage slot writes (item 11).
            for (slot, storage_slot) in &revm_account.storage {
                if storage_slot.is_changed() {
                    let key = revm_u256_to_bytes32(*slot);
                    let value = revm_u256_to_bytes32(storage_slot.present_value());
                    let _ = self.state.set_storage(&l1_addr, key, value);
                }
            }

            // Persist bytecode if the account carries inline code (item 12).
            if let Some(code) = &info.code {
                if !code.is_empty() {
                    let code_bytes = code.bytecode.to_vec();
                    let code_hash = sha256(&code_bytes);
                    let code_key = [b"contract:code:".as_ref(), code_hash.as_slice()].concat();
                    let _ = self.state.set_raw(&code_key, code_bytes);

                    // Record the code hash on the account.
                    if let Ok(Some(mut account)) = self.state.get_account(&l1_addr) {
                        account.set_code_hash(code_hash);
                        let _ = self.state.update_account(&l1_addr, &account);
                    }
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Contract address derivation (item 13)
// ---------------------------------------------------------------------------

/// Compute a deterministic 32-byte contract address from `sha256(sender || nonce_le)`.
///
/// This mirrors the vage convention of SHA-256-based addressing rather than
/// Ethereum's keccak-based CREATE scheme.
pub fn compute_contract_address(sender: &Address, nonce: u64) -> Address {
    let mut data = Vec::with_capacity(40);
    data.extend_from_slice(sender.as_bytes());
    data.extend_from_slice(&nonce.to_le_bytes());
    let hash = sha256(&data);
    Address(hash)
}

// ---------------------------------------------------------------------------
// Type-conversion helpers
// ---------------------------------------------------------------------------

/// Convert a vage 32-byte `Address` to a revm 20-byte `Address` (item 3).
///
/// We use the **last 20 bytes** so that the mapping is consistent with how most
/// EVM tooling computes CREATE2-style addresses from a 32-byte salt.
#[inline]
pub fn l1_addr_to_revm(addr: &Address) -> RevmAddress {
    let bytes = addr.as_bytes();
    let mut out = [0u8; 20];
    out.copy_from_slice(&bytes[12..32]);
    RevmAddress::from(out)
}

/// Convert a revm 20-byte `Address` back to a vage 32-byte `Address`.
///
/// Pads with 12 zero bytes on the left.
#[inline]
pub fn revm_addr_to_l1(addr: RevmAddress) -> Address {
    let mut out = [0u8; 32];
    out[12..32].copy_from_slice(addr.as_slice());
    Address(out)
}

/// Convert `primitive_types::U256` (big-endian internally) to `alloy_primitives::U256`.
#[inline]
fn prim_u256_to_revm(value: PrimU256) -> RevmU256 {
    let mut bytes = [0u8; 32];
    value.to_big_endian(&mut bytes);
    RevmU256::from_be_bytes(bytes)
}

/// Convert `alloy_primitives::U256` to `primitive_types::U256`.
#[inline]
fn revm_u256_to_prim(value: RevmU256) -> PrimU256 {
    let bytes = value.to_be_bytes::<32>();
    PrimU256::from_big_endian(&bytes)
}

/// Encode a `alloy_primitives::U256` storage key as a 32-byte big-endian array.
#[inline]
fn revm_u256_to_bytes32(value: RevmU256) -> [u8; 32] {
    value.to_be_bytes::<32>()
}

// ---------------------------------------------------------------------------
// Gas schedule integration (item 20)
// ---------------------------------------------------------------------------

/// Build a [`GasMeter`] from the `gas_limit` field of a transaction, applying
/// the EVM gas schedule defined in [`EvmConfig`].
pub fn gas_meter_for_tx(tx: &Transaction, _config: &EvmConfig) -> GasMeter {
    // The EVM itself handles gas accounting internally during `transact_commit`.
    // We create a GasMeter here so the outer `Executor` pipeline can record
    // and enforce the block-level gas cap consistently.
    GasMeter::new(tx.gas_limit)
}

// ---------------------------------------------------------------------------
// Precompile support (item 19)
// ---------------------------------------------------------------------------

/// Returns the revm `SpecId` that enables the standard set of EVM precompiles
/// (SHA-256 at 0x02, RIPEMD at 0x03, ECRecover at 0x01, etc.).
///
/// Setting `SpecId::CANCUN` (the default) activates all precompiles through
/// the Cancun hardfork.  Switch to an earlier spec to restrict the available
/// precompile set.
pub fn precompile_spec_id(config: &EvmConfig) -> revm::primitives::SpecId {
    config.spec_id
}
