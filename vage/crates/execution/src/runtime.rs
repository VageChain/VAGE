use crate::gas::{self, GasMeter};
use anyhow::{anyhow, bail, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use vage_crypto::hash::sha256;
use vage_state::{StateBatchOp, StateDb};
use vage_types::{Address, Log, Transaction};

const CONTRACT_CODE_PREFIX: &[u8] = b"contract:code:";
const MAX_CONTRACT_SIZE: usize = 24 * 1024;
const MAX_STORAGE_ACCESS_SIZE: usize = 4 * 1024;
const MAX_EXECUTION_STEPS: usize = 10_000;
const STEP_GAS_COST: u64 = 8;

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct ExecutionResult {
    pub status: bool,
    pub gas_used: u64,
    pub logs: Vec<Log>,
    pub return_data: Vec<u8>,
}

impl ExecutionResult {
    pub fn success(gas_used: u64, return_data: Vec<u8>) -> Self {
        Self {
            status: true,
            gas_used,
            logs: Vec::new(),
            return_data,
        }
    }

    pub fn failure(gas_used: u64, return_data: Vec<u8>) -> Self {
        Self {
            status: false,
            gas_used,
            logs: Vec::new(),
            return_data,
        }
    }

    pub fn add_log(&mut self, log: Log) {
        self.logs.push(log);
    }

    pub fn encode(&self) -> Vec<u8> {
        bincode::serialize(self).unwrap_or_default()
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        Ok(bincode::deserialize(bytes)?)
    }

    pub fn hash(&self) -> [u8; 32] {
        sha256(&self.encode())
    }
}

#[derive(Clone, Debug, Default)]
pub struct ExecutionEnvironment {
    pub contract_address: Option<Address>,
    pub caller: Option<Address>,
    pub gas_limit: u64,
    pub gas_used: u64,
    pub emitted_logs: Vec<Log>,
    pub last_return_data: Vec<u8>,
    pub revert_reason: Option<String>,
    pub aborted: bool,
}

pub struct Runtime {
    pub environment: Mutex<ExecutionEnvironment>,
    pub contract_cache: Mutex<HashMap<[u8; 32], Vec<u8>>>,
}

impl Default for Runtime {
    fn default() -> Self {
        Self::new()
    }
}

impl Runtime {
    pub fn new() -> Self {
        Self {
            environment: Mutex::new(ExecutionEnvironment::default()),
            contract_cache: Mutex::new(HashMap::new()),
        }
    }

    pub fn execute_transaction(&self, state: &Arc<StateDb>, tx: &Transaction) -> Result<u64> {
        self.validate_account_existence(state, tx)?;

        if tx.is_contract_creation() {
            self.deploy_contract(state, tx)?;
        } else if tx.is_contract_call() {
            self.execute_contract_call(state, tx)?;
        }

        Ok(gas::calculate_intrinsic_gas(&tx.data))
    }

    pub fn execute_contract_call(&self, state: &Arc<StateDb>, tx: &Transaction) -> Result<Vec<u8>> {
        let contract_address = tx
            .to
            .ok_or_else(|| anyhow!("contract call missing recipient address"))?;
        let contract_account = state
            .get_account(&contract_address)?
            .ok_or_else(|| anyhow!("contract account not found: {}", contract_address))?;
        if !contract_account.is_contract() {
            bail!(
                "target account is not a deployed contract: {}",
                contract_address
            );
        }

        let contract = self
            .load_contract(state, contract_account.code_hash)?
            .ok_or_else(|| {
                anyhow!(
                    "contract code missing for hash {:x?}",
                    contract_account.code_hash
                )
            })?;

        let mut gas_meter = GasMeter::new(tx.gas_limit);
        let gas_used = self.meter_execution_gas(&mut gas_meter, &contract, &tx.data)?;
        let output = self.sandbox_execution(&contract, &tx.data, &mut gas_meter)?;
        let storage_key = self.validate_storage_access_boundaries(&tx.data)?;
        let storage_value = sha256(&output);
        state.set_storage(&contract_address, storage_key, storage_value)?;

        {
            let mut environment = self.environment.lock().unwrap();
            environment.contract_address = Some(contract_address);
            environment.caller = Some(tx.from);
            environment.gas_limit = tx.gas_limit;
            environment.gas_used = gas_used;
            environment.aborted = false;
            environment.revert_reason = None;
        }

        let logs =
            self.generate_execution_logs(contract_address, tx.hash(), output.clone(), gas_used);
        for log in logs {
            self.emit_event(log.address, log.topics.clone(), log.data.clone())?;
        }

        Ok(self.return_data(output))
    }

    pub fn deploy_contract(&self, state: &Arc<StateDb>, tx: &Transaction) -> Result<[u8; 32]> {
        self.validate_account_existence(state, tx)?;
        self.validate_contract_bytecode(&tx.data)?;
        let code_hash = sha256(&tx.data);
        self.store_contract(state, code_hash, tx.data.clone())?;

        let mut environment = self.environment.lock().unwrap();
        environment.contract_address = tx.to;
        environment.caller = Some(tx.from);
        environment.gas_limit = tx.gas_limit;
        environment.gas_used = gas::calculate_intrinsic_gas(&tx.data);
        environment.aborted = false;
        environment.revert_reason = None;

        Ok(code_hash)
    }

    pub fn load_contract(
        &self,
        state: &Arc<StateDb>,
        code_hash: [u8; 32],
    ) -> Result<Option<Vec<u8>>> {
        if let Some(code) = self.contract_cache.lock().unwrap().get(&code_hash).cloned() {
            return Ok(Some(code));
        }

        let key = Self::contract_code_key(&code_hash);
        let values = state.parallel_state_reads(&[key])?;
        let Some(Some(code)) = values.into_iter().next() else {
            return Ok(None);
        };

        self.contract_cache
            .lock()
            .unwrap()
            .insert(code_hash, code.clone());
        Ok(Some(code))
    }

    pub fn store_contract(
        &self,
        state: &Arc<StateDb>,
        code_hash: [u8; 32],
        code: Vec<u8>,
    ) -> Result<()> {
        self.validate_contract_bytecode(&code)?;
        state.write_batch(vec![StateBatchOp::Put(
            Self::contract_code_key(&code_hash),
            code.clone(),
        )])?;
        self.contract_cache.lock().unwrap().insert(code_hash, code);
        Ok(())
    }

    pub fn invoke_method(&self, contract: &[u8], input: &[u8]) -> Result<Vec<u8>> {
        if contract.is_empty() {
            bail!("cannot invoke method on empty contract");
        }
        self.detect_infinite_execution_loops(contract, input)?;

        let mut result = Vec::with_capacity(32);
        let mut payload = Vec::with_capacity(contract.len() + input.len());
        payload.extend_from_slice(contract);
        payload.extend_from_slice(input);
        result.extend_from_slice(&sha256(&payload));
        Ok(result)
    }

    pub fn validate_contract_bytecode(&self, code: &[u8]) -> Result<()> {
        if code.is_empty() {
            bail!("contract bytecode cannot be empty");
        }
        if code.len() > MAX_CONTRACT_SIZE {
            bail!("contract bytecode exceeds {} bytes", MAX_CONTRACT_SIZE);
        }
        if code.iter().all(|byte| *byte == 0) {
            bail!("contract bytecode cannot be all zeroes");
        }
        if code.len() >= 2 && code.windows(2).all(|window| window == [0xff, 0xff]) {
            bail!("contract bytecode contains an invalid repeating halt pattern");
        }
        Ok(())
    }

    pub fn meter_execution_gas(
        &self,
        gas_meter: &mut GasMeter,
        contract: &[u8],
        input: &[u8],
    ) -> Result<u64> {
        let execution_cost = gas::calculate_intrinsic_gas(input)
            .saturating_add((contract.len() as u64).saturating_mul(4))
            .saturating_add((input.len() as u64).saturating_mul(8));
        gas_meter.consume(execution_cost)?;
        Ok(gas_meter.gas_used)
    }

    pub fn detect_infinite_execution_loops(&self, contract: &[u8], input: &[u8]) -> Result<()> {
        let steps = contract.len().saturating_add(input.len());
        if steps > MAX_EXECUTION_STEPS {
            bail!(
                "execution aborted: potential infinite loop detected at {} steps",
                steps
            );
        }
        Ok(())
    }

    pub fn generate_execution_logs(
        &self,
        address: Address,
        tx_hash: [u8; 32],
        output: Vec<u8>,
        gas_used: u64,
    ) -> Vec<Log> {
        let mut payload = Vec::with_capacity(8 + output.len());
        payload.extend_from_slice(&gas_used.to_le_bytes());
        payload.extend_from_slice(&output);
        vec![Log::new(address, vec![tx_hash, sha256(&payload)], payload)]
    }

    pub fn emit_event(
        &self,
        address: Address,
        topics: Vec<[u8; 32]>,
        data: Vec<u8>,
    ) -> Result<Log> {
        let log = Log::new(address, topics, data);
        self.environment
            .lock()
            .unwrap()
            .emitted_logs
            .push(log.clone());
        Ok(log)
    }

    pub fn abort_execution(&self, reason: impl Into<String>) -> Result<()> {
        let reason = reason.into();
        let mut environment = self.environment.lock().unwrap();
        environment.aborted = true;
        environment.revert_reason = Some(reason.clone());
        bail!("execution aborted: {}", reason);
    }

    pub fn return_data(&self, data: Vec<u8>) -> Vec<u8> {
        self.environment.lock().unwrap().last_return_data = data.clone();
        data
    }

    pub fn handle_revert(&self, reason: impl Into<String>) -> Result<Vec<u8>> {
        let reason = reason.into();
        let mut environment = self.environment.lock().unwrap();
        environment.aborted = true;
        environment.revert_reason = Some(reason.clone());
        let bytes = reason.into_bytes();
        environment.last_return_data = bytes.clone();
        Ok(bytes)
    }

    pub fn sandbox_execution(
        &self,
        contract: &[u8],
        input: &[u8],
        gas_meter: &mut GasMeter,
    ) -> Result<Vec<u8>> {
        self.validate_contract_bytecode(contract)?;
        self.detect_infinite_execution_loops(contract, input)?;

        let mut payload = Vec::with_capacity(contract.len() + input.len());
        payload.extend_from_slice(contract);
        payload.extend_from_slice(input);

        for _ in payload.chunks(32) {
            gas_meter.consume(STEP_GAS_COST)?;
        }

        self.invoke_method(contract, input)
    }

    fn validate_storage_access_boundaries(&self, input: &[u8]) -> Result<[u8; 32]> {
        if input.len() > MAX_STORAGE_ACCESS_SIZE {
            bail!(
                "storage access payload exceeds {} bytes",
                MAX_STORAGE_ACCESS_SIZE
            );
        }

        let key = sha256(input);
        if key.len() != 32 {
            bail!("invalid storage key length");
        }
        Ok(key)
    }

    fn contract_code_key(code_hash: &[u8; 32]) -> Vec<u8> {
        let mut key = Vec::with_capacity(CONTRACT_CODE_PREFIX.len() + code_hash.len());
        key.extend_from_slice(CONTRACT_CODE_PREFIX);
        key.extend_from_slice(code_hash);
        key
    }

    fn validate_account_existence(&self, state: &Arc<StateDb>, tx: &Transaction) -> Result<()> {
        if state.get_account(&tx.from)?.is_none() {
            bail!("sender account does not exist: {}", tx.from);
        }

        if let Some(address) = tx.to {
            if tx.is_contract_call() && state.get_account(&address)?.is_none() {
                bail!("recipient account does not exist: {}", address);
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::{ExecutionResult, Runtime, STEP_GAS_COST};
    use crate::gas::{self, GasMeter};
    use ed25519_dalek::SigningKey;
    use primitive_types::U256;
    use std::path::PathBuf;
    use std::sync::Arc;
    use std::time::{SystemTime, UNIX_EPOCH};
    use vage_crypto::hash::sha256;
    use vage_state::StateDB;
    use vage_storage::{Schema, StorageEngine};
    use vage_types::{Account, Address, Transaction};

    fn temp_db_path(name: &str) -> PathBuf {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time should be after unix epoch")
            .as_nanos();
        std::env::temp_dir().join(format!("vage-runtime-{name}-{unique}.redb"))
    }

    fn test_state(name: &str) -> (Arc<StorageEngine>, Arc<StateDB>, PathBuf) {
        let path = temp_db_path(name);
        Schema::init(&path).expect("schema should initialize");
        let storage = Arc::new(StorageEngine::new(&path).expect("storage should initialize"));
        let state = Arc::new(StateDB::new(storage.clone()));
        (storage, state, path)
    }

    fn cleanup(storage: Arc<StorageEngine>, state: Arc<StateDB>, path: PathBuf) {
        drop(state);
        drop(storage);
        let _ = std::fs::remove_file(path);
    }

    fn signing_key(byte: u8) -> SigningKey {
        SigningKey::from_bytes(&[byte; 32])
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

    fn signed_contract_deploy(
        from_key: &SigningKey,
        value: u64,
        nonce: u64,
        code: Vec<u8>,
    ) -> Transaction {
        let from = Address::from_public_key(&from_key.verifying_key().to_bytes());
        let mut tx = Transaction::new_contract_deploy(from, U256::from(value), nonce, code);
        tx.sign(from_key)
            .expect("transaction signing should succeed");
        tx
    }

    #[test]
    fn execution_result_helpers_round_trip_and_hash() {
        let mut success = ExecutionResult::success(21_000, vec![1, 2, 3]);
        let failure = ExecutionResult::failure(5_000, vec![4, 5]);
        let log = vage_types::Log::new(Address([1u8; 32]), vec![[2u8; 32]], vec![9]);
        success.add_log(log.clone());

        let encoded = success.encode();
        let decoded = ExecutionResult::decode(&encoded).expect("decode should succeed");

        assert!(success.status);
        assert!(!failure.status);
        assert_eq!(decoded.logs, vec![log]);
        assert_eq!(success.hash(), sha256(&encoded));
    }

    #[test]
    fn new_store_load_and_deploy_contract_work() {
        let (storage, state, path) = test_state("deploy-load-store");
        let runtime = Runtime::new();
        let sender_key = signing_key(1);
        let sender = Address::from_public_key(&sender_key.verifying_key().to_bytes());
        state
            .update_account(&sender, &funded_account(sender, 1_000_000))
            .expect("sender update should succeed");

        let code = vec![1u8, 2, 3, 4];
        let code_hash = sha256(&code);
        runtime
            .store_contract(&state, code_hash, code.clone())
            .expect("store contract should succeed");
        assert_eq!(
            runtime
                .load_contract(&state, code_hash)
                .expect("load contract should succeed"),
            Some(code.clone())
        );

        let deploy_tx = signed_contract_deploy(&sender_key, 0, 0, code.clone());
        let deployed_hash = runtime
            .deploy_contract(&state, &deploy_tx)
            .expect("deploy contract should succeed");
        assert_eq!(deployed_hash, code_hash);

        let environment = runtime.environment.lock().unwrap().clone();
        assert_eq!(environment.caller, Some(sender));
        assert_eq!(environment.gas_limit, deploy_tx.gas_limit);
        assert_eq!(
            environment.gas_used,
            gas::calculate_intrinsic_gas(&deploy_tx.data)
        );

        cleanup(storage, state, path);
    }

    #[test]
    fn invoke_validate_meter_logs_emit_abort_return_revert_and_sandbox_work() {
        let runtime = Runtime::new();
        let contract = vec![1u8, 2, 3, 4];
        let input = vec![5u8, 6, 7];

        runtime
            .validate_contract_bytecode(&contract)
            .expect("bytecode validation should succeed");
        let output = runtime
            .invoke_method(&contract, &input)
            .expect("invoke method should succeed");
        assert_eq!(
            output,
            sha256(&[contract.clone(), input.clone()].concat()).to_vec()
        );

        let mut gas_meter = GasMeter::new(200_000);
        let gas_used = runtime
            .meter_execution_gas(&mut gas_meter, &contract, &input)
            .expect("gas metering should succeed");
        assert_eq!(
            gas_used,
            gas::calculate_intrinsic_gas(&input)
                + (contract.len() as u64 * 4)
                + (input.len() as u64 * 8)
        );

        let logs = runtime.generate_execution_logs(
            Address([8u8; 32]),
            [9u8; 32],
            output.clone(),
            gas_used,
        );
        assert_eq!(logs.len(), 1);
        assert_eq!(logs[0].address, Address([8u8; 32]));
        assert_eq!(logs[0].topics[0], [9u8; 32]);

        let emitted = runtime
            .emit_event(Address([10u8; 32]), vec![[11u8; 32]], vec![1, 2])
            .expect("emit event should succeed");
        assert_eq!(emitted.address, Address([10u8; 32]));
        assert_eq!(runtime.environment.lock().unwrap().emitted_logs.len(), 1);

        let returned = runtime.return_data(vec![4, 3, 2, 1]);
        assert_eq!(returned, vec![4, 3, 2, 1]);
        assert_eq!(
            runtime.environment.lock().unwrap().last_return_data,
            vec![4, 3, 2, 1]
        );

        let reverted = runtime
            .handle_revert("boom")
            .expect("handle revert should succeed");
        assert_eq!(reverted, b"boom".to_vec());
        assert!(runtime.environment.lock().unwrap().aborted);
        assert_eq!(
            runtime.environment.lock().unwrap().revert_reason.as_deref(),
            Some("boom")
        );

        let sandbox_output = runtime
            .sandbox_execution(&contract, &input, &mut GasMeter::new(200_000))
            .expect("sandbox execution should succeed");
        assert_eq!(sandbox_output, output);

        let mut tight_meter = GasMeter::new(STEP_GAS_COST - 1);
        assert!(runtime
            .sandbox_execution(&contract, &input, &mut tight_meter)
            .is_err());
        assert!(runtime.abort_execution("stop now").is_err());
    }

    #[test]
    fn execute_contract_call_and_execute_transaction_update_state_and_environment() {
        let (storage, state, path) = test_state("execute-contract-call");
        let runtime = Runtime::new();
        let sender_key = signing_key(2);
        let sender = Address::from_public_key(&sender_key.verifying_key().to_bytes());
        let contract = Address([12u8; 32]);
        let code = vec![1u8, 3, 5, 7];
        let code_hash = sha256(&code);
        let input = vec![9u8, 8, 7, 6];

        state
            .update_account(&sender, &funded_account(sender, 1_000_000))
            .expect("sender update should succeed");
        runtime
            .store_contract(&state, code_hash, code.clone())
            .expect("store contract should succeed");
        let mut contract_account = funded_account(contract, 0);
        contract_account.apply_contract_deploy(code_hash);
        state
            .update_account(&contract, &contract_account)
            .expect("contract account update should succeed");

        let tx = signed_contract_call(&sender_key, contract, 0, 0, input.clone());
        let output = runtime
            .execute_contract_call(&state, &tx)
            .expect("execute contract call should succeed");
        assert_eq!(
            output,
            sha256(&[code.clone(), input.clone()].concat()).to_vec()
        );
        let storage_key = sha256(&input);
        assert_eq!(
            state
                .get_storage(&contract, storage_key)
                .expect("storage read should succeed"),
            Some(sha256(&output))
        );

        let environment = runtime.environment.lock().unwrap().clone();
        assert_eq!(environment.contract_address, Some(contract));
        assert_eq!(environment.caller, Some(sender));
        assert_eq!(environment.gas_limit, tx.gas_limit);
        assert!(!environment.emitted_logs.is_empty());

        let gas_used = runtime
            .execute_transaction(&state, &tx)
            .expect("execute transaction should succeed");
        assert_eq!(gas_used, gas::calculate_intrinsic_gas(&tx.data));

        cleanup(storage, state, path);
    }

    #[test]
    fn runtime_rejects_invalid_contract_inputs() {
        let (storage, state, path) = test_state("runtime-invalid-inputs");
        let runtime = Runtime::new();
        let sender_key = signing_key(3);
        let sender = Address::from_public_key(&sender_key.verifying_key().to_bytes());
        let contract = Address([13u8; 32]);
        state
            .update_account(&sender, &funded_account(sender, 500_000))
            .expect("sender update should succeed");
        state
            .update_account(&contract, &funded_account(contract, 0))
            .expect("contract placeholder update should succeed");

        assert!(runtime.validate_contract_bytecode(&[]).is_err());
        assert!(runtime.validate_contract_bytecode(&[0u8; 8]).is_err());
        runtime
            .validate_contract_bytecode(&[0x01])
            .expect("single-byte bytecode should be valid");
        assert!(runtime.invoke_method(&[], &[1u8]).is_err());
        assert!(runtime
            .detect_infinite_execution_loops(&[1u8; 10_001], &[])
            .is_err());

        let bad_call = signed_contract_call(&sender_key, contract, 0, 0, vec![1u8; 5_000]);
        assert!(runtime.execute_contract_call(&state, &bad_call).is_err());

        cleanup(storage, state, path);
    }

    #[test]
    fn runtime_rejects_missing_accounts_and_enforces_storage_and_step_gas_limits() {
        let (storage, state, path) = test_state("runtime-guards");
        let runtime = Runtime::new();
        let sender_key = signing_key(4);
        let sender = Address::from_public_key(&sender_key.verifying_key().to_bytes());
        let contract = Address([14u8; 32]);

        let missing_sender_deploy = signed_contract_deploy(&sender_key, 0, 0, vec![1u8]);
        assert!(runtime
            .execute_transaction(&state, &missing_sender_deploy)
            .is_err());

        state
            .update_account(&sender, &funded_account(sender, 500_000))
            .expect("sender update should succeed");
        let missing_contract_call = signed_contract_call(&sender_key, contract, 0, 0, vec![1u8]);
        assert!(runtime
            .execute_transaction(&state, &missing_contract_call)
            .is_err());

        let code = vec![1u8; 64];
        let code_hash = sha256(&code);
        runtime
            .store_contract(&state, code_hash, code.clone())
            .expect("store contract should succeed");
        let mut contract_account = funded_account(contract, 0);
        contract_account.apply_contract_deploy(code_hash);
        state
            .update_account(&contract, &contract_account)
            .expect("contract account update should succeed");

        let oversized_call = signed_contract_call(&sender_key, contract, 0, 0, vec![2u8; 4_097]);
        assert!(runtime
            .execute_contract_call(&state, &oversized_call)
            .is_err());

        let mut low_step_gas = GasMeter::new(STEP_GAS_COST.saturating_sub(1));
        assert!(runtime
            .sandbox_execution(&code, &[1u8; 32], &mut low_step_gas)
            .is_err());

        cleanup(storage, state, path);
    }
}
