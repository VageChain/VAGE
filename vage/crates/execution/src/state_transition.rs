use crate::gas::{self, GasMeter};
use anyhow::{anyhow, bail, Result};
use primitive_types::U256;
use std::sync::Arc;
use vage_state::StateDb;
use vage_types::{Account, Transaction};

pub struct StateTransition {
    pub tx: Transaction,
    pub state: Arc<StateDb>,
    pub gas_meter: GasMeter,
}

pub struct StateTransitionManager {
    state: Arc<StateDb>,
}

impl StateTransition {
    pub fn new(tx: Transaction, state: Arc<StateDb>) -> Self {
        Self {
            gas_meter: GasMeter::new(tx.gas_limit),
            tx,
            state,
        }
    }

    pub fn apply(&mut self) -> Result<[u8; 32]> {
        let _snapshot = self.state.begin_read_only_snapshot();
        let result = (|| {
            self.validate_post_state()?;

            if self.tx.is_contract_creation() {
                self.apply_contract_deploy()?;
            } else if self.tx.is_contract_call() {
                self.apply_contract_call()?;
            } else {
                self.apply_transfer()?;
            }

            self.commit_changes()
        })();

        if result.is_err() {
            self.revert_on_failure()?;
        }

        result
    }

    pub fn apply_transfer(&mut self) -> Result<()> {
        let mut sender = self.load_sender()?;
        let mut receiver = self
            .load_receiver()?
            .ok_or_else(|| anyhow!("receiver does not exist"))?;

        self.charge_upfront_gas(&mut sender)?;
        self.gas_meter.consume(self.gas_meter.gas_cost_transfer())?;
        self.update_sender_balance(&mut sender, self.tx.value)?;
        self.update_receiver_balance(&mut receiver, self.tx.value)?;
        self.increment_nonce(&mut sender);
        self.gas_meter.refund_unused(&mut sender, &self.tx);

        sender.validate()?;
        receiver.validate()?;
        self.state.update_account(&self.tx.from, &sender)?;
        if let Some(address) = self.tx.to {
            self.state.update_account(&address, &receiver)?;
        }
        Ok(())
    }

    pub fn apply_contract_call(&mut self) -> Result<()> {
        let mut sender = self.load_sender()?;
        let mut contract = self
            .load_receiver()?
            .ok_or_else(|| anyhow!("contract account does not exist"))?;
        if !contract.is_contract() {
            bail!("target account is not a deployed contract");
        }

        self.charge_upfront_gas(&mut sender)?;
        self.gas_meter
            .consume(self.gas_meter.gas_cost_contract_call())?;
        self.validate_storage_access_boundaries()?;
        self.update_sender_balance(&mut sender, self.tx.value)?;
        self.update_receiver_balance(&mut contract, self.tx.value)?;
        self.increment_nonce(&mut sender);
        self.gas_meter
            .consume(self.gas_meter.gas_cost_storage_write())?;
        self.write_contract_storage()?;
        self.gas_meter.refund_unused(&mut sender, &self.tx);

        sender.validate()?;
        contract.validate()?;
        self.state.update_account(&self.tx.from, &sender)?;
        if let Some(address) = self.tx.to {
            self.state.update_account(&address, &contract)?;
        }
        Ok(())
    }

    pub fn apply_contract_deploy(&mut self) -> Result<()> {
        let mut sender = self.load_sender()?;
        self.charge_upfront_gas(&mut sender)?;
        self.gas_meter
            .consume(self.gas_meter.gas_cost_contract_call())?;
        self.update_sender_balance(&mut sender, self.tx.value)?;
        self.increment_nonce(&mut sender);
        self.gas_meter.refund_unused(&mut sender, &self.tx);
        sender.validate()?;
        self.state.update_account(&self.tx.from, &sender)?;

        let contract_address =
            vage_types::Address::from(vage_crypto::hash::sha256(&self.tx.hash()));
        let mut contract = self
            .state
            .get_account(&contract_address)?
            .unwrap_or_else(|| Account::new(contract_address));
        contract.increase_balance(self.tx.value);
        contract.apply_contract_deploy(vage_crypto::hash::sha256(&self.tx.data));
        contract.validate()?;
        self.state.update_account(&contract_address, &contract)?;
        Ok(())
    }

    pub fn update_sender_balance(&self, sender: &mut Account, amount: U256) -> Result<()> {
        let (_, overflowed) = amount.overflowing_add(self.tx.gas_cost());
        if overflowed {
            bail!("transaction total cost overflow");
        }
        sender.decrease_balance(amount)
    }

    pub fn update_receiver_balance(&self, receiver: &mut Account, amount: U256) -> Result<()> {
        let (_, overflowed) = receiver.balance.overflowing_add(amount);
        if overflowed {
            bail!("receiver balance overflow");
        }
        receiver.increase_balance(amount);
        Ok(())
    }

    pub fn increment_nonce(&self, sender: &mut Account) {
        sender.increment_nonce();
    }

    pub fn write_contract_storage(&self) -> Result<()> {
        let contract = self
            .tx
            .to
            .ok_or_else(|| anyhow!("missing contract address for storage write"))?;
        self.validate_storage_access_boundaries()?;
        let storage_key = vage_crypto::hash::sha256(&self.tx.data);
        self.state
            .set_storage(&contract, storage_key, self.tx.hash())
    }

    pub fn read_contract_storage(&self) -> Result<Option<[u8; 32]>> {
        let contract = self
            .tx
            .to
            .ok_or_else(|| anyhow!("missing contract address for storage read"))?;
        self.validate_storage_access_boundaries()?;
        let storage_key = vage_crypto::hash::sha256(&self.tx.data);
        self.state.get_storage(&contract, storage_key)
    }

    pub fn calculate_state_root(&self) -> [u8; 32] {
        self.state.state_root()
    }

    pub fn revert_on_failure(&self) -> Result<[u8; 32]> {
        self.state.rollback()?;
        Ok(self.state.state_root())
    }

    pub fn commit_changes(&self) -> Result<[u8; 32]> {
        self.state.commit()
    }

    pub fn validate_post_state(&self) -> Result<()> {
        self.tx.validate_basic()?;
        let sender = self
            .state
            .get_account(&self.tx.from)?
            .ok_or_else(|| anyhow!("sender account does not exist"))?;

        if sender.nonce != self.tx.nonce {
            bail!(
                "nonce mismatch for {}: expected {}, got {}",
                self.tx.from,
                sender.nonce,
                self.tx.nonce
            );
        }

        let intrinsic_gas = gas::calculate_intrinsic_gas(&self.tx.data);
        if self.tx.gas_limit < intrinsic_gas {
            bail!("gas limit too low for intrinsic gas");
        }
        if self.gas_meter.out_of_gas() {
            bail!("gas meter is already exhausted");
        }

        let total_cost = self.tx.value.saturating_add(self.tx.gas_cost());
        let (_, overflowed) = self.tx.value.overflowing_add(self.tx.gas_cost());
        if overflowed {
            bail!("transaction total cost overflow");
        }
        if sender.balance < total_cost {
            bail!("insufficient balance for state transition");
        }

        Ok(())
    }

    fn load_sender(&self) -> Result<Account> {
        self.state
            .get_account(&self.tx.from)?
            .ok_or_else(|| anyhow!("sender account does not exist"))
    }

    fn load_receiver(&self) -> Result<Option<Account>> {
        match self.tx.to {
            Some(address) => Ok(Some(
                self.state
                    .get_account(&address)?
                    .unwrap_or_else(|| Account::new(address)),
            )),
            None => Ok(None),
        }
    }

    fn charge_upfront_gas(&mut self, sender: &mut Account) -> Result<()> {
        self.gas_meter.deduct_fee(sender, &self.tx)?;
        Ok(())
    }

    fn validate_storage_access_boundaries(&self) -> Result<()> {
        if self.tx.data.len() > 4096 {
            bail!("storage access exceeds 4096 byte boundary");
        }
        Ok(())
    }
}

impl StateTransitionManager {
    pub fn new(state: Arc<StateDb>) -> Self {
        Self { state }
    }

    pub fn apply_transactions(
        &self,
        transactions: &[Transaction],
        _root_hash: [u8; 32],
    ) -> Result<[u8; 32]> {
        let mut latest_root = self.state.state_root();
        for tx in transactions {
            let mut transition = StateTransition::new(tx.clone(), self.state.clone());
            latest_root = transition.apply()?;
        }
        Ok(latest_root)
    }
}

#[cfg(test)]
mod tests {
    use super::{GasMeter, StateTransition, StateTransitionManager};
    use crate::gas;
    use ed25519_dalek::SigningKey;
    use primitive_types::U256;
    use std::path::PathBuf;
    use std::sync::Arc;
    use std::time::{SystemTime, UNIX_EPOCH};
    use vage_state::StateDB;
    use vage_storage::{Schema, StorageEngine};
    use vage_types::{Account, Address, Transaction};

    fn temp_db_path(name: &str) -> PathBuf {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time should be after unix epoch")
            .as_nanos();
        std::env::temp_dir().join(format!("vage-state-transition-{name}-{unique}.redb"))
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

    fn signed_transfer(from_key: &SigningKey, to: Address, value: u64, nonce: u64) -> Transaction {
        let from = Address::from_public_key(&from_key.verifying_key().to_bytes());
        let mut tx = Transaction::new_transfer(from, to, U256::from(value), nonce);
        tx.sign(from_key)
            .expect("transaction signing should succeed");
        tx
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
    fn gas_meter_helpers_cover_limits_fees_and_refunds() {
        let tx =
            Transaction::new_transfer(Address([1u8; 32]), Address([2u8; 32]), U256::from(1u64), 0);
        // Use a fixed limit large enough that consume(1_000) succeeds.
        let gas_limit = 10_000u64;
        let mut gas_meter = GasMeter::new(gas_limit);
        let mut account = funded_account(Address([1u8; 32]), 100_000);

        gas_meter
            .consume(1_000)
            .expect("gas consume should succeed");
        assert_eq!(gas_meter.remaining(), gas_limit - 1_000);
        assert!(!gas_meter.out_of_gas());
        assert_eq!(gas_meter.calculate_fee(&tx), U256::from(1_000u64));
        assert_eq!(gas_meter.gas_cost_transfer(), gas::VALUE_TRANSFER_GAS);
        assert_eq!(gas_meter.gas_cost_storage_read(), gas::STORAGE_READ_GAS);
        assert_eq!(gas_meter.gas_cost_storage_write(), gas::STORAGE_WRITE_GAS);
        assert_eq!(
            gas_meter.gas_cost_contract_call(),
            gas::INTRINSIC_GAS + gas::STORAGE_READ_GAS + gas::STORAGE_WRITE_GAS
        );

        // Build a fee transaction whose gas_limit matches the meter limit.
        let fee_tx = {
            let mut t = Transaction::new_transfer(
                Address([1u8; 32]),
                Address([2u8; 32]),
                U256::from(1u64),
                0,
            );
            t.gas_limit = gas_limit;
            t
        };
        let prepaid = gas_meter
            .deduct_fee(&mut account, &fee_tx)
            .expect("fee deduction should succeed");
        assert_eq!(prepaid, fee_tx.gas_cost());
        let refund = gas_meter.refund_unused(&mut account, &fee_tx);
        assert_eq!(refund, fee_tx.gas_cost() - U256::from(1_000u64));
        gas_meter.refund(500);
        assert_eq!(gas_meter.gas_used, 500);
        gas_meter.reset();
        assert_eq!(gas_meter.gas_used, 0);
    }

    #[test]
    fn new_and_apply_transfer_update_balances_nonce_and_root() {
        let (storage, state, path) = test_state("apply-transfer");
        let sender_key = signing_key(1);
        let sender = Address::from_public_key(&sender_key.verifying_key().to_bytes());
        let receiver = Address([3u8; 32]);
        state
            .update_account(&sender, &funded_account(sender, 400_000))
            .expect("sender update should succeed");
        state
            .update_account(&receiver, &funded_account(receiver, 25))
            .expect("receiver update should succeed");

        let tx = signed_transfer(&sender_key, receiver, 1_500, 0);
        let mut transition = StateTransition::new(tx.clone(), state.clone());
        assert_eq!(transition.tx.hash(), tx.hash());
        assert_eq!(transition.gas_meter.gas_limit, tx.gas_limit);

        let root = transition.apply().expect("transfer apply should succeed");
        assert_eq!(root, state.state_root());
        assert_eq!(
            state.get_nonce(&sender).expect("nonce read should succeed"),
            1
        );
        assert_eq!(
            state
                .get_balance(&receiver)
                .expect("receiver balance read should succeed"),
            U256::from(1_525u64)
        );

        cleanup(storage, state, path);
    }

    #[test]
    fn contract_call_helpers_read_and_write_storage_and_apply() {
        let (storage, state, path) = test_state("apply-contract-call");
        let sender_key = signing_key(2);
        let sender = Address::from_public_key(&sender_key.verifying_key().to_bytes());
        let contract = Address([4u8; 32]);
        let data = vec![7u8, 8, 9];

        state
            .update_account(&sender, &funded_account(sender, 500_000))
            .expect("sender update should succeed");
        let mut contract_account = funded_account(contract, 0);
        contract_account.apply_contract_deploy([6u8; 32]);
        state
            .update_account(&contract, &contract_account)
            .expect("contract update should succeed");

        let tx = signed_contract_call(&sender_key, contract, 900, 0, data.clone());
        let transition = StateTransition::new(tx.clone(), state.clone());
        transition
            .write_contract_storage()
            .expect("storage write should succeed");
        assert_eq!(
            transition
                .read_contract_storage()
                .expect("storage read should succeed"),
            Some(tx.hash())
        );

        let mut transition = StateTransition::new(tx.clone(), state.clone());
        let root = transition
            .apply_contract_call()
            .and_then(|_| transition.commit_changes())
            .expect("contract call should succeed");
        assert_eq!(root, state.state_root());
        assert_eq!(
            state
                .get_balance(&contract)
                .expect("contract balance read should succeed"),
            U256::from(900u64)
        );
        assert_eq!(
            state
                .get_nonce(&sender)
                .expect("sender nonce read should succeed"),
            1
        );

        cleanup(storage, state, path);
    }

    #[test]
    fn contract_deploy_apply_creates_contract_without_double_charging() {
        let (storage, state, path) = test_state("apply-contract-deploy");
        let sender_key = signing_key(3);
        let sender = Address::from_public_key(&sender_key.verifying_key().to_bytes());
        let code = vec![1u8, 2, 3, 4];
        state
            .update_account(&sender, &funded_account(sender, 2_500_000))
            .expect("sender update should succeed");

        let tx = signed_contract_deploy(&sender_key, 500, 0, code.clone());
        let mut transition = StateTransition::new(tx.clone(), state.clone());
        let root = transition
            .apply()
            .expect("contract deploy apply should succeed");

        let contract_address = Address::from(vage_crypto::hash::sha256(&tx.hash()));
        let contract = state
            .get_account(&contract_address)
            .expect("contract load should succeed")
            .expect("contract should exist");
        assert_eq!(root, state.state_root());
        assert!(contract.is_contract());
        assert_eq!(contract.balance, U256::from(500u64));
        assert_eq!(
            state
                .get_nonce(&sender)
                .expect("sender nonce read should succeed"),
            1
        );

        cleanup(storage, state, path);
    }

    #[test]
    fn helper_methods_cover_balance_updates_commit_revert_and_validation() {
        let (storage, state, path) = test_state("helpers");
        let sender_key = signing_key(4);
        let sender = Address::from_public_key(&sender_key.verifying_key().to_bytes());
        let receiver = Address([9u8; 32]);
        state
            .update_account(&sender, &funded_account(sender, 300_000))
            .expect("sender update should succeed");
        state
            .update_account(&receiver, &funded_account(receiver, 50))
            .expect("receiver update should succeed");

        let tx = signed_transfer(&sender_key, receiver, 750, 0);
        let transition = StateTransition::new(tx.clone(), state.clone());
        transition
            .validate_post_state()
            .expect("post state validation should succeed");

        let mut sender_account = state
            .get_account(&sender)
            .expect("sender read should succeed")
            .expect("sender should exist");
        let mut receiver_account = state
            .get_account(&receiver)
            .expect("receiver read should succeed")
            .expect("receiver should exist");
        transition
            .update_sender_balance(&mut sender_account, tx.value)
            .expect("sender balance update should succeed");
        transition
            .update_receiver_balance(&mut receiver_account, tx.value)
            .expect("receiver balance update should succeed");
        transition.increment_nonce(&mut sender_account);
        assert_eq!(sender_account.nonce, 1);
        assert_eq!(receiver_account.balance, U256::from(800u64));

        let committed_root = transition.commit_changes().expect("commit should succeed");
        assert_eq!(transition.calculate_state_root(), committed_root);

        state
            .set_balance(&receiver, U256::from(999u64))
            .expect("balance mutation should succeed");
        let reverted_root = transition
            .revert_on_failure()
            .expect("revert should succeed");
        assert_eq!(reverted_root, committed_root);
        assert_eq!(
            state
                .get_balance(&receiver)
                .expect("receiver balance read should succeed"),
            U256::from(50u64)
        );

        let mut bad_nonce_tx = tx.clone();
        bad_nonce_tx.nonce = 7;
        let bad_nonce_transition = StateTransition::new(bad_nonce_tx, state.clone());
        assert!(bad_nonce_transition.validate_post_state().is_err());

        cleanup(storage, state, path);
    }

    #[test]
    fn manager_applies_transactions_and_rejects_invalid_contract_targets() {
        let (storage, state, path) = test_state("manager");
        let sender_key = signing_key(5);
        let sender = Address::from_public_key(&sender_key.verifying_key().to_bytes());
        let receiver = Address([10u8; 32]);
        let plain_account = Address([11u8; 32]);
        state
            .update_account(&sender, &funded_account(sender, 500_000))
            .expect("sender update should succeed");
        state
            .update_account(&receiver, &funded_account(receiver, 0))
            .expect("receiver update should succeed");
        state
            .update_account(&plain_account, &funded_account(plain_account, 0))
            .expect("plain account update should succeed");

        let tx = signed_transfer(&sender_key, receiver, 1_000, 0);
        let manager = StateTransitionManager::new(state.clone());
        let root = manager
            .apply_transactions(&[tx], state.state_root())
            .expect("manager apply should succeed");
        assert_eq!(root, state.state_root());

        let call_tx = signed_contract_call(&sender_key, plain_account, 1, 1, vec![1u8]);
        let mut transition = StateTransition::new(call_tx, state.clone());
        assert!(transition.apply_contract_call().is_err());

        cleanup(storage, state, path);
    }
}
