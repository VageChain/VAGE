use crate::Address;
use anyhow::{bail, Result};
use primitive_types::U256;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Account {
    pub address: Address,
    pub balance: U256,
    pub nonce: u64,
    pub code_hash: [u8; 32],
    pub storage_root: [u8; 32],
}

impl Account {
    /// Create a new empty account with a given address.
    pub fn new(address: Address) -> Self {
        Self {
            address,
            balance: U256::zero(),
            nonce: 0,
            code_hash: [0u8; 32],    // Empty hash
            storage_root: [0u8; 32], // Empty root
        }
    }

    /// Create an empty system account for genesis initialization.
    pub fn empty() -> Self {
        Self::new(Address::zero())
    }

    /// Increase the account balance.
    pub fn increase_balance(&mut self, amount: U256) {
        self.balance = self.balance.saturating_add(amount);
    }

    /// Decrease the account balance with overflow/underflow checks.
    pub fn decrease_balance(&mut self, amount: U256) -> Result<()> {
        if self.balance < amount {
            bail!("Insufficient balance for address {}", self.address);
        }
        self.balance -= amount;
        Ok(())
    }

    /// Apply a value transfer update to the account.
    pub fn apply_transfer(&mut self, amount: U256) {
        self.increase_balance(amount);
    }

    /// Increment the account nonce after a successful transaction.
    pub fn increment_nonce(&mut self) {
        self.nonce = self.nonce.saturating_add(1);
    }

    /// Set the code hash for contract accounts.
    pub fn set_code_hash(&mut self, hash: [u8; 32]) {
        self.code_hash = hash;
    }

    /// Mark an account as a contract by deploying its code hash.
    pub fn apply_contract_deploy(&mut self, code_hash: [u8; 32]) {
        self.set_code_hash(code_hash);
    }

    /// Set the root hash of the account's internal storage tree.
    pub fn set_storage_root(&mut self, root: [u8; 32]) {
        self.storage_root = root;
    }

    /// Check if this account represents a smart contract.
    pub fn is_contract(&self) -> bool {
        self.code_hash != [0u8; 32]
    }

    /// Calculate the canonical hash of the account for state commitments.
    pub fn hash(&self) -> [u8; 32] {
        let bytes = bincode::serialize(self).expect("account serialization should succeed");
        let mut hasher = Sha256::new();
        hasher.update(&bytes);
        let result = hasher.finalize();
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&result);
        bytes
    }

    /// Validate the account state for transition correctness.
    pub fn validate(&self) -> Result<()> {
        // Validation logic for state transitions
        if self.nonce == u64::MAX {
            bail!("Account nonce exhausted");
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::Account;
    use crate::Address;
    use primitive_types::U256;

    #[test]
    fn new_and_empty_accounts_start_with_zeroed_state() {
        let address = Address([9u8; 32]);
        let account = Account::new(address);
        let empty = Account::empty();

        assert_eq!(account.address, address);
        assert_eq!(account.balance, U256::zero());
        assert_eq!(account.nonce, 0);
        assert_eq!(account.code_hash, [0u8; 32]);
        assert_eq!(account.storage_root, [0u8; 32]);
        assert_eq!(empty.address, Address::zero());
    }

    #[test]
    fn balance_updates_and_transfer_are_applied() {
        let mut account = Account::new(Address([1u8; 32]));

        account.increase_balance(U256::from(25u64));
        account.apply_transfer(U256::from(5u64));

        assert_eq!(account.balance, U256::from(30u64));
    }

    #[test]
    fn decrease_balance_rejects_underflow() {
        let mut account = Account::new(Address([2u8; 32]));
        account.increase_balance(U256::from(10u64));

        account
            .decrease_balance(U256::from(4u64))
            .expect("sufficient balance should succeed");

        assert_eq!(account.balance, U256::from(6u64));
        assert!(account.decrease_balance(U256::from(7u64)).is_err());
    }

    #[test]
    fn nonce_and_contract_fields_update() {
        let mut account = Account::new(Address([3u8; 32]));
        let code_hash = [5u8; 32];
        let storage_root = [7u8; 32];

        account.increment_nonce();
        account.set_code_hash(code_hash);
        account.set_storage_root(storage_root);

        assert_eq!(account.nonce, 1);
        assert_eq!(account.code_hash, code_hash);
        assert_eq!(account.storage_root, storage_root);
        assert!(account.is_contract());
    }

    #[test]
    fn apply_contract_deploy_marks_account_as_contract() {
        let mut account = Account::new(Address([4u8; 32]));
        let deployed_hash = [8u8; 32];

        account.apply_contract_deploy(deployed_hash);

        assert_eq!(account.code_hash, deployed_hash);
        assert!(account.is_contract());
    }

    #[test]
    fn hash_and_bincode_are_deterministic() {
        let mut account = Account::new(Address([6u8; 32]));
        account.increase_balance(U256::from(99u64));
        account.increment_nonce();

        let first_hash = account.hash();
        let second_hash = account.hash();
        let encoded = bincode::serialize(&account).expect("bincode serialization should work");
        let decoded: Account =
            bincode::deserialize(&encoded).expect("bincode deserialization should work");

        assert_eq!(first_hash, second_hash);
        assert_eq!(decoded, account);
    }

    #[test]
    fn validate_rejects_exhausted_nonce() {
        let mut account = Account::new(Address([7u8; 32]));
        account.nonce = u64::MAX;

        assert!(account.validate().is_err());
    }

    #[test]
    fn serde_round_trip_preserves_account_fields() {
        let mut account = Account::new(Address([10u8; 32]));
        account.increase_balance(U256::from(123u64));
        account.nonce = 9;
        account.set_code_hash([11u8; 32]);
        account.set_storage_root([12u8; 32]);

        let json = serde_json::to_string(&account).expect("json serialization should work");
        let decoded: Account =
            serde_json::from_str(&json).expect("json deserialization should work");

        assert_eq!(decoded, account);
    }
}
