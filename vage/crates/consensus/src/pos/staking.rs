use anyhow::{bail, Result};
use primitive_types::U256;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use vage_storage::StorageEngine;
use vage_types::{Address, Validator};

const STAKING_STATE_PREFIX: &[u8] = b"staking:";
const DEFAULT_LOCKUP_PERIOD_EPOCHS: u64 = 7;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Stake {
    pub validator: Address,
    pub amount: U256,
}

pub struct StakingManager {
    stakes: HashMap<Address, Stake>,
    delegations: HashMap<(Address, Address), U256>,
    current_epoch: u64,
    lockup_epochs: u64,
    storage: Option<Arc<StorageEngine>>,
}

impl StakingManager {
    pub fn new() -> Self {
        Self {
            stakes: HashMap::new(),
            delegations: HashMap::new(),
            current_epoch: 0,
            lockup_epochs: DEFAULT_LOCKUP_PERIOD_EPOCHS,
            storage: None,
        }
    }

    pub fn with_storage(storage: Arc<StorageEngine>) -> Self {
        let mut manager = Self::new();
        manager.storage = Some(storage);
        manager
    }

    pub fn stake_tokens(&mut self, validator: Address, amount: U256) -> Result<()> {
        if amount.is_zero() {
            bail!("stake amount must be greater than zero");
        }

        let entry = self.stakes.entry(validator).or_insert(Stake {
            validator,
            amount: U256::zero(),
        });
        entry.amount = entry.amount.saturating_add(amount);
        self.staking_state_persistence()
    }

    pub fn unstake_tokens(&mut self, validator: &Address, amount: U256) -> Result<()> {
        if amount.is_zero() {
            bail!("unstake amount must be greater than zero");
        }
        if self.current_epoch < self.lockup_period() {
            bail!("stake is still locked");
        }

        let entry = self
            .stakes
            .get_mut(validator)
            .ok_or_else(|| anyhow::anyhow!("validator {} has no stake", validator))?;
        if entry.amount < amount {
            bail!("insufficient stake for validator {}", validator);
        }

        entry.amount -= amount;
        if entry.amount.is_zero() {
            self.stakes.remove(validator);
        }

        self.staking_state_persistence()
    }

    pub fn delegate_stake(
        &mut self,
        delegator: Address,
        validator: Address,
        amount: U256,
    ) -> Result<()> {
        if amount.is_zero() {
            bail!("delegation amount must be greater than zero");
        }

        let key = (delegator, validator);
        let delegated = self.delegations.entry(key).or_insert(U256::zero());
        *delegated = delegated.saturating_add(amount);
        self.stake_tokens(validator, amount)
    }

    pub fn slash_validator(&mut self, validator: &Address, amount: U256) -> Result<()> {
        let stake = self
            .stakes
            .get_mut(validator)
            .ok_or_else(|| anyhow::anyhow!("validator {} has no stake", validator))?;
        stake.amount = stake.amount.saturating_sub(amount);
        self.staking_state_persistence()
    }

    pub fn reward_validator(&mut self, validator: &Address, amount: U256) -> Result<()> {
        let entry = self.stakes.entry(*validator).or_insert(Stake {
            validator: *validator,
            amount: U256::zero(),
        });
        entry.amount = entry.amount.saturating_add(amount);
        self.staking_state_persistence()
    }

    pub fn calculate_voting_power(&self, validator: &Address) -> u64 {
        self.stakes
            .get(validator)
            .map(|stake| (stake.amount / U256::from(10u64.pow(18))).as_u64())
            .unwrap_or(0)
    }

    pub fn staking_epoch_update(&mut self) -> Result<u64> {
        self.current_epoch = self.current_epoch.saturating_add(1);
        self.staking_state_persistence()?;
        Ok(self.current_epoch)
    }

    pub fn lockup_period(&self) -> u64 {
        self.lockup_epochs
    }

    pub fn staking_state_persistence(&self) -> Result<()> {
        let Some(storage) = &self.storage else {
            return Ok(());
        };

        let mut changes = Vec::with_capacity(self.stakes.len() + self.delegations.len() + 1);
        changes.push((
            Self::epoch_key(),
            Some(self.current_epoch.to_le_bytes().to_vec()),
        ));

        for (validator, stake) in &self.stakes {
            changes.push((
                Self::stake_key(validator),
                Some(bincode::serialize(stake).unwrap_or_default()),
            ));
        }

        for ((delegator, validator), amount) in &self.delegations {
            changes.push((
                Self::delegation_key(delegator, validator),
                Some(bincode::serialize(amount).unwrap_or_default()),
            ));
        }

        storage.atomic_state_commit(changes)
    }

    pub fn stake(&mut self, address: Address, amount: U256) {
        let _ = self.stake_tokens(address, amount);
    }

    pub fn get_stake(&self, address: &Address) -> U256 {
        self.stakes
            .get(address)
            .map(|stake| stake.amount)
            .unwrap_or_else(U256::zero)
    }

    pub fn validator_stake(&self, validator: &Validator) -> U256 {
        self.get_stake(&validator.address)
    }

    pub fn current_epoch(&self) -> u64 {
        self.current_epoch
    }

    fn stake_key(validator: &Address) -> Vec<u8> {
        let mut key = STAKING_STATE_PREFIX.to_vec();
        key.extend_from_slice(b"stake:");
        key.extend_from_slice(validator.as_bytes());
        key
    }

    fn delegation_key(delegator: &Address, validator: &Address) -> Vec<u8> {
        let mut key = STAKING_STATE_PREFIX.to_vec();
        key.extend_from_slice(b"delegate:");
        key.extend_from_slice(delegator.as_bytes());
        key.extend_from_slice(validator.as_bytes());
        key
    }

    fn epoch_key() -> Vec<u8> {
        let mut key = STAKING_STATE_PREFIX.to_vec();
        key.extend_from_slice(b"epoch");
        key
    }
}

#[cfg(test)]
mod tests {
    use super::{Stake, StakingManager};
    use primitive_types::U256;
    use std::fs;
    use std::path::PathBuf;
    use std::sync::Arc;
    use std::time::{SystemTime, UNIX_EPOCH};
    use vage_storage::StorageEngine;
    use vage_types::{Address, Validator};

    fn unique_storage_path(name: &str) -> PathBuf {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock should be valid")
            .as_nanos();
        std::env::temp_dir().join(format!("vage-{name}-{unique}.redb"))
    }

    fn test_storage(name: &str) -> (Arc<StorageEngine>, PathBuf) {
        let path = unique_storage_path(name);
        let storage = Arc::new(
            StorageEngine::new(path.to_string_lossy().as_ref())
                .expect("test storage should initialize"),
        );
        (storage, path)
    }

    fn cleanup_storage(path: PathBuf) {
        let _ = fs::remove_file(path);
    }

    fn addr(seed: u8) -> Address {
        Address([seed; 32])
    }

    fn amount(units: u64) -> U256 {
        U256::from(units) * U256::from(10u64.pow(18))
    }

    fn validator(seed: u8) -> Validator {
        Validator::new(addr(seed), [seed; 32], amount(1))
    }

    #[test]
    fn stake_struct_and_basic_stake_reward_slash_flows_work() {
        let validator_address = addr(1);
        let sample = Stake {
            validator: validator_address,
            amount: amount(2),
        };
        assert_eq!(sample.validator, validator_address);
        assert_eq!(sample.amount, amount(2));

        let mut manager = StakingManager::new();
        manager
            .stake_tokens(validator_address, amount(3))
            .expect("staking should succeed");
        manager
            .reward_validator(&validator_address, amount(2))
            .expect("reward should succeed");
        manager
            .slash_validator(&validator_address, amount(1))
            .expect("slash should succeed");

        assert_eq!(manager.get_stake(&validator_address), amount(4));
        assert_eq!(manager.calculate_voting_power(&validator_address), 4);
    }

    #[test]
    fn unstake_respects_lockup_and_removes_zeroed_stake() {
        let validator_address = addr(2);
        let mut manager = StakingManager::new();
        manager
            .stake_tokens(validator_address, amount(2))
            .expect("staking should succeed");

        assert_eq!(manager.lockup_period(), 7);
        assert!(manager
            .unstake_tokens(&validator_address, amount(1))
            .is_err());

        for _ in 0..manager.lockup_period() {
            manager
                .staking_epoch_update()
                .expect("epoch update should succeed");
        }

        manager
            .unstake_tokens(&validator_address, amount(2))
            .expect("unstake after lockup should succeed");
        assert_eq!(manager.get_stake(&validator_address), U256::zero());
        assert_eq!(manager.calculate_voting_power(&validator_address), 0);
    }

    #[test]
    fn delegate_stake_increases_delegatee_stake_and_voting_power() {
        let delegator = addr(3);
        let validator_address = addr(4);
        let mut manager = StakingManager::new();

        manager
            .delegate_stake(delegator, validator_address, amount(5))
            .expect("delegation should succeed");

        assert_eq!(manager.get_stake(&validator_address), amount(5));
        assert_eq!(manager.calculate_voting_power(&validator_address), 5);
    }

    #[test]
    fn staking_epoch_update_and_validator_helpers_reflect_state() {
        let validator = validator(5);
        let mut manager = StakingManager::new();

        manager.stake(validator.address, amount(6));
        assert_eq!(manager.validator_stake(&validator), amount(6));
        assert_eq!(
            manager
                .staking_epoch_update()
                .expect("epoch should advance"),
            1
        );
        assert_eq!(
            manager
                .staking_epoch_update()
                .expect("epoch should advance"),
            2
        );
    }

    #[test]
    fn staking_state_persistence_writes_epoch_stakes_and_delegations() {
        let (storage, path) = test_storage("staking-persistence");
        let validator_address = addr(6);
        let delegator = addr(7);
        let mut manager = StakingManager::with_storage(storage.clone());

        manager
            .stake_tokens(validator_address, amount(2))
            .expect("staking should succeed");
        manager
            .delegate_stake(delegator, validator_address, amount(1))
            .expect("delegation should succeed");
        manager
            .staking_epoch_update()
            .expect("epoch update should persist");

        let epoch_key = [b"staking:".as_slice(), b"epoch".as_slice()].concat();
        let epoch_bytes = storage
            .state_get(epoch_key)
            .expect("epoch read should succeed")
            .expect("epoch should be stored");
        let mut epoch_arr = [0u8; 8];
        epoch_arr.copy_from_slice(&epoch_bytes);
        assert_eq!(u64::from_le_bytes(epoch_arr), 1);

        let mut stake_key = b"staking:stake:".to_vec();
        stake_key.extend_from_slice(validator_address.as_bytes());
        let stored_stake: Stake = bincode::deserialize(
            &storage
                .state_get(stake_key)
                .expect("stake read should succeed")
                .expect("stake should be stored"),
        )
        .expect("stake should deserialize");
        assert_eq!(stored_stake.amount, amount(3));

        let mut delegation_key = b"staking:delegate:".to_vec();
        delegation_key.extend_from_slice(delegator.as_bytes());
        delegation_key.extend_from_slice(validator_address.as_bytes());
        let stored_delegation: U256 = bincode::deserialize(
            &storage
                .state_get(delegation_key)
                .expect("delegation read should succeed")
                .expect("delegation should be stored"),
        )
        .expect("delegation should deserialize");
        assert_eq!(stored_delegation, amount(1));

        cleanup_storage(path);
    }
}
