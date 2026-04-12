use anyhow::{bail, Result};
use primitive_types::U256;
use std::collections::HashMap;
use vage_types::{Address, Validator};

pub struct ValidatorSet {
    validators: HashMap<Address, Validator>,
    total_stake: U256,
}

impl ValidatorSet {
    pub fn new() -> Self {
        Self {
            validators: HashMap::new(),
            total_stake: U256::zero(),
        }
    }

    pub fn add_validator(&mut self, validator: Validator) -> Result<()> {
        self.validate_validator(&validator)?;

        if let Some(existing) = self.validators.insert(validator.address, validator.clone()) {
            self.total_stake = self.total_stake.saturating_sub(existing.stake);
        }

        self.total_stake = self.total_stake.saturating_add(validator.stake);
        Ok(())
    }

    pub fn remove_validator(&mut self, address: &Address) -> Option<Validator> {
        let removed = self.validators.remove(address)?;
        self.total_stake = self.total_stake.saturating_sub(removed.stake);
        Some(removed)
    }

    pub fn total_stake(&self) -> U256 {
        self.total_stake
    }

    pub fn voting_power(&self, address: &Address) -> u64 {
        self.validators
            .get(address)
            .map(|validator| validator.voting_power)
            .unwrap_or(0)
    }

    pub fn validator(&self, address: &Address) -> Option<&Validator> {
        self.validators.get(address)
    }

    pub fn leader_selection(&self, view: u64) -> Option<Address> {
        let active = self.active_validators();
        if active.is_empty() {
            return None;
        }

        let index = (view as usize) % active.len();
        Some(active[index].address)
    }

    pub fn quorum_threshold(&self) -> usize {
        let count = self.active_validators().len();
        if count == 0 {
            return 0;
        }
        ((count * 2) / 3) + 1
    }

    pub fn validate_validator(&self, validator: &Validator) -> Result<()> {
        if validator.pubkey == [0u8; 32] {
            bail!("validator {} has an empty public key", validator.address);
        }
        if validator.is_jailed() {
            bail!("validator {} is jailed", validator.address);
        }
        if validator.stake.is_zero() {
            bail!("validator {} has zero stake", validator.address);
        }
        Ok(())
    }

    pub fn active_validators(&self) -> Vec<Validator> {
        let mut active: Vec<Validator> = self
            .validators
            .values()
            .filter(|validator| validator.is_active())
            .cloned()
            .collect();
        active.sort_by(|left, right| {
            right
                .voting_power
                .cmp(&left.voting_power)
                .then_with(|| left.address.as_bytes().cmp(right.address.as_bytes()))
        });
        active
    }

    pub fn all_validators(&self) -> Vec<Validator> {
        self.validators.values().cloned().collect()
    }

    pub fn replace_validators(&mut self, validators: Vec<Validator>) -> Result<()> {
        self.validators.clear();
        self.total_stake = U256::zero();

        for validator in validators {
            self.add_validator(validator)?;
        }

        Ok(())
    }

    pub fn active_validator_count(&self) -> usize {
        self.active_validators().len()
    }

    pub fn total_active_voting_power(&self) -> u64 {
        self.active_validators()
            .iter()
            .map(|validator| validator.voting_power)
            .sum()
    }

    pub fn get_proposer(&self, view: u64) -> Option<Address> {
        self.leader_selection(view)
    }
}

#[cfg(test)]
mod tests {
    use super::ValidatorSet;
    use primitive_types::U256;
    use vage_types::validator::ValidatorStatus;
    use vage_types::{Address, Validator};

    fn validator(seed: u8, active: bool, stake_units: u64) -> Validator {
        let address = Address([seed; 32]);
        let pubkey = [seed; 32];
        let mut validator = Validator::new(
            address,
            pubkey,
            U256::from(stake_units) * U256::from(10u64.pow(18)),
        );
        validator.status = if active {
            ValidatorStatus::Active
        } else {
            ValidatorStatus::Inactive
        };
        validator
    }

    #[test]
    fn add_remove_and_total_stake_track_validator_set_state() {
        let mut set = ValidatorSet::new();
        let first = validator(1, true, 2);
        let second = validator(2, false, 3);

        set.add_validator(first.clone())
            .expect("first validator should be accepted");
        set.add_validator(second.clone())
            .expect("second validator should be accepted");

        assert_eq!(set.total_stake(), first.stake + second.stake);
        assert_eq!(
            set.validator(&first.address)
                .map(|validator| validator.address),
            Some(first.address)
        );
        assert_eq!(set.voting_power(&second.address), second.voting_power);

        let removed = set
            .remove_validator(&second.address)
            .expect("validator should be removed");
        assert_eq!(removed.address, second.address);
        assert_eq!(set.total_stake(), first.stake);
    }

    #[test]
    fn leader_selection_and_get_proposer_only_use_active_validators() {
        let mut set = ValidatorSet::new();
        let first = validator(3, true, 1);
        let second = validator(4, false, 1);
        let third = validator(5, true, 1);

        set.add_validator(first.clone())
            .expect("first validator should be added");
        set.add_validator(second)
            .expect("second validator should be added");
        set.add_validator(third.clone())
            .expect("third validator should be added");

        let active = set.active_validators();
        assert_eq!(active.len(), 2);
        assert!(active.iter().all(|validator| validator.is_active()));
        assert_eq!(set.active_validator_count(), 2);
        assert_eq!(set.leader_selection(0), Some(first.address));
        assert_eq!(set.leader_selection(1), Some(third.address));
        assert_eq!(set.leader_selection(2), Some(first.address));
        assert_eq!(set.get_proposer(1), Some(third.address));
    }

    #[test]
    fn quorum_threshold_and_voting_power_cover_zero_one_and_multiple_active_validators() {
        let mut empty = ValidatorSet::new();
        assert_eq!(empty.quorum_threshold(), 0);
        assert_eq!(empty.total_active_voting_power(), 0);
        assert_eq!(empty.get_proposer(0), None);

        let one = validator(6, true, 2);
        empty
            .add_validator(one.clone())
            .expect("validator should be added");
        assert_eq!(empty.quorum_threshold(), 1);
        assert_eq!(empty.total_active_voting_power(), one.voting_power);

        let two = validator(7, true, 3);
        let three = validator(8, true, 4);
        empty
            .add_validator(two.clone())
            .expect("validator should be added");
        empty
            .add_validator(three.clone())
            .expect("validator should be added");
        assert_eq!(empty.quorum_threshold(), 3);
        assert_eq!(
            empty.total_active_voting_power(),
            one.voting_power + two.voting_power + three.voting_power
        );
    }

    #[test]
    fn replace_validators_and_validation_reject_invalid_entries() {
        let mut set = ValidatorSet::new();
        let active = validator(9, true, 1);
        let jailed = {
            let mut validator = validator(10, true, 1);
            validator.status = ValidatorStatus::Jailed;
            validator
        };
        let zero_stake = validator(11, true, 0);
        let empty_key = Validator::new(Address([12u8; 32]), [0u8; 32], U256::from(10u64.pow(18)));

        assert!(set.validate_validator(&jailed).is_err());
        assert!(set.validate_validator(&zero_stake).is_err());
        assert!(set.validate_validator(&empty_key).is_err());

        set.replace_validators(vec![active.clone()])
            .expect("replacement should succeed with valid validators");
        assert_eq!(set.active_validator_count(), 1);
        assert_eq!(set.total_stake(), active.stake);
    }
}
