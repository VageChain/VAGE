use crate::Address;
use anyhow::{bail, Result};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use primitive_types::U256;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum ValidatorStatus {
    Active,
    Inactive,
    Jailed,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Validator {
    pub address: Address,
    pub pubkey: [u8; 32],
    pub stake: U256,
    pub voting_power: u64,
    pub status: ValidatorStatus,
}

impl Validator {
    /// Create a new validator with initial address, public key, and stake.
    pub fn new(address: Address, pubkey: [u8; 32], stake: U256) -> Self {
        let voting_power = Self::calculate_voting_power(stake);
        Self {
            address,
            pubkey,
            stake,
            voting_power,
            status: ValidatorStatus::Inactive,
        }
    }

    /// Calculate voting power based on stake (e.g., stake / base_unit).
    fn calculate_voting_power(stake: U256) -> u64 {
        // Simplified calculation for voting power from stake
        (stake / U256::from(10u64.pow(18))).as_u64()
    }

    /// Update the validator's voting power based on current stake.
    pub fn update_voting_power(&mut self) {
        self.voting_power = Self::calculate_voting_power(self.stake);
    }

    /// Increase the validator's stake.
    pub fn increase_stake(&mut self, amount: U256) {
        self.stake = self.stake.saturating_add(amount);
        self.update_voting_power();
    }

    /// Decrease the validator's stake.
    pub fn decrease_stake(&mut self, amount: U256) -> Result<()> {
        if self.stake < amount {
            bail!(
                "Insufficient stake to decrease from validator {}",
                self.address
            );
        }
        self.stake -= amount;
        self.update_voting_power();
        Ok(())
    }

    /// Check if the validator is currently active and participating in consensus.
    pub fn is_active(&self) -> bool {
        matches!(self.status, ValidatorStatus::Active)
    }

    /// Check if the validator has been jailed for misbehavior.
    pub fn is_jailed(&self) -> bool {
        matches!(self.status, ValidatorStatus::Jailed)
    }

    /// Slash a validator's stake as a penalty for misbehavior.
    pub fn slash(&mut self, amount: U256) {
        self.stake = self.stake.saturating_sub(amount);
        self.update_voting_power();
        self.status = ValidatorStatus::Jailed;
    }

    /// Reward a validator for successful participation.
    pub fn reward(&mut self, amount: U256) {
        self.stake = self.stake.saturating_add(amount);
        self.update_voting_power();
    }

    /// Verify a consensus message signature using the validator's public key.
    pub fn verify_signature(&self, message: &[u8], sig_bytes: &[u8; 64]) -> Result<bool> {
        let public_key = VerifyingKey::from_bytes(&self.pubkey)
            .map_err(|e| anyhow::anyhow!("Invalid validator pubkey: {:?}", e))?;
        let sig = Signature::from_bytes(sig_bytes);

        public_key
            .verify(message, &sig)
            .map(|_| true)
            .map_err(|e| anyhow::anyhow!("Validator signature verification failed: {:?}", e))
    }

    /// Calculate the validator's share of the total network stake.
    pub fn stake_ratio(&self, total_stake: U256) -> f64 {
        if total_stake.is_zero() {
            return 0.0;
        }
        // Use floating point division for ratio approximation
        (self.stake.as_u128() as f64) / (total_stake.as_u128() as f64)
    }

    /// Calculate the canonical hash of the validator for set commitment.
    pub fn hash(&self) -> [u8; 32] {
        let bytes = bincode::serialize(self).expect("validator serialization should succeed");
        let mut hasher = Sha256::new();
        hasher.update(&bytes);
        let result = hasher.finalize();
        let mut hash_bytes = [0u8; 32];
        hash_bytes.copy_from_slice(&result);
        hash_bytes
    }

    /// Update the validator's public key.
    pub fn update_pubkey(&mut self, new_pubkey: [u8; 32]) {
        self.pubkey = new_pubkey;
    }
}

#[cfg(test)]
mod tests {
    use super::{Validator, ValidatorStatus};
    use crate::Address;
    use ed25519_dalek::{Signer, SigningKey};
    use primitive_types::U256;

    fn unit() -> U256 {
        U256::from(10u64.pow(18))
    }

    #[test]
    fn new_validator_initializes_expected_fields() {
        let validator = Validator::new(Address([1u8; 32]), [2u8; 32], unit() * U256::from(3u64));

        assert_eq!(validator.address, Address([1u8; 32]));
        assert_eq!(validator.pubkey, [2u8; 32]);
        assert_eq!(validator.stake, unit() * U256::from(3u64));
        assert_eq!(validator.voting_power, 3);
        assert_eq!(validator.status, ValidatorStatus::Inactive);
    }

    #[test]
    fn stake_updates_refresh_voting_power() {
        let mut validator = Validator::new(Address([3u8; 32]), [4u8; 32], unit());

        validator.increase_stake(unit() * U256::from(2u64));
        assert_eq!(validator.voting_power, 3);

        validator
            .decrease_stake(unit())
            .expect("stake decrease should succeed");
        assert_eq!(validator.voting_power, 2);
        assert!(validator.decrease_stake(unit() * U256::from(3u64)).is_err());
    }

    #[test]
    fn status_helpers_reflect_validator_state() {
        let mut validator = Validator::new(Address([5u8; 32]), [6u8; 32], unit());
        assert!(!validator.is_active());
        assert!(!validator.is_jailed());

        validator.status = ValidatorStatus::Active;
        assert!(validator.is_active());

        validator.status = ValidatorStatus::Jailed;
        assert!(validator.is_jailed());
    }

    #[test]
    fn slash_and_reward_adjust_stake() {
        let mut validator =
            Validator::new(Address([7u8; 32]), [8u8; 32], unit() * U256::from(5u64));

        validator.reward(unit());
        assert_eq!(validator.stake, unit() * U256::from(6u64));

        validator.slash(unit() * U256::from(2u64));
        assert_eq!(validator.stake, unit() * U256::from(4u64));
        assert_eq!(validator.voting_power, 4);
        assert!(validator.is_jailed());
    }

    #[test]
    fn verify_signature_accepts_valid_messages() {
        let signing_key = SigningKey::from_bytes(&[9u8; 32]);
        let pubkey = signing_key.verifying_key().to_bytes();
        let validator = Validator::new(Address::from_public_key(&pubkey), pubkey, unit());
        let message = b"hotstuff-vote";
        let signature = signing_key.sign(message).to_bytes();

        assert!(validator
            .verify_signature(message, &signature)
            .expect("signature verification should succeed"));
    }

    #[test]
    fn stake_ratio_and_hash_are_deterministic() {
        let validator = Validator::new(Address([10u8; 32]), [11u8; 32], unit() * U256::from(2u64));

        assert_eq!(validator.stake_ratio(unit() * U256::from(4u64)), 0.5);
        assert_eq!(validator.stake_ratio(U256::zero()), 0.0);
        assert_eq!(validator.hash(), validator.hash());
    }

    #[test]
    fn bincode_round_trip_and_pubkey_update_work() {
        let mut validator = Validator::new(Address([12u8; 32]), [13u8; 32], unit());
        validator.update_pubkey([14u8; 32]);

        let encoded = bincode::serialize(&validator).expect("bincode serialization should work");
        let decoded: Validator =
            bincode::deserialize(&encoded).expect("bincode deserialization should work");

        assert_eq!(validator.pubkey, [14u8; 32]);
        assert_eq!(decoded, validator);
    }
}
