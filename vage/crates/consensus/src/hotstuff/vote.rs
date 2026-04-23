use anyhow::{bail, Result};
use ed25519_dalek::{Signer, SigningKey};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use vage_crypto::bls::{
    aggregate_public_keys, aggregate_votes, verify_quorum_certificate, BlsPublicKey, BlsSignature,
};
use vage_crypto::hash::{domain_hash, DOMAIN_CONSENSUS};
use vage_types::{Address, Validator};

mod serde_sig {
    use serde::de::Error;
    use serde::{Deserializer, Serializer};
    pub fn serialize<S>(sig: &[u8; 64], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_bytes(sig.as_slice())
    }
    pub fn deserialize<'de, D>(deserializer: D) -> Result<[u8; 64], D::Error>
    where
        D: Deserializer<'de>,
    {
        let bytes: Vec<u8> = serde::Deserialize::deserialize(deserializer)?;
        bytes
            .try_into()
            .map_err(|_| Error::custom("expected 64 bytes"))
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Vote {
    pub validator: Address,
    pub block_hash: [u8; 32],
    pub view: u64,
    #[serde(with = "serde_sig")]
    pub signature: [u8; 64],
}

impl Vote {
    pub fn new(validator: Address, block_hash: [u8; 32], view: u64) -> Self {
        Self {
            validator,
            block_hash,
            view,
            signature: [0u8; 64],
        }
    }

    pub fn sign(&mut self, signing_key: &SigningKey) -> Result<()> {
        let message = self.signing_message();
        self.signature = signing_key.sign(&message).to_bytes();
        Ok(())
    }

    pub fn verify_signature(&self, validator: &Validator) -> Result<bool> {
        validator.verify_signature(&self.signing_message(), &self.signature)
    }

    pub fn encode(&self) -> Vec<u8> {
        bincode::serialize(self).unwrap_or_default()
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        Ok(bincode::deserialize(bytes)?)
    }

    fn signing_message(&self) -> [u8; 32] {
        let mut bytes = Vec::with_capacity(72);
        bytes.extend_from_slice(self.validator.as_bytes());
        bytes.extend_from_slice(&self.block_hash);
        bytes.extend_from_slice(&self.view.to_le_bytes());
        domain_hash(DOMAIN_CONSENSUS, &bytes)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct QuorumCertificate {
    pub block_hash: [u8; 32],
    pub view: u64,
    pub signatures: Vec<Vec<u8>>,
    pub validators: Vec<Address>,
}

impl QuorumCertificate {
    pub fn new(
        block_hash: [u8; 32],
        view: u64,
        signatures: Vec<Vec<u8>>,
        validators: Vec<Address>,
    ) -> Self {
        Self {
            block_hash,
            view,
            signatures,
            validators,
        }
    }

    pub fn verify(&self, validator_set: &[Validator], threshold: usize) -> Result<bool> {
        if self.signatures.len() != self.validators.len() {
            return Ok(false);
        }
        if self.validators.len() < threshold {
            return Ok(false);
        }

        let mut seen_validators = HashSet::with_capacity(self.validators.len());

        for (address, signature) in self.validators.iter().zip(self.signatures.iter()) {
            if !seen_validators.insert(*address) {
                return Ok(false);
            }

            let Some(validator) = validator_set
                .iter()
                .find(|validator| validator.address == *address)
            else {
                return Ok(false);
            };

            if signature.len() != 64 {
                return Ok(false);
            }

            let mut sig = [0u8; 64];
            sig.copy_from_slice(signature);
            if !validator.verify_signature(&self.vote_signing_message(*address), &sig)? {
                return Ok(false);
            }
        }

        Ok(true)
    }

    pub fn verify_with_voting_power(
        &self,
        validator_set: &[Validator],
        threshold: usize,
        required_voting_power: u64,
    ) -> Result<bool> {
        if !self.verify(validator_set, threshold)? {
            return Ok(false);
        }

        let mut total_voting_power = 0u64;
        for address in &self.validators {
            let Some(validator) = validator_set
                .iter()
                .find(|validator| validator.address == *address)
            else {
                return Ok(false);
            };
            total_voting_power = total_voting_power.saturating_add(validator.voting_power);
        }

        Ok(total_voting_power >= required_voting_power)
    }

    pub fn aggregate_bls_signatures(&self) -> Result<Vec<u8>> {
        Ok(self.aggregate_bls_signature()?.0)
    }

    pub fn aggregate_bls_signature(&self) -> Result<BlsSignature> {
        let signatures: Result<Vec<_>> = self
            .signatures
            .iter()
            .map(|signature| Ok(BlsSignature(signature.clone())))
            .collect();
        aggregate_votes(&signatures?)
    }

    pub fn verify_bls_aggregate_signature(&self, public_keys: &[BlsPublicKey]) -> Result<bool> {
        if public_keys.len() != self.validators.len() {
            return Ok(false);
        }

        let mut seen_validators = HashSet::with_capacity(self.validators.len());
        for address in &self.validators {
            if !seen_validators.insert(*address) {
                return Ok(false);
            }
        }

        let aggregate_public_key = aggregate_public_keys(public_keys)?;
        let aggregate_signature = self.aggregate_bls_signature()?;
        Ok(verify_quorum_certificate(
            &aggregate_public_key,
            &self.block_hash,
            &aggregate_signature,
        ))
    }

    pub fn encode(&self) -> Vec<u8> {
        bincode::serialize(self).unwrap_or_default()
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        Ok(bincode::deserialize(bytes)?)
    }

    pub fn validator_bitmap(&self) -> Vec<u8> {
        vec![1u8; self.validators.len()]
    }

    pub fn is_genesis(&self) -> bool {
        self.block_hash == [0u8; 32] && self.view == 0 && self.validators.is_empty()
    }

    fn vote_signing_message(&self, validator: Address) -> [u8; 32] {
        let mut bytes = Vec::with_capacity(72);
        bytes.extend_from_slice(validator.as_bytes());
        bytes.extend_from_slice(&self.block_hash);
        bytes.extend_from_slice(&self.view.to_le_bytes());
        domain_hash(DOMAIN_CONSENSUS, &bytes)
    }
}

#[derive(Clone, Debug, Default)]
pub struct VoteCollector {
    votes: HashMap<(u64, [u8; 32]), Vec<Vote>>,
    validator_votes: HashMap<(u64, Address), [u8; 32]>,
}

impl VoteCollector {
    pub fn new() -> Self {
        Self {
            votes: HashMap::new(),
            validator_votes: HashMap::new(),
        }
    }

    pub fn add_vote(&mut self, vote: Vote) -> Result<()> {
        let validator = vote.validator;
        let block_hash = vote.block_hash;
        let view = vote.view;

        if let Some(previous_block_hash) = self.validator_votes.get(&(vote.view, vote.validator)) {
            if previous_block_hash != &vote.block_hash {
                bail!(
                    "double voting detected for validator {} in view {}",
                    vote.validator,
                    vote.view
                );
            }
        }

        let entry = self.votes.entry((vote.view, vote.block_hash)).or_default();
        if !entry
            .iter()
            .any(|existing| existing.validator == vote.validator)
        {
            entry.push(vote);
        }
        self.validator_votes.insert((view, validator), block_hash);
        Ok(())
    }

    pub fn vote_count(&self, view: u64, block_hash: [u8; 32]) -> usize {
        self.votes
            .get(&(view, block_hash))
            .map(|votes| votes.len())
            .unwrap_or(0)
    }

    pub fn has_quorum(&self, view: u64, block_hash: [u8; 32], threshold: usize) -> bool {
        self.vote_count(view, block_hash) >= threshold
    }

    pub fn aggregate_signatures(
        &self,
        view: u64,
        block_hash: [u8; 32],
    ) -> Vec<(Address, [u8; 64])> {
        self.votes
            .get(&(view, block_hash))
            .map(|votes| {
                votes
                    .iter()
                    .map(|vote| (vote.validator, vote.signature))
                    .collect()
            })
            .unwrap_or_default()
    }

    pub fn build_quorum_certificate(
        &self,
        view: u64,
        block_hash: [u8; 32],
        threshold: usize,
    ) -> Option<QuorumCertificate> {
        if !self.has_quorum(view, block_hash, threshold) {
            return None;
        }

        Some(QuorumCertificate::new(
            block_hash,
            view,
            self.aggregate_signatures(view, block_hash)
                .into_iter()
                .map(|(_, signature)| signature.to_vec())
                .collect(),
            self.votes
                .get(&(view, block_hash))?
                .iter()
                .map(|vote| vote.validator)
                .collect(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::{QuorumCertificate, Vote, VoteCollector};
    use ed25519_dalek::SigningKey;
    use primitive_types::U256;
    use vage_crypto::bls::{bls_generate_keypair, validator_vote_signature};
    use vage_types::{Address, Validator};

    fn validator_from_signing_key(signing_key: &SigningKey) -> Validator {
        let pubkey = signing_key.verifying_key().to_bytes();
        Validator::new(
            Address::from_public_key(&pubkey),
            pubkey,
            U256::from(10u64.pow(18)),
        )
    }

    fn signing_key(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    #[test]
    fn quorum_certificate_new_encode_decode_and_bitmap_work() {
        let qc = QuorumCertificate::new(
            [4u8; 32],
            12,
            vec![vec![1u8; 64], vec![2u8; 64]],
            vec![Address([1u8; 32]), Address([2u8; 32])],
        );

        assert_eq!(qc.block_hash, [4u8; 32]);
        assert_eq!(qc.view, 12);
        assert_eq!(qc.signatures.len(), 2);
        assert_eq!(qc.validators.len(), 2);
        assert_eq!(qc.validator_bitmap(), vec![1u8, 1u8]);

        let encoded = qc.encode();
        let decoded = QuorumCertificate::decode(&encoded)
            .expect("quorum certificate decoding should succeed");

        assert_eq!(decoded.block_hash, qc.block_hash);
        assert_eq!(decoded.view, qc.view);
        assert_eq!(decoded.signatures, qc.signatures);
        assert_eq!(decoded.validators, qc.validators);
    }

    #[test]
    fn quorum_certificate_verify_rejects_threshold_mismatch_and_unknown_validator() {
        let signer = signing_key(6);
        let validator = validator_from_signing_key(&signer);
        let mut vote = Vote::new(validator.address, [6u8; 32], 1);
        vote.sign(&signer).expect("vote signing should succeed");

        let qc = QuorumCertificate::new(
            vote.block_hash,
            vote.view,
            vec![vote.signature.to_vec()],
            vec![vote.validator],
        );

        assert!(!qc
            .verify(std::slice::from_ref(&validator), 2)
            .expect("threshold check should run"));

        let other_validator = validator_from_signing_key(&signing_key(7));
        assert!(!qc
            .verify(&[other_validator], 1)
            .expect("validator lookup should run"));
    }

    #[test]
    fn vote_new_sign_verify_and_codec_round_trip() {
        let signing_key = signing_key(0);
        let validator = validator_from_signing_key(&signing_key);
        let mut vote = Vote::new(validator.address, [3u8; 32], 9);

        assert_eq!(vote.validator, validator.address);
        assert_eq!(vote.block_hash, [3u8; 32]);
        assert_eq!(vote.view, 9);
        assert_eq!(vote.signature, [0u8; 64]);

        vote.sign(&signing_key)
            .expect("vote signing should succeed");
        assert!(vote
            .verify_signature(&validator)
            .expect("vote verification should succeed"));

        let encoded = vote.encode();
        let decoded = Vote::decode(&encoded).expect("vote decoding should succeed");

        assert_eq!(decoded.validator, vote.validator);
        assert_eq!(decoded.block_hash, vote.block_hash);
        assert_eq!(decoded.view, vote.view);
        assert_eq!(decoded.signature, vote.signature);
    }

    #[test]
    fn vote_collector_add_vote_counts_quorum_and_aggregates_signatures() {
        let signing_key = signing_key(4);
        let validator = validator_from_signing_key(&signing_key);
        let mut vote = Vote::new(validator.address, [8u8; 32], 6);
        vote.sign(&signing_key)
            .expect("vote signing should succeed");

        let mut collector = VoteCollector::new();
        collector
            .add_vote(vote.clone())
            .expect("vote insert should succeed");
        collector
            .add_vote(vote.clone())
            .expect("duplicate vote for same block should be ignored");

        assert_eq!(collector.vote_count(6, [8u8; 32]), 1);
        assert!(collector.has_quorum(6, [8u8; 32], 1));
        assert!(!collector.has_quorum(6, [8u8; 32], 2));

        let aggregated = collector.aggregate_signatures(6, [8u8; 32]);
        assert_eq!(aggregated.len(), 1);
        assert_eq!(aggregated[0].0, validator.address);
        assert_eq!(aggregated[0].1, vote.signature);

        let qc = collector
            .build_quorum_certificate(6, [8u8; 32], 1)
            .expect("qc should be built at quorum");
        assert_eq!(qc.block_hash, [8u8; 32]);
        assert_eq!(qc.view, 6);
        assert_eq!(qc.validators, vec![validator.address]);
        assert_eq!(qc.signatures, vec![vote.signature.to_vec()]);

        assert!(collector
            .build_quorum_certificate(6, [8u8; 32], 2)
            .is_none());
    }

    #[test]
    fn vote_collector_rejects_double_vote_for_different_block_in_same_view() {
        let signing_key = signing_key(5);
        let validator = validator_from_signing_key(&signing_key);
        let mut first_vote = Vote::new(validator.address, [1u8; 32], 2);
        first_vote
            .sign(&signing_key)
            .expect("first vote signing should succeed");
        let mut second_vote = Vote::new(validator.address, [2u8; 32], 2);
        second_vote
            .sign(&signing_key)
            .expect("second vote signing should succeed");

        let mut collector = VoteCollector::new();
        collector
            .add_vote(first_vote)
            .expect("first vote insert should succeed");

        assert!(collector.add_vote(second_vote).is_err());
    }

    #[test]
    fn quorum_certificate_verifies_signed_votes_using_view_message() {
        let signing_key = signing_key(1);
        let validator = validator_from_signing_key(&signing_key);
        let mut vote = Vote::new(validator.address, [7u8; 32], 4);
        vote.sign(&signing_key)
            .expect("vote signing should succeed");

        let qc = QuorumCertificate::new(
            vote.block_hash,
            vote.view,
            vec![vote.signature.to_vec()],
            vec![vote.validator],
        );

        assert!(qc
            .verify(&[validator], 1)
            .expect("qc verification should succeed"));
    }

    #[test]
    fn quorum_certificate_rejects_duplicate_validator_entries() {
        let signing_key = signing_key(2);
        let validator = validator_from_signing_key(&signing_key);
        let mut vote = Vote::new(validator.address, [9u8; 32], 2);
        vote.sign(&signing_key)
            .expect("vote signing should succeed");

        let qc = QuorumCertificate::new(
            vote.block_hash,
            vote.view,
            vec![vote.signature.to_vec(), vote.signature.to_vec()],
            vec![vote.validator, vote.validator],
        );

        assert!(!qc
            .verify(std::slice::from_ref(&validator), 2)
            .expect("qc verification should succeed"));
        assert!(!qc
            .verify_with_voting_power(&[validator], 2, 2)
            .expect("voting power verification should succeed"));
    }

    #[test]
    fn quorum_certificate_bls_helper_verifies_aggregated_signature() {
        let (sk1, pk1) = bls_generate_keypair();
        let (sk2, pk2) = bls_generate_keypair();
        let block_hash = [11u8; 32];
        let sig1 =
            validator_vote_signature(&sk1, &block_hash).expect("vote signature should succeed");
        let sig2 =
            validator_vote_signature(&sk2, &block_hash).expect("vote signature should succeed");
        let qc = QuorumCertificate::new(
            block_hash,
            3,
            vec![sig1.0, sig2.0],
            vec![Address([1u8; 32]), Address([2u8; 32])],
        );

        assert!(qc
            .verify_bls_aggregate_signature(&[pk1, pk2])
            .expect("bls aggregate verification should succeed"));
        assert!(!qc
            .aggregate_bls_signatures()
            .expect("bls aggregation should succeed")
            .is_empty());
    }

    #[test]
    fn vote_collector_builds_qc_with_view() {
        let signing_key = signing_key(3);
        let validator = validator_from_signing_key(&signing_key);
        let mut vote = Vote::new(validator.address, [5u8; 32], 8);
        vote.sign(&signing_key)
            .expect("vote signing should succeed");

        let mut collector = VoteCollector::new();
        collector
            .add_vote(vote)
            .expect("vote insert should succeed");
        let qc = collector
            .build_quorum_certificate(8, [5u8; 32], 1)
            .expect("qc should be built");

        assert_eq!(qc.view, 8);
    }
}
