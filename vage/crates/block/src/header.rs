use anyhow::{bail, Context, Result};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use vage_types::{Address, BlockHeight, Canonical, Hash, Timestamp};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::time::{SystemTime, UNIX_EPOCH};

mod serde_sig {
    use serde::{Deserializer, Serializer};
    use serde::de::Error;
    pub fn serialize<S>(sig: &Option<[u8; 64]>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match sig {
            Some(s) => serializer.serialize_some(s.as_slice()),
            None => serializer.serialize_none(),
        }
    }
    pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<[u8; 64]>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let opt: Option<Vec<u8>> = serde::Deserialize::deserialize(deserializer)?;
        match opt {
            Some(vec) => {
                let arr = vec.try_into().map_err(|_| Error::custom("expected 64 bytes"))?;
                Ok(Some(arr))
            }
            None => Ok(None),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct BlockHeader {
    pub parent_hash: Hash,
    pub state_root: Hash,
    pub tx_root: Hash,
    pub receipts_root: Hash,
    pub validator_root: Hash,
    pub zk_proof: Option<Vec<u8>>,
    pub height: BlockHeight,
    pub timestamp: Timestamp,
    pub proposer: Address,
    #[serde(default, with = "serde_sig")]
    pub signature: Option<[u8; 64]>,
}

impl BlockHeader {
    /// Create a new block header for a specific height and parent.
    pub fn new(parent_hash: Hash, height: BlockHeight) -> Self {
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        Self {
            parent_hash,
            state_root: [0u8; 32],
            tx_root: [0u8; 32],
            receipts_root: [0u8; 32],
            validator_root: [0u8; 32],
            zk_proof: None,
            height,
            timestamp: ts,
            proposer: Address::zero(),
            signature: None,
        }
    }

    /// Create the genesis block header (height 0).
    pub fn genesis() -> Self {
        Self {
            parent_hash: [0u8; 32],
            state_root: [0u8; 32],
            tx_root: [0u8; 32],
            receipts_root: [0u8; 32],
            validator_root: [0u8; 32],
            zk_proof: None,
            height: 0,
            timestamp: 1600000000, // Fixed genesis timestamp
            proposer: Address::zero(),
            signature: None,
        }
    }

    /// Calculate the canonical hash of the header.
    pub fn hash(&self) -> Hash {
        let mut hasher = Sha256::new();
        // Hash without the signature for deterministic verification
        let mut temp = self.clone();
        temp.signature = None;
        let bytes = temp.encode();
        hasher.update(&bytes);
        let result = hasher.finalize();
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&result);
        bytes
    }

    pub fn encode(&self) -> Vec<u8> {
        <Self as Canonical>::encode(self)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        <Self as Canonical>::decode(bytes)
    }

    /// Verify that the header correctly links to its parent.
    pub fn verify_parent(&self, expected_parent_hash: Hash) -> bool {
        self.parent_hash == expected_parent_hash
    }

    /// Verify that the height is sequentially correct.
    pub fn verify_height(&self, expected_height: BlockHeight) -> bool {
        self.height == expected_height
    }

    /// Verify that the timestamp is strictly increasing.
    pub fn verify_timestamp(&self, previous_timestamp: Timestamp) -> bool {
        self.timestamp > previous_timestamp
    }

    /// Sign the block header as the proposer.
    pub fn sign(&mut self, signing_key: &SigningKey) -> Result<()> {
        let hash = self.hash();
        let sig = signing_key.sign(&hash);
        self.signature = Some(sig.to_bytes());
        Ok(())
    }

    /// Verify the proposer's signature on the header.
    pub fn verify_signature(&self, public_key_bytes: &[u8; 32]) -> Result<bool> {
        let sig_bytes = self
            .signature
            .ok_or_else(|| anyhow::anyhow!("No header signature"))?;

        let derived_proposer = Address::from_public_key(public_key_bytes);
        if derived_proposer != self.proposer {
            bail!(
                "proposer public key does not match header proposer: expected {}, derived {}",
                self.proposer,
                derived_proposer
            );
        }

        let public_key =
            VerifyingKey::from_bytes(public_key_bytes).context("Invalid proposer public key")?;
        let sig = Signature::from_bytes(&sig_bytes);

        public_key
            .verify(&self.hash(), &sig)
            .map(|_| true)
            .map_err(|e| anyhow::anyhow!("Block signature verification failed: {:?}", e))
    }

    pub fn set_state_root(&mut self, root: Hash) {
        self.state_root = root;
    }
    pub fn set_tx_root(&mut self, root: Hash) {
        self.tx_root = root;
    }
    pub fn set_receipts_root(&mut self, root: Hash) {
        self.receipts_root = root;
    }
    pub fn set_validator_root(&mut self, root: Hash) {
        self.validator_root = root;
    }
    pub fn set_zk_proof(&mut self, proof: Vec<u8>) {
        self.zk_proof = Some(proof);
    }
    pub fn set_timestamp(&mut self, ts: Timestamp) {
        self.timestamp = ts;
    }

    /// Canonical binary size of the header.
    pub fn size_bytes(&self) -> usize {
        self.encode().len()
    }

    /// Perform basic integrity and range checks on the header fields.
    pub fn validate_basic(&self) -> Result<()> {
        if self.timestamp == 0 {
            bail!("Block timestamp cannot be zero");
        }
        if self.height == 0 && self.parent_hash != [0u8; 32] {
            bail!("Genesis header must have zero parent hash");
        }
        Ok(())
    }
}

// Removed Canonical impl because there is a blanket impl

impl vage_crypto::hash::Hashable for BlockHeader {
    fn hash(&self) -> vage_crypto::hash::Hash {
        self.hash()
    }
}

#[cfg(test)]
mod tests {
    use super::BlockHeader;
    use ed25519_dalek::SigningKey;
    use vage_types::Address;

    #[test]
    fn new_header_initializes_expected_defaults() {
        let parent_hash = [1u8; 32];
        let header = BlockHeader::new(parent_hash, 7);

        assert_eq!(header.parent_hash, parent_hash);
        assert_eq!(header.height, 7);
        assert_eq!(header.state_root, [0u8; 32]);
        assert_eq!(header.tx_root, [0u8; 32]);
        assert_eq!(header.receipts_root, [0u8; 32]);
        assert_eq!(header.validator_root, [0u8; 32]);
        assert_eq!(header.proposer, Address::zero());
        assert_eq!(header.signature, None);
        assert!(header.timestamp > 0);
    }

    #[test]
    fn genesis_header_is_fixed_and_valid() {
        let header = BlockHeader::genesis();

        assert_eq!(header.parent_hash, [0u8; 32]);
        assert_eq!(header.height, 0);
        assert_eq!(header.timestamp, 1_600_000_000);
        header.validate_basic().expect("genesis header should validate");
    }

    #[test]
    fn hash_ignores_signature_and_encode_round_trips() {
        let mut header = BlockHeader::new([2u8; 32], 3);
        header.proposer = Address([3u8; 32]);

        let unsigned_hash = header.hash();
        let encoded = header.encode();
        let decoded = BlockHeader::decode(&encoded).expect("decode should succeed");

        header.signature = Some([9u8; 64]);

        assert_eq!(decoded, BlockHeader::decode(&encoded).expect("repeat decode should succeed"));
        assert_eq!(unsigned_hash, header.hash());
    }

    #[test]
    fn parent_height_timestamp_and_root_setters_work() {
        let mut header = BlockHeader::new([4u8; 32], 5);

        header.set_state_root([5u8; 32]);
        header.set_tx_root([6u8; 32]);
        header.set_receipts_root([7u8; 32]);
        header.set_validator_root([8u8; 32]);
        header.set_timestamp(42);

        assert!(header.verify_parent([4u8; 32]));
        assert!(header.verify_height(5));
        assert!(header.verify_timestamp(41));
        assert_eq!(header.state_root, [5u8; 32]);
        assert_eq!(header.tx_root, [6u8; 32]);
        assert_eq!(header.receipts_root, [7u8; 32]);
        assert_eq!(header.validator_root, [8u8; 32]);
        assert_eq!(header.timestamp, 42);
        assert!(header.size_bytes() > 0);
    }

    #[test]
    fn signing_and_signature_verification_work() {
        let signing_key = SigningKey::from_bytes(&[10u8; 32]);
        let public_key = signing_key.verifying_key().to_bytes();
        let proposer = Address::from_public_key(&public_key);
        let mut header = BlockHeader::new([11u8; 32], 9);
        header.proposer = proposer;

        header.sign(&signing_key).expect("signing should succeed");

        assert!(header
            .verify_signature(&public_key)
            .expect("verification should succeed"));
    }

    #[test]
    fn verification_rejects_mismatched_proposer_key() {
        let signing_key = SigningKey::from_bytes(&[12u8; 32]);
        let other_public_key = SigningKey::from_bytes(&[13u8; 32]).verifying_key().to_bytes();
        let mut header = BlockHeader::new([14u8; 32], 10);
        header.proposer = Address::from_public_key(&signing_key.verifying_key().to_bytes());
        header.sign(&signing_key).expect("signing should succeed");

        assert!(header.verify_signature(&other_public_key).is_err());
    }
}
