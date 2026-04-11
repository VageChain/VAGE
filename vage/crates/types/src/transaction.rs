use crate::Address;
use anyhow::{bail, Result};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use primitive_types::U256;
use rlp::{Decodable, Encodable, Rlp, RlpStream};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Custom serde helpers for `Option<[u8; 64]>` (Ed25519 signature).
/// Serde doesn't implement Deserialize for arrays larger than 32 out of the box.
mod serde_sig {
    use serde::{Deserializer, Serializer};
    use serde::de::Error;

    pub fn serialize<S: Serializer>(val: &Option<[u8; 64]>, s: S) -> Result<S::Ok, S::Error> {
        match val {
            Some(bytes) => s.serialize_some(bytes.as_slice()),
            None => s.serialize_none(),
        }
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Option<[u8; 64]>, D::Error> {
        let opt: Option<Vec<u8>> = serde::Deserialize::deserialize(d)?;
        match opt {
            None => Ok(None),
            Some(bytes) => bytes
                .try_into()
                .map(Some)
                .map_err(|_| D::Error::custom("expected 64-byte ed25519 signature")),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Transaction {
    pub from: Address,
    pub to: Option<Address>, // None for contract creation
    #[serde(default)]
    pub signer_pubkey: Option<[u8; 32]>,
    pub value: U256,
    pub nonce: u64,
    pub gas_limit: u64,
    pub gas_price: U256,
    pub data: Vec<u8>,
    #[serde(with = "serde_sig")]
    pub signature: Option<[u8; 64]>,
    /// EIP-155-style replay protection. Transactions without a chain_id are rejected
    /// by the mempool unless explicitly configured to allow chain-agnostic txs.
    #[serde(default)]
    pub chain_id: Option<u64>,
}

impl Transaction {
    /// Create a new value transfer transaction.
    pub fn new_transfer(from: Address, to: Address, value: U256, nonce: u64) -> Self {
        Self {
            from,
            to: Some(to),
            signer_pubkey: None,
            value,
            nonce,
            gas_limit: 210,
            gas_price: U256::from(1),
            data: Vec::new(),
            signature: None,
            chain_id: Some(1),
        }
    }

    /// Create a new contract call transaction.
    pub fn new_contract_call(
        from: Address,
        to: Address,
        value: U256,
        nonce: u64,
        data: Vec<u8>,
    ) -> Self {
        Self {
            from,
            to: Some(to),
            signer_pubkey: None,
            value,
            nonce,
            gas_limit: 1000,
            gas_price: U256::from(1),
            data,
            signature: None,
            chain_id: Some(1),
        }
    }

    /// Create a new contract deployment transaction.
    pub fn new_contract_deploy(from: Address, value: U256, nonce: u64, code: Vec<u8>) -> Self {
        Self {
            from,
            to: None,
            signer_pubkey: None,
            value,
            nonce,
            gas_limit: 10000,
            gas_price: U256::from(1),
            data: code,
            signature: None,
            chain_id: Some(1),
        }
    }

    /// Calculate the canonical hash of the transaction using SHA256.
    pub fn hash(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        // Hash the transaction fields without the signature
        let mut temp = self.clone();
        temp.signature = None;
        let bytes = bincode::serialize(&temp).expect("transaction serialization should succeed");
        hasher.update(&bytes);
        let result = hasher.finalize();
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&result);
        bytes
    }

    /// Sign the transaction using an Ed25519 private key.
    pub fn sign(&mut self, signing_key: &SigningKey) -> Result<()> {
        let public_key = signing_key.verifying_key().to_bytes();
        let derived_sender = Address::from_public_key(&public_key);
        if derived_sender != self.from {
            bail!(
                "signing key does not match transaction sender: expected {}, derived {}",
                self.from,
                derived_sender
            );
        }

        self.signer_pubkey = Some(public_key);
        let hash = self.hash();
        let sig = signing_key.sign(&hash);
        self.signature = Some(sig.to_bytes());
        Ok(())
    }

    /// Verify the transaction's signature.
    pub fn verify_signature(&self) -> Result<bool> {
        let sig_bytes = self
            .signature
            .ok_or_else(|| anyhow::anyhow!("No signature present"))?;
        let public_key_bytes = self
            .signer_pubkey
            .ok_or_else(|| anyhow::anyhow!("No signer public key present"))?;

        if Address::from_public_key(&public_key_bytes) != self.from {
            bail!("signer public key does not match transaction sender address");
        }

        let public_key = VerifyingKey::from_bytes(&public_key_bytes)
            .map_err(|e| anyhow::anyhow!("Invalid public key: {:?}", e))?;
        let sig = Signature::from_bytes(&sig_bytes);
        let hash = self.hash();

        public_key
            .verify(&hash, &sig)
            .map(|_| true)
            .map_err(|e| anyhow::anyhow!("Signature verification failed: {:?}", e))
    }

    pub fn sender(&self) -> Result<Address> {
        let public_key_bytes = self
            .signer_pubkey
            .ok_or_else(|| anyhow::anyhow!("No signer public key present"))?;
        Ok(Address::from_public_key(&public_key_bytes))
    }

    pub fn validate_signature(&self) -> Result<()> {
        if !self.verify_signature()? {
            bail!("Transaction signature is invalid");
        }
        Ok(())
    }

    /// Get total gas cost for the transaction.
    pub fn gas_cost(&self) -> U256 {
        self.gas_price.saturating_mul(U256::from(self.gas_limit))
    }

    /// Returns the approximate size of the transaction in bytes.
    pub fn size_bytes(&self) -> usize {
        bincode::serialize(self)
            .expect("transaction serialization should succeed")
            .len()
    }

    pub fn is_contract_creation(&self) -> bool {
        self.to.is_none()
    }

    pub fn is_contract_call(&self) -> bool {
        self.to.is_some() && !self.data.is_empty()
    }

    pub fn validate_gas_limit(&self) -> Result<()> {
        if self.gas_limit == 0 {
            bail!("Gas limit must be greater than zero");
        }
        Ok(())
    }

    pub fn validate_nonce(&self, expected_nonce: u64) -> Result<()> {
        if self.nonce != expected_nonce {
            bail!(
                "Invalid transaction nonce. Expected {}, got {}",
                expected_nonce,
                self.nonce
            );
        }
        Ok(())
    }

    /// Validate the transaction's basic properties.
    pub fn validate_basic(&self) -> Result<()> {
        self.validate_gas_limit()?;

        if self.gas_price.is_zero() {
            bail!("Gas price must be greater than zero");
        }

        if self.is_contract_creation() && self.data.is_empty() {
            bail!("Contract creation must include deployment code");
        }

        Ok(())
    }

    pub fn rlp_encode(&self) -> Vec<u8> {
        rlp::encode(self).to_vec()
    }

    pub fn rlp_decode(bytes: &[u8]) -> Result<Self> {
        rlp::decode(bytes).map_err(|error| anyhow::anyhow!("RLP decode failed: {:?}", error))
    }
}

// RLP Encoding/Decoding for network compatibility
impl Encodable for Transaction {
    fn rlp_append(&self, s: &mut RlpStream) {
        s.begin_list(10);
        s.append(&self.from.0.as_slice());
        match &self.to {
            Some(addr) => { s.append(&addr.0.as_slice()); }
            None => { s.append_empty_data(); }
        }
        match &self.signer_pubkey {
            Some(pubkey) => { s.append(&pubkey.as_slice()); }
            None => { s.append_empty_data(); }
        }
        // U256 doesn't implement rlp::Encodable — encode as 32 big-endian bytes.
        let mut value_bytes = [0u8; 32];
        self.value.to_big_endian(&mut value_bytes);
        s.append(&value_bytes.as_slice());
        s.append(&self.nonce);
        s.append(&self.gas_limit);
        let mut price_bytes = [0u8; 32];
        self.gas_price.to_big_endian(&mut price_bytes);
        s.append(&price_bytes.as_slice());
        s.append(&self.data);
        match &self.signature {
            Some(sig) => { s.append(&sig.as_slice()); }
            None => { s.append_empty_data(); }
        }
        s.append(&self.chain_id.unwrap_or_default());
    }
}

impl Decodable for Transaction {
    fn decode(rlp: &Rlp) -> Result<Self, rlp::DecoderError> {
        Ok(Self {
            from: {
                let bytes: Vec<u8> = rlp.val_at(0)?;
                Address(bytes.try_into().map_err(|_| {
                    rlp::DecoderError::Custom("Invalid from address length")
                })?)
            },
            to: {
                let bytes: Vec<u8> = rlp.val_at(1)?;
                if bytes.is_empty() {
                    None
                } else {
                    Some(Address(bytes.try_into().map_err(|_| {
                        rlp::DecoderError::Custom("Invalid address length")
                    })?))
                }
            },
            signer_pubkey: {
                let bytes: Vec<u8> = rlp.val_at(2)?;
                if bytes.is_empty() {
                    None
                } else {
                    Some(
                        bytes
                            .try_into()
                            .map_err(|_| rlp::DecoderError::Custom("Invalid public key length"))?,
                    )
                }
            },
            value: {
                let bytes: Vec<u8> = rlp.val_at(3)?;
                U256::from_big_endian(&bytes)
            },
            nonce: rlp.val_at(4)?,
            gas_limit: rlp.val_at(5)?,
            gas_price: {
                let bytes: Vec<u8> = rlp.val_at(6)?;
                U256::from_big_endian(&bytes)
            },
            data: rlp.val_at(7)?,
            signature: {
                let bytes: Vec<u8> = rlp.val_at(8)?;
                if bytes.is_empty() {
                    None
                } else {
                    Some(
                        bytes
                            .try_into()
                            .map_err(|_| rlp::DecoderError::Custom("Invalid signature length"))?,
                    )
                }
            },
            chain_id: if rlp.item_count()? > 9 {
                Some(rlp.val_at(9)?)
            } else {
                None
            },
        })
    }
}

#[cfg(test)]
mod tests {
    use super::Transaction;
    use crate::Address;
    use ed25519_dalek::SigningKey;
    use primitive_types::U256;

    #[test]
    fn constructors_set_expected_defaults() {
        let from = Address([1u8; 32]);
        let to = Address([2u8; 32]);

        let transfer = Transaction::new_transfer(from, to, U256::from(5u64), 7);
        let call = Transaction::new_contract_call(from, to, U256::from(6u64), 8, vec![1, 2]);
        let deploy = Transaction::new_contract_deploy(from, U256::from(7u64), 9, vec![3, 4]);

        assert_eq!(transfer.to, Some(to));
        assert_eq!(transfer.signer_pubkey, None);
        assert_eq!(transfer.gas_limit, 210);       // VageChain: 21_000 / 100
        assert!(call.is_contract_call());
        assert_eq!(call.gas_limit, 1_000);          // VageChain: 100_000 / 100
        assert!(deploy.is_contract_creation());
        assert_eq!(deploy.gas_limit, 10_000);       // VageChain: 1_000_000 / 100
    }

    #[test]
    fn signing_and_signature_validation_work() {
        let signing_key = SigningKey::from_bytes(&[7u8; 32]);
        let public_key = signing_key.verifying_key().to_bytes();
        let from = Address::from_public_key(&public_key);
        let to = Address([3u8; 32]);
        let mut tx = Transaction::new_transfer(from, to, U256::from(10u64), 1);

        tx.sign(&signing_key).expect("signing should succeed");

        assert_eq!(tx.signer_pubkey, Some(public_key));
        assert!(tx.verify_signature().expect("verification should succeed"));
        tx.validate_signature()
            .expect("signature should validate");
        assert_eq!(tx.sender().expect("sender recovery should work"), from);
    }

    #[test]
    fn sender_recovery_requires_embedded_public_key() {
        let tx = Transaction::new_transfer(
            Address([1u8; 32]),
            Address([2u8; 32]),
            U256::from(1u64),
            0,
        );

        assert!(tx.sender().is_err());
    }

    #[test]
    fn signing_rejects_mismatched_sender_address() {
        let signing_key = SigningKey::from_bytes(&[11u8; 32]);
        let mut tx = Transaction::new_transfer(
            Address([12u8; 32]),
            Address([13u8; 32]),
            U256::from(1u64),
            0,
        );

        assert!(tx.sign(&signing_key).is_err());
    }

    #[test]
    fn gas_cost_size_and_hash_are_deterministic() {
        let tx = Transaction::new_contract_call(
            Address([4u8; 32]),
            Address([5u8; 32]),
            U256::from(9u64),
            2,
            vec![9, 8, 7],
        );

        assert_eq!(tx.gas_cost(), U256::from(1_000u64)); // gas_limit=1000, gas_price=1
        assert!(tx.size_bytes() > 0);
        assert_eq!(tx.hash(), tx.hash());
    }

    #[test]
    fn validation_helpers_reject_invalid_nonce_and_gas() {
        let mut tx = Transaction::new_transfer(
            Address([6u8; 32]),
            Address([7u8; 32]),
            U256::from(1u64),
            3,
        );

        assert!(tx.validate_nonce(2).is_err());

        tx.gas_limit = 0;
        assert!(tx.validate_gas_limit().is_err());
        assert!(tx.validate_basic().is_err());
    }

    #[test]
    fn validate_basic_rejects_invalid_contract_deploys() {
        let tx = Transaction::new_contract_deploy(
            Address([8u8; 32]),
            U256::from(1u64),
            0,
            Vec::new(),
        );

        assert!(tx.validate_basic().is_err());
    }

    #[test]
    fn bincode_and_rlp_round_trip() {
        let signing_key = SigningKey::from_bytes(&[9u8; 32]);
        let public_key = signing_key.verifying_key().to_bytes();
        let from = Address::from_public_key(&public_key);
        let mut tx = Transaction::new_contract_call(
            from,
            Address([10u8; 32]),
            U256::from(15u64),
            5,
            vec![1, 2, 3, 4],
        );
        tx.sign(&signing_key).expect("signing should succeed");

        let encoded = bincode::serialize(&tx).expect("bincode serialization should work");
        let decoded: Transaction =
            bincode::deserialize(&encoded).expect("bincode deserialization should work");
        let rlp_round_trip = Transaction::rlp_decode(&tx.rlp_encode()).expect("rlp should round-trip");

        assert_eq!(decoded, tx);
        assert_eq!(rlp_round_trip, tx);
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Log {
    pub address: Address,
    pub topics: Vec<[u8; 32]>,
    pub data: Vec<u8>,
}

impl Log {
    /// Create a new log entry.
    pub fn new(address: Address, topics: Vec<[u8; 32]>, data: Vec<u8>) -> Self {
        Self {
            address,
            topics,
            data,
        }
    }

    /// Calculate a hash of all topics (for specialized indexing).
    pub fn topic_hash(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        for topic in &self.topics {
            hasher.update(topic);
        }
        let result = hasher.finalize();
        let mut hash_bytes = [0u8; 32];
        hash_bytes.copy_from_slice(&result);
        hash_bytes
    }

    /// Encode the log into its canonical binary representation.
    pub fn encode(&self) -> Vec<u8> {
        bincode::serialize(self).expect("log serialization should succeed")
    }
}

#[cfg(test)]
mod log_tests {
    use super::Log;
    use crate::Address;

    #[test]
    fn new_log_initializes_expected_fields() {
        let address = Address([1u8; 32]);
        let topics = vec![[2u8; 32], [3u8; 32]];
        let data = vec![4, 5, 6];

        let log = Log::new(address, topics.clone(), data.clone());

        assert_eq!(log.address, address);
        assert_eq!(log.topics, topics);
        assert_eq!(log.data, data);
    }

    #[test]
    fn topic_hash_is_deterministic() {
        let log = Log::new(Address([7u8; 32]), vec![[8u8; 32], [9u8; 32]], vec![1, 2]);

        assert_eq!(log.topic_hash(), log.topic_hash());
    }

    #[test]
    fn encode_round_trip_preserves_log() {
        let log = Log::new(
            Address([10u8; 32]),
            vec![[11u8; 32], [12u8; 32]],
            vec![13, 14, 15],
        );

        let encoded = log.encode();
        let decoded: Log = bincode::deserialize(&encoded).expect("log deserialization should work");

        assert_eq!(decoded, log);
    }

    #[test]
    fn serde_round_trip_preserves_log() {
        let log = Log::new(Address([16u8; 32]), vec![[17u8; 32]], vec![18, 19]);

        let json = serde_json::to_string(&log).expect("log json serialization should work");
        let decoded: Log = serde_json::from_str(&json).expect("log json deserialization should work");

        assert_eq!(decoded, log);
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Receipt {
    pub tx_hash: [u8; 32],
    pub status: bool, // true for success, false for failure
    pub gas_used: u64,
    pub logs: Vec<Log>,
    pub state_root: Option<[u8; 32]>,
}

impl Receipt {
    /// Create a new successful transaction receipt.
    pub fn new_success(tx_hash: [u8; 32], gas_used: u64, state_root: Option<[u8; 32]>) -> Self {
        Self {
            tx_hash,
            status: true,
            gas_used,
            logs: Vec::new(),
            state_root,
        }
    }

    /// Create a new failed transaction receipt.
    pub fn new_failure(tx_hash: [u8; 32], gas_used: u64) -> Self {
        Self {
            tx_hash,
            status: false,
            gas_used,
            logs: Vec::new(),
            state_root: None,
        }
    }

    /// Add an event log entry to the transaction receipt.
    pub fn add_log(&mut self, entry: Log) {
        self.logs.push(entry);
    }

    /// Calculate the canonical hash of the receipt for Merkle tree inclusion.
    pub fn hash(&self) -> [u8; 32] {
        let bytes = bincode::serialize(self).expect("receipt serialization should succeed");
        let mut hasher = Sha256::new();
        hasher.update(&bytes);
        let result = hasher.finalize();
        let mut hash_bytes = [0u8; 32];
        hash_bytes.copy_from_slice(&result);
        hash_bytes
    }

    /// Canonical binary encoding for storage.
    pub fn bincode_encode(&self) -> Vec<u8> {
        bincode::serialize(self).expect("receipt serialization should succeed")
    }
}

#[cfg(test)]
mod receipt_tests {
    use super::{Log, Receipt};
    use crate::Address;

    #[test]
    fn new_success_initializes_expected_fields() {
        let tx_hash = [1u8; 32];
        let state_root = Some([2u8; 32]);

        let receipt = Receipt::new_success(tx_hash, 21_000, state_root);

        assert_eq!(receipt.tx_hash, tx_hash);
        assert!(receipt.status);
        assert_eq!(receipt.gas_used, 21_000);
        assert!(receipt.logs.is_empty());
        assert_eq!(receipt.state_root, state_root);
    }

    #[test]
    fn new_failure_clears_state_root() {
        let tx_hash = [3u8; 32];

        let receipt = Receipt::new_failure(tx_hash, 50_000);

        assert_eq!(receipt.tx_hash, tx_hash);
        assert!(!receipt.status);
        assert_eq!(receipt.gas_used, 50_000);
        assert!(receipt.logs.is_empty());
        assert_eq!(receipt.state_root, None);
    }

    #[test]
    fn add_log_appends_entries() {
        let mut receipt = Receipt::new_success([4u8; 32], 30_000, Some([5u8; 32]));
        let log = Log::new(Address([6u8; 32]), vec![[7u8; 32]], vec![1, 2, 3]);

        receipt.add_log(log.clone());

        assert_eq!(receipt.logs, vec![log]);
    }

    #[test]
    fn hash_and_bincode_are_deterministic() {
        let mut receipt = Receipt::new_success([8u8; 32], 42_000, Some([9u8; 32]));
        receipt.add_log(Log::new(Address([10u8; 32]), vec![[11u8; 32]], vec![4, 5, 6]));

        let first_hash = receipt.hash();
        let second_hash = receipt.hash();
        let encoded = receipt.bincode_encode();
        let decoded: Receipt =
            bincode::deserialize(&encoded).expect("receipt deserialization should work");

        assert_eq!(first_hash, second_hash);
        assert_eq!(decoded, receipt);
    }

    #[test]
    fn serde_round_trip_preserves_receipt_fields() {
        let mut receipt = Receipt::new_failure([12u8; 32], 64_000);
        receipt.add_log(Log::new(
            Address([13u8; 32]),
            vec![[14u8; 32], [15u8; 32]],
            vec![7, 8, 9],
        ));

        let json = serde_json::to_string(&receipt).expect("receipt json serialization should work");
        let decoded: Receipt =
            serde_json::from_str(&json).expect("receipt json deserialization should work");

        assert_eq!(decoded, receipt);
    }
}
