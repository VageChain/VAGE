use crate::{Canonical, Transaction};
use serde::{Deserialize, Serialize};

pub const CANONICAL_MESSAGE_VERSION: u8 = 1;
pub const MAX_CANONICAL_MESSAGE_SIZE: usize = 2 * 1024 * 1024;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum NetworkMessage {
    // --- Mempool Propagation ---
    GossipTransaction(Transaction),

    // --- Consensus Propagation ---
    GossipProposedBlock(Vec<u8>), // Serialized block data
    ConsensusVote {
        validator: [u8; 32],
        block_hash: [u8; 32],
        signature: Vec<u8>,
    },

    // --- Light Client / RPC Sync ---
    GetBlockHeaders {
        start_height: u64,
        limit: u64,
    },
    BlockHeaders(Vec<Vec<u8>>),

    // --- State Sync ---
    GetStateProof(Vec<u8>),
    StateProof(Vec<u8>),
}

impl NetworkMessage {
    pub fn encode(&self) -> Vec<u8> {
        <Self as Canonical>::encode(self)
    }

    pub fn decode(bytes: &[u8]) -> anyhow::Result<Self> {
        <Self as Canonical>::decode(bytes)
    }

    pub fn hash(&self) -> [u8; 32] {
        <Self as Canonical>::hash(self)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CanonicalMessage {
    pub version: u8,
    pub compressed: bool,
    pub payload: Vec<u8>,
}

impl CanonicalMessage {
    pub fn new(payload: Vec<u8>) -> anyhow::Result<Self> {
        let compressed_payload = compress_payload(&payload);
        let (compressed, payload) = if compressed_payload.len() < payload.len() {
            (true, compressed_payload)
        } else {
            (false, payload)
        };

        let message = Self {
            version: CANONICAL_MESSAGE_VERSION,
            compressed,
            payload,
        };
        message.validate_size()?;
        Ok(message)
    }

    pub fn from_network_message(message: &NetworkMessage) -> anyhow::Result<Self> {
        let payload = message.encode();
        Self::new(payload)
    }

    pub fn to_network_message(&self) -> anyhow::Result<NetworkMessage> {
        if self.version != CANONICAL_MESSAGE_VERSION {
            anyhow::bail!("unsupported canonical message version {}", self.version);
        }

        let payload = if self.compressed {
            decompress_payload(&self.payload)?
        } else {
            self.payload.clone()
        };

        NetworkMessage::decode(&payload)
    }

    pub fn encode(&self) -> anyhow::Result<Vec<u8>> {
        self.validate_size()?;
        Ok(<Self as Canonical>::encode(self))
    }

    pub fn decode(bytes: &[u8]) -> anyhow::Result<Self> {
        let message = <Self as Canonical>::decode(bytes)?;
        message.validate_size()?;
        Ok(message)
    }

    pub fn validate_size(&self) -> anyhow::Result<()> {
        if self.payload.len() > MAX_CANONICAL_MESSAGE_SIZE {
            anyhow::bail!(
                "canonical message payload exceeds max size: {} > {}",
                self.payload.len(),
                MAX_CANONICAL_MESSAGE_SIZE
            );
        }
        Ok(())
    }
}

// Blank line left as replacement
fn compress_payload(payload: &[u8]) -> Vec<u8> {
    if payload.is_empty() {
        return Vec::new();
    }

    let mut compressed = Vec::with_capacity(payload.len());
    let mut index = 0usize;
    while index < payload.len() {
        let byte = payload[index];
        let mut run_len = 1u8;
        while index + (run_len as usize) < payload.len()
            && payload[index + (run_len as usize)] == byte
            && run_len < u8::MAX
        {
            run_len = run_len.saturating_add(1);
        }

        compressed.push(run_len);
        compressed.push(byte);
        index += run_len as usize;
    }

    compressed
}

fn decompress_payload(payload: &[u8]) -> anyhow::Result<Vec<u8>> {
    if payload.is_empty() {
        return Ok(Vec::new());
    }

    if !payload.len().is_multiple_of(2) {
        anyhow::bail!("invalid compressed payload length");
    }

    let mut decompressed = Vec::new();
    for chunk in payload.chunks_exact(2) {
        let run_len = chunk[0] as usize;
        let byte = chunk[1];
        if run_len == 0 {
            anyhow::bail!("invalid compressed payload run length");
        }
        decompressed.extend(std::iter::repeat_n(byte, run_len));
        if decompressed.len() > MAX_CANONICAL_MESSAGE_SIZE {
            anyhow::bail!("decompressed payload exceeds max canonical message size");
        }
    }

    Ok(decompressed)
}

#[cfg(test)]
mod tests {
    use super::{
        CanonicalMessage, NetworkMessage, CANONICAL_MESSAGE_VERSION, MAX_CANONICAL_MESSAGE_SIZE,
    };
    use crate::{Address, Transaction};
    use primitive_types::U256;

    fn assert_canonical_round_trip(original: NetworkMessage) {
        let canonical = CanonicalMessage::from_network_message(&original)
            .expect("canonical message creation should succeed");
        let encoded = canonical.encode().expect("canonical encode should succeed");
        let decoded = CanonicalMessage::decode(&encoded).expect("canonical decode should succeed");
        let restored = decoded
            .to_network_message()
            .expect("network message should restore");

        assert_eq!(decoded.version, CANONICAL_MESSAGE_VERSION);
        assert_eq!(restored.encode(), original.encode());

        match (original, restored) {
            (
                NetworkMessage::GossipTransaction(expected),
                NetworkMessage::GossipTransaction(actual),
            ) => {
                assert_eq!(actual, expected);
            }
            (
                NetworkMessage::GossipProposedBlock(expected),
                NetworkMessage::GossipProposedBlock(actual),
            ) => {
                assert_eq!(actual, expected);
            }
            (
                NetworkMessage::ConsensusVote {
                    validator: expected_validator,
                    block_hash: expected_hash,
                    signature: expected_signature,
                },
                NetworkMessage::ConsensusVote {
                    validator,
                    block_hash,
                    signature,
                },
            ) => {
                assert_eq!(validator, expected_validator);
                assert_eq!(block_hash, expected_hash);
                assert_eq!(signature, expected_signature);
            }
            (
                NetworkMessage::GetBlockHeaders {
                    start_height: expected_start,
                    limit: expected_limit,
                },
                NetworkMessage::GetBlockHeaders {
                    start_height,
                    limit,
                },
            ) => {
                assert_eq!(start_height, expected_start);
                assert_eq!(limit, expected_limit);
            }
            (NetworkMessage::BlockHeaders(expected), NetworkMessage::BlockHeaders(actual)) => {
                assert_eq!(actual, expected);
            }
            (NetworkMessage::GetStateProof(expected), NetworkMessage::GetStateProof(actual)) => {
                assert_eq!(actual, expected);
            }
            (NetworkMessage::StateProof(expected), NetworkMessage::StateProof(actual)) => {
                assert_eq!(actual, expected);
            }
            (expected, actual) => {
                panic!(
                    "restored different variant: expected {:?}, got {:?}",
                    expected, actual
                );
            }
        }
    }

    #[test]
    fn canonical_message_round_trips_network_payloads() {
        let tx =
            Transaction::new_transfer(Address([1u8; 32]), Address([2u8; 32]), U256::from(10u64), 4);
        assert_canonical_round_trip(NetworkMessage::GossipTransaction(tx));
    }

    #[test]
    fn canonical_message_encoding_is_deterministic() {
        let message = CanonicalMessage::new(vec![7u8; 32]).expect("message should build");

        let first = message.encode().expect("first encode should succeed");
        let second = message.encode().expect("second encode should succeed");
        let decoded = CanonicalMessage::decode(&first).expect("decode should succeed");

        assert_eq!(first, second);
        assert_eq!(decoded.version, CANONICAL_MESSAGE_VERSION);
        assert_eq!(decoded.compressed, message.compressed);
        assert_eq!(decoded.payload, message.payload);
    }

    #[test]
    fn network_message_hash_and_encode_are_deterministic() {
        let message = NetworkMessage::ConsensusVote {
            validator: [3u8; 32],
            block_hash: [4u8; 32],
            signature: vec![5u8; 64],
        };

        let first_encoded = message.encode();
        let second_encoded = message.encode();
        let decoded = NetworkMessage::decode(&first_encoded).expect("decode should succeed");

        assert_eq!(first_encoded, second_encoded);
        assert_eq!(message.hash(), message.hash());
        match decoded {
            NetworkMessage::ConsensusVote {
                validator,
                block_hash,
                signature,
            } => {
                assert_eq!(validator, [3u8; 32]);
                assert_eq!(block_hash, [4u8; 32]);
                assert_eq!(signature, vec![5u8; 64]);
            }
            other => panic!("unexpected decoded message: {:?}", other),
        }
    }

    #[test]
    fn canonical_message_prefers_compression_when_payload_shrinks() {
        let payload = vec![9u8; 512];
        let message = CanonicalMessage::new(payload.clone()).expect("message should build");

        assert!(message.compressed);
        assert!(message.payload.len() < payload.len());
        assert!(message.to_network_message().is_err());
    }

    #[test]
    fn canonical_message_bincode_round_trip_preserves_compression_metadata() {
        let network = NetworkMessage::BlockHeaders(vec![vec![1u8; 64], vec![2u8; 64]]);
        let canonical = CanonicalMessage::from_network_message(&network)
            .expect("canonical message creation should succeed");

        let encoded = canonical.encode().expect("canonical encode should succeed");
        let decoded = CanonicalMessage::decode(&encoded).expect("canonical decode should succeed");
        let restored = decoded
            .to_network_message()
            .expect("network message should restore");

        assert_eq!(decoded.version, CANONICAL_MESSAGE_VERSION);
        assert_eq!(decoded.compressed, canonical.compressed);
        assert_eq!(decoded.payload, canonical.payload);
        match restored {
            NetworkMessage::BlockHeaders(headers) => {
                assert_eq!(headers, vec![vec![1u8; 64], vec![2u8; 64]]);
            }
            other => panic!("unexpected restored message: {:?}", other),
        }
    }

    #[test]
    fn canonical_message_rejects_oversized_payloads_and_decompression_bombs() {
        let oversized = CanonicalMessage {
            version: CANONICAL_MESSAGE_VERSION,
            compressed: false,
            payload: vec![0u8; MAX_CANONICAL_MESSAGE_SIZE + 1],
        };
        assert!(oversized.validate_size().is_err());
        assert!(oversized.encode().is_err());

        let decompression_bomb = CanonicalMessage {
            version: CANONICAL_MESSAGE_VERSION,
            compressed: true,
            payload: vec![255, 1, 255, 1, 255, 1],
        };
        assert!(decompression_bomb.validate_size().is_ok());
        assert!(decompression_bomb.to_network_message().is_err());
    }

    #[test]
    fn canonical_message_round_trips_multiple_network_variants_exactly() {
        let tx =
            Transaction::new_transfer(Address([9u8; 32]), Address([8u8; 32]), U256::from(55u64), 9);
        let cases = vec![
            NetworkMessage::GossipTransaction(tx.clone()),
            NetworkMessage::GossipProposedBlock(vec![7u8; 256]),
            NetworkMessage::ConsensusVote {
                validator: [1u8; 32],
                block_hash: [2u8; 32],
                signature: vec![3u8; 96],
            },
            NetworkMessage::GetBlockHeaders {
                start_height: 12,
                limit: 4,
            },
            NetworkMessage::BlockHeaders(vec![vec![4u8; 80], vec![5u8; 96]]),
            NetworkMessage::GetStateProof(vec![6u8; 128]),
            NetworkMessage::StateProof(vec![7u8; 192]),
        ];

        for original in cases {
            assert_canonical_round_trip(original);
        }
    }
}
