use anyhow::{Context, Result};
use serde::Serialize;
use sha2::{Digest, Sha256};
use vage_types::{Canonical, Transaction, Validator};

/// Canonical cryptographic hash type.
pub type Hash = [u8; 32];

pub const GENESIS_HASH: Hash = [0u8; 32];

pub const DOMAIN_TX_HASH: &str = "VAGE_TX";
pub const DOMAIN_BLOCK_HASH: &str = "VAGE_BLOCK";
pub const DOMAIN_CONSENSUS: &str = "VAGE_CONSENSUS";

/// Compute the SHA256 digest of arbitrary data.
pub fn sha256(data: &[u8]) -> Hash {
    let mut hash = [0u8; 32];
    sha256_into(data, &mut hash);
    hash
}

/// Compute the SHA256 digest directly into a caller-provided output buffer.
pub fn sha256_into(data: &[u8], out: &mut Hash) {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let result = hasher.finalize();
    out.copy_from_slice(&result);
}

/// Compute a hash with domain separation to prevent replay attacks.
pub fn domain_hash(domain: &str, data: &[u8]) -> Hash {
    let mut hash = [0u8; 32];
    domain_hash_into(domain, data, &mut hash);
    hash
}

/// Compute a domain-separated hash directly into a caller-provided output buffer.
pub fn domain_hash_into(domain: &str, data: &[u8], out: &mut Hash) {
    let mut hasher = Sha256::new();
    hasher.update(domain.as_bytes());
    hasher.update(data);
    let result = hasher.finalize();
    out.copy_from_slice(&result);
}

/// A wrapper for deterministic hashing of byte slices.
pub fn hash_bytes(data: &[u8]) -> Hash {
    sha256(data)
}

/// Concatenate and hash two hashes (useful for Merkle trees).
pub fn hash_concat(left: Hash, right: Hash) -> Hash {
    let mut hasher = Sha256::new();
    hasher.update(left);
    hasher.update(right);
    let result = hasher.finalize();
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&result);
    hash
}

/// Hash a key-value pair or composite data.
pub fn hash_pair(a: &[u8], b: &[u8]) -> Hash {
    let mut hash = [0u8; 32];
    hash_pair_into(a, b, &mut hash);
    hash
}

/// Hash two byte slices into a caller-provided output buffer without intermediate allocation.
pub fn hash_pair_into(a: &[u8], b: &[u8], out: &mut Hash) {
    let mut hasher = Sha256::new();
    hasher.update(a);
    hasher.update(b);
    let result = hasher.finalize();
    out.copy_from_slice(&result);
}

/// Hash a canonically serializable structure using the shared deterministic encoding path.
pub fn hash_struct<T: Canonical + Serialize>(value: &T) -> Hash {
    let bytes = Canonical::encode(value);
    sha256(&bytes)
}

/// The hash of empty state or empty data.
pub fn hash_empty() -> Hash {
    sha256(&[])
}

/// Utility for hashing common UTF-8 strings.
pub fn hash_string(s: &str) -> Hash {
    sha256(s.as_bytes())
}

/// Format a hash as a hexadecimal string.
pub fn hash_hex(hash: Hash) -> String {
    hex::encode(hash)
}

/// Parse a hexadecimal string into a 32-byte hash.
pub fn parse_hash(h: &str) -> Result<Hash> {
    let vec =
        hex::decode(h.trim_start_matches("0x")).context("Invalid hex string for hash parsing")?;
    if vec.len() != 32 {
        anyhow::bail!("Invalid hash length: expected 32 bytes, got {}", vec.len());
    }
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&vec);
    Ok(hash)
}

// --- Hashable Trait & Implementations ---

pub trait Hashable {
    fn hash(&self) -> Hash;
}

impl Hashable for Transaction {
    fn hash(&self) -> Hash {
        vage_types::Canonical::hash(self)
    }
}

// Removed BlockHeader

impl Hashable for Validator {
    fn hash(&self) -> Hash {
        vage_types::Canonical::hash(self)
    }
}

// --- Random & Key Derivation Utilities ---

/// Generate cryptographically secure random bytes of a given length.
pub fn secure_random_bytes(len: usize) -> Vec<u8> {
    use rand::{thread_rng, RngCore};
    let mut bytes = vec![0u8; len];
    thread_rng().fill_bytes(&mut bytes);
    bytes
}

/// Generate a 32-byte cryptographically secure random seed.
pub fn generate_seed() -> [u8; 32] {
    use rand::{thread_rng, RngCore};
    let mut seed = [0u8; 32];
    thread_rng().fill_bytes(&mut seed);
    seed
}

/// Derive a deterministic 32-byte key from a seed and an index.
pub fn derive_key(seed: &[u8; 32], index: u64) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(seed);
    hasher.update(index.to_le_bytes());
    let result = hasher.finalize();
    let mut key = [0u8; 32];
    key.copy_from_slice(&result);
    key
}

/// Link a data point to a previous hash (Blockchain chaining).
pub fn hash_chain(previous_hash: Hash, data: &[u8]) -> Hash {
    hash_pair(&previous_hash, &sha256(data))
}

/// Hash a single 64-bit unsigned integer (for indexing/nonces).
pub fn hash_u64(val: u64) -> Hash {
    sha256(&val.to_le_bytes())
}

/// Hash an Address structure.
pub fn hash_address(addr: &vage_types::Address) -> Hash {
    sha256(addr.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::{
        derive_key, domain_hash, domain_hash_into, generate_seed, hash_address, hash_bytes,
        hash_chain, hash_concat, hash_empty, hash_hex, hash_pair, hash_pair_into, hash_string,
        hash_struct, hash_u64, parse_hash, secure_random_bytes, sha256, sha256_into,
        DOMAIN_CONSENSUS, GENESIS_HASH,
    };
    use vage_types::{Address, Canonical, NetworkMessage, Transaction};

    #[test]
    fn sha256_and_hash_bytes_match() {
        let data = b"vage";
        assert_eq!(sha256(data), hash_bytes(data));
    }

    #[test]
    fn concat_pair_and_empty_hashes_are_stable() {
        let left = [1u8; 32];
        let right = [2u8; 32];

        assert_eq!(GENESIS_HASH, [0u8; 32]);
        assert_eq!(hash_empty(), sha256(&[]));
        assert_eq!(hash_concat(left, right), hash_pair(&left, &right));
    }

    #[test]
    fn string_and_hex_round_trip_work() {
        let hash = hash_string("vage");
        let encoded = hash_hex(hash);
        let decoded = parse_hash(&encoded).expect("hash parsing should succeed");

        assert_eq!(decoded, hash);
    }

    #[test]
    fn hash_struct_uses_deterministic_encoding() {
        let tx = Transaction::new_transfer(Address([1u8; 32]), Address([2u8; 32]), 3u64.into(), 4);

        assert_eq!(hash_struct(&tx), hash_struct(&tx));
        assert_eq!(hash_struct(&tx), sha256(&Canonical::encode(&tx)));
    }

    #[test]
    fn secure_random_bytes_and_seed_have_expected_sizes() {
        let bytes = secure_random_bytes(48);
        let seed = generate_seed();

        assert_eq!(bytes.len(), 48);
        assert_eq!(seed.len(), 32);
    }

    #[test]
    fn derive_key_is_deterministic_per_index() {
        let seed = [7u8; 32];

        assert_eq!(derive_key(&seed, 1), derive_key(&seed, 1));
        assert_ne!(derive_key(&seed, 1), derive_key(&seed, 2));
    }

    #[test]
    fn chain_u64_and_address_hash_helpers_match_sha256_inputs() {
        let previous_hash = [3u8; 32];
        let data = b"block-data";
        let address = Address([9u8; 32]);

        assert_eq!(
            hash_chain(previous_hash, data),
            hash_pair(&previous_hash, &sha256(data))
        );
        assert_eq!(hash_u64(42), sha256(&42u64.to_le_bytes()));
        assert_eq!(hash_address(&address), sha256(address.as_bytes()));
    }

    #[test]
    fn consensus_messages_encode_and_hash_stably_across_nodes() {
        let message = NetworkMessage::ConsensusVote {
            validator: [3u8; 32],
            block_hash: [4u8; 32],
            signature: vec![5u8; 64],
        };

        let node_a_bytes = Canonical::encode(&message);
        let node_b_bytes = Canonical::encode(&message);

        assert_eq!(node_a_bytes, node_b_bytes);
        assert_eq!(hash_struct(&message), sha256(&node_a_bytes));
        assert_ne!(
            super::domain_hash(DOMAIN_CONSENSUS, &node_a_bytes),
            sha256(&node_a_bytes)
        );
    }

    #[test]
    fn zero_copy_hash_helpers_match_allocating_variants() {
        let mut sha_out = [0u8; 32];
        let mut domain_out = [0u8; 32];
        let mut pair_out = [0u8; 32];

        sha256_into(b"payload", &mut sha_out);
        domain_hash_into(DOMAIN_CONSENSUS, b"payload", &mut domain_out);
        hash_pair_into(b"left", b"right", &mut pair_out);

        assert_eq!(sha_out, sha256(b"payload"));
        assert_eq!(domain_out, domain_hash(DOMAIN_CONSENSUS, b"payload"));
        assert_eq!(pair_out, hash_pair(b"left", b"right"));
    }
}
