use anyhow::Result;
use serde::{de::DeserializeOwned, Serialize};
use sha2::{Digest, Sha256};

/// A trait for types that can be canonically serialized and hashed.
pub trait Canonical: Serialize + DeserializeOwned {
    /// Serialize the object into its canonical binary representation using bincode.
    /// This ensures deterministic output across all nodes in the network.
    fn encode(&self) -> Vec<u8> {
        use bincode::Options;
        // Use a strictly deterministic configuration: Little Endian, Variable Integer Encoding, and reject trailing bytes.
        let options = bincode::options()
            .with_little_endian()
            .with_varint_encoding()
            .reject_trailing_bytes();

        options
            .serialize(self)
            .expect("Canonical serialization should not fail")
    }

    /// Deserialize an object from its canonical binary representation.
    fn decode(bytes: &[u8]) -> Result<Self> {
        use bincode::Options;
        let options = bincode::options()
            .with_little_endian()
            .with_varint_encoding()
            .reject_trailing_bytes();

        options
            .deserialize(bytes)
            .map_err(|e| anyhow::anyhow!("Decoding failed: {:?}", e))
    }

    /// Calculate the canonical hash of the object using SHA256.
    fn hash(&self) -> [u8; 32] {
        let bytes = self.encode();
        let mut hasher = Sha256::new();
        hasher.update(&bytes);
        let result = hasher.finalize();
        let mut hash_bytes = [0u8; 32];
        hash_bytes.copy_from_slice(&result);
        hash_bytes
    }
}

// Blanket implementation for all suitable types.
impl<T: Serialize + DeserializeOwned> Canonical for T {}
