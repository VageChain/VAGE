use rand::Rng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fmt;

#[derive(
    Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize, PartialOrd, Ord,
)]
pub struct Address(pub [u8; 32]);

impl Address {
    /// Create a new address from a 32-byte public key using SHA256 hashing.
    pub fn from_public_key(pubkey: &[u8]) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(pubkey);
        let result = hasher.finalize();
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&result);
        Self(bytes)
    }

    /// Return an all-zero address (e.g., for system accounts).
    pub fn zero() -> Self {
        Self([0u8; 32])
    }

    /// Check if the address is all zero.
    pub fn is_zero(&self) -> bool {
        self.0 == [0u8; 32]
    }

    /// Create a random address (mainly for testing).
    pub fn random() -> Self {
        let mut rng = rand::thread_rng();
        let mut bytes = [0u8; 32];
        rng.fill(&mut bytes);
        Self(bytes)
    }

    /// Return the hexadecimal representation of the address.
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    /// Parse an address from a hexadecimal string.
    pub fn from_hex(s: &str) -> Result<Self, hex::FromHexError> {
        let vec = hex::decode(s.trim_start_matches("0x"))?;
        if vec.len() != 32 {
            return Err(hex::FromHexError::InvalidStringLength);
        }
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&vec);
        Ok(Self(bytes))
    }

    /// Return the raw bytes of the address.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl AsRef<[u8; 32]> for Address {
    fn as_ref(&self) -> &[u8; 32] {
        &self.0
    }
}

impl AsRef<[u8]> for Address {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Display for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "0x{}", self.to_hex())
    }
}

impl From<[u8; 32]> for Address {
    fn from(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

impl TryFrom<&[u8]> for Address {
    type Error = &'static str;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        if bytes.len() != 32 {
            return Err("Invalid address length. Expected 32 bytes.");
        }
        let mut addr = [0u8; 32];
        addr.copy_from_slice(bytes);
        Ok(Self(addr))
    }
}

impl From<Address> for [u8; 32] {
    fn from(address: Address) -> [u8; 32] {
        address.0
    }
}

#[cfg(test)]
mod tests {
    use super::Address;

    #[test]
    fn derives_address_from_public_key_with_sha256() {
        let public_key = [7u8; 32];

        let address = Address::from_public_key(&public_key);

        assert_eq!(
            address.to_hex(),
            "4bb06f8e4e3a7715d201d573d0aa423762e55dabd61a2c02278fa56cc6d294e0"
        );
    }

    #[test]
    fn zero_address_helpers_are_consistent() {
        let address = Address::zero();

        assert!(address.is_zero());
        assert_eq!(address.as_bytes(), &[0u8; 32]);
        assert_eq!(address.to_string(), format!("0x{}", "00".repeat(32)));
    }

    #[test]
    fn hex_round_trip_supports_prefixed_strings() {
        let original = Address([0x11; 32]);
        let encoded = format!("0x{}", original.to_hex());

        let decoded = Address::from_hex(&encoded).expect("hex decoding should work");

        assert_eq!(decoded, original);
    }

    #[test]
    fn try_from_slice_validates_length() {
        let bytes = [3u8; 32];

        let address = Address::try_from(bytes.as_slice()).expect("32-byte slice is valid");
        let round_trip: [u8; 32] = address.into();

        assert_eq!(address, Address(bytes));
        assert_eq!(round_trip, bytes);
        assert!(Address::try_from(&bytes[..31]).is_err());
    }

    #[test]
    fn serde_and_bincode_round_trip() {
        let address = Address::random();

        let json = serde_json::to_string(&address).expect("json serialization should work");
        let json_round_trip: Address =
            serde_json::from_str(&json).expect("json deserialization should work");
        let bytes = bincode::serialize(&address).expect("bincode serialization should work");
        let bincode_round_trip: Address =
            bincode::deserialize(&bytes).expect("bincode deserialization should work");

        assert_eq!(json_round_trip, address);
        assert_eq!(bincode_round_trip, address);
    }

    #[test]
    fn ordering_is_lexicographic_for_deterministic_collections() {
        let lower = Address([0u8; 32]);
        let higher = Address([1u8; 32]);

        assert!(lower < higher);
    }
}
