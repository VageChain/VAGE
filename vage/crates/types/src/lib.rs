pub mod account;
pub mod address;
pub mod message;
pub mod serialization;
pub mod transaction;
pub mod validator;

pub use crate::account::Account;
pub use crate::address::Address;
pub use crate::message::{
    CanonicalMessage, NetworkMessage, CANONICAL_MESSAGE_VERSION, MAX_CANONICAL_MESSAGE_SIZE,
};
pub use crate::serialization::Canonical;
pub use crate::transaction::{Log, Receipt, Transaction};
pub use crate::validator::Validator;

/// Canonical types for the VageChain blockchain
pub type Amount = u128;
pub type Nonce = u64;
pub type Gas = u64;
pub type BlockHeight = u64;
pub type Timestamp = u64;
pub type Hash = [u8; 32];
pub type Signature = Vec<u8>;

use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Error, Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub enum TxError {
    #[error("Invalid transaction signature")]
    InvalidSignature,
    #[error("Invalid transaction nonce. Expected {0}, got {1}")]
    InvalidNonce(u64, u64),
    #[error("Insufficient balance to execute transaction")]
    InsufficientBalance,
}

#[derive(Error, Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub enum AccountError {
    #[error("Mathematical overflow during account state transition")]
    Overflow,
    #[error("Mathematical underflow during account state transition")]
    Underflow,
}

#[derive(Error, Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub enum ValidatorError {
    #[error("Insufficient stake to perform this consensus action")]
    InsufficientStake,
}
