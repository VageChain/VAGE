pub mod block;
pub mod body;
pub mod header;

/// Canonical block limits for the VageChain network
pub const MAX_BLOCK_SIZE_BYTES: usize = 2 * 1024 * 1024; // 2MB
pub const MAX_TRANSACTIONS_PER_BLOCK: usize = 10_000;

pub use crate::block::{Block, BlockBuilder};
pub use crate::body::BlockBody;
pub use crate::header::BlockHeader;
