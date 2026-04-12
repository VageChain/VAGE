//! Snapshot-based state-sync engine.
//!
//! # Protocol
//!
//! 1. **Server side** (`StateSyncEngine::create_snapshot`): compresses all
//!    `account:*` entries from the storage engine into a length-prefixed,
//!    zstd-compressed binary chunk and stores it alongside the canonical
//!    `state_root` and `block_height` at which it was taken.
//!
//! 2. **Client side** (`StateSyncEngine::apply_snapshot`): decompresses the
//!    chunk, replays every key/value pair into the local storage backend, and
//!    verifies the resulting state root matches the one advertised in the
//!    snapshot manifest.
//!
//! Snapshots are gossiped on `TOPIC_STATE_SYNC` (see `networking::gossip`).

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tracing::info;
use vage_state::StateDB;
use vage_storage::StorageEngine;

/// Wire-format manifest that accompanies a compressed state chunk.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SnapshotManifest {
    /// Block height at which the snapshot was taken.
    pub height: u64,
    /// State root (Verkle / SMT root hash) at `height`.
    pub state_root: [u8; 32],
    /// Number of key/value pairs in the snapshot.
    pub entry_count: u64,
    /// SHA-256 checksum of the raw (uncompressed) payload.
    pub payload_checksum: [u8; 32],
}

/// A snapshot that can be transmitted over the gossip layer.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StateSnapshot {
    pub manifest: SnapshotManifest,
    /// zstd-compressed, bincode-encoded `Vec<(Vec<u8>, Vec<u8>)>` of key/value pairs.
    pub compressed_payload: Vec<u8>,
}

/// Prefix used for all account state entries in the storage engine.
const ACCOUNT_STATE_PREFIX: &[u8] = b"account:";

pub struct StateSyncEngine {
    storage: Arc<StorageEngine>,
    state: Arc<StateDB>,
}

impl StateSyncEngine {
    pub fn new(storage: Arc<StorageEngine>, state: Arc<StateDB>) -> Self {
        Self { storage, state }
    }

    /// Create a compressed snapshot of all account state at the current head.
    /// The snapshot includes every `account:*` key from the storage engine.
    pub fn create_snapshot(&self, height: u64) -> Result<StateSnapshot> {
        info!("Creating state snapshot at height {}", height);

        // 1. Collect all account state entries.
        let entries: Vec<(Vec<u8>, Vec<u8>)> = self
            .storage
            .state_prefix_scan(ACCOUNT_STATE_PREFIX.to_vec())
            .context("failed to scan account state for snapshot")?;

        let entry_count = entries.len() as u64;
        info!("Snapshot contains {} account state entries", entry_count);

        // 2. Serialize and compute checksum of the raw payload.
        let raw_payload =
            bincode::serialize(&entries).context("failed to serialize snapshot entries")?;

        let payload_checksum = checksum(&raw_payload);

        // 3. Compress with zstd (level 3 â€” fast, good ratio).
        let compressed_payload =
            zstd::encode_all(raw_payload.as_slice(), 3).context("zstd compression failed")?;

        // 4. Fetch the current state root.
        let state_root = self
            .storage
            .state_get_bytes(b"metadata:state_root")
            .context("failed to read state root from storage")?
            .and_then(|b| b.try_into().ok())
            .unwrap_or([0u8; 32]);

        Ok(StateSnapshot {
            manifest: SnapshotManifest {
                height,
                state_root,
                entry_count,
                payload_checksum,
            },
            compressed_payload,
        })
    }

    /// Apply a received snapshot to the local node's storage and verify the
    /// resulting state root matches the manifest.
    pub fn apply_snapshot(&self, snapshot: StateSnapshot) -> Result<()> {
        info!(
            "Applying state snapshot: height={}, entries={}",
            snapshot.manifest.height, snapshot.manifest.entry_count
        );

        // 1. Decompress.
        let raw_payload = zstd::decode_all(snapshot.compressed_payload.as_slice())
            .context("zstd decompression failed")?;

        // 2. Verify payload checksum.
        let actual_checksum = checksum(&raw_payload);
        if actual_checksum != snapshot.manifest.payload_checksum {
            bail!(
                "snapshot payload checksum mismatch: expected {:?}, got {:?}",
                snapshot.manifest.payload_checksum,
                actual_checksum
            );
        }

        // 3. Deserialize entries.
        let entries: Vec<(Vec<u8>, Vec<u8>)> =
            bincode::deserialize(&raw_payload).context("failed to deserialize snapshot entries")?;

        if entries.len() as u64 != snapshot.manifest.entry_count {
            bail!(
                "snapshot entry count mismatch: expected {}, got {}",
                snapshot.manifest.entry_count,
                entries.len()
            );
        }

        // 4. Replay all entries into local storage.
        for (key, value) in entries {
            self.storage
                .state_put(key, value)
                .context("failed to write snapshot entry to storage")?;
        }

        info!(
            "State snapshot applied: {} entries written",
            snapshot.manifest.entry_count
        );

        // 5. Verify state root after replay.
        let stored_root: Option<[u8; 32]> = self
            .storage
            .state_get_bytes(b"metadata:state_root")
            .ok()
            .flatten()
            .and_then(|b| b.try_into().ok());

        // Commit and recompute.
        let computed_root = self
            .state
            .commit()
            .context("state commit after snapshot failed")?;

        if computed_root != snapshot.manifest.state_root {
            bail!(
                "state root mismatch after snapshot replay: expected 0x{}, got 0x{}",
                hex::encode(snapshot.manifest.state_root),
                hex::encode(computed_root)
            );
        }

        // Persist the verified state root.
        self.storage
            .state_put(b"metadata:state_root".to_vec(), computed_root.to_vec())?;

        // Suppress unused-variable if stored_root isn't used further.
        let _ = stored_root;

        info!(
            "State root verified: 0x{}",
            hex::encode(snapshot.manifest.state_root)
        );

        Ok(())
    }

    /// Encode a `StateSnapshot` for transmission via gossip.
    pub fn encode_for_gossip(snapshot: &StateSnapshot) -> Result<Vec<u8>> {
        bincode::serialize(snapshot).context("failed to encode state snapshot for gossip")
    }

    /// Decode a `StateSnapshot` received from gossip.
    pub fn decode_from_gossip(payload: &[u8]) -> Result<StateSnapshot> {
        bincode::deserialize(payload).context("failed to decode state snapshot from gossip")
    }
}

/// SHA-256 checksum helper.
fn checksum(data: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(data);
    h.finalize().into()
}
