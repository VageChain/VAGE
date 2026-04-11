use crate::node::Node;
use anyhow::{bail, Result};
use vage_block::Block;
use std::path::Path;
use tracing::{error, info, warn};

pub struct Recovery;

impl Recovery {
    /// Full recovery pipeline â€” runs all four steps in order.
    ///
    /// Call this during node startup if the storage path exists but may be
    /// stale or inconsistent (e.g. after a crash or ungraceful shutdown).
    pub async fn run(node: &mut Node, storage_path: &str) -> Result<()> {
        // Step 1: detect (and quarantine) corrupted storage.
        Self::detect_and_repair_storage(storage_path)?;

        // Step 2: restore from snapshot if one is available.
        let snapshot_path = format!("{}.snapshot", storage_path);
        if Path::new(&snapshot_path).exists() {
            Self::restore_from_snapshot(&snapshot_path, storage_path)?;
        }

        // Step 3: replay recent blocks to heal in-memory state.
        let from_height = node.storage.latest_block_height()?.saturating_sub(128);
        Self::replay_recent_blocks(node, from_height).await?;

        // Step 4: recover consensus state.
        Self::recover_consensus_state(node).await?;

        Ok(())
    }

    /// Step 1 â€” Detect corrupted storage.
    ///
    /// Attempts to open the redb database at `storage_path`.  If the open
    /// fails (e.g. file is truncated or the page checksum is invalid) the
    /// corrupt file is renamed to `<path>.corrupted` and a fresh database is
    /// created in its place so the node can continue with an empty chain.
    /// If the file opens but the integrity check reports inconsistencies the
    /// function returns an error requiring manual intervention.
    pub fn detect_and_repair_storage(storage_path: &str) -> Result<()> {
        info!("Running storage integrity check for {}...", storage_path);
        let path = Path::new(storage_path);
        if !path.exists() {
            return Ok(()); // Fresh start â€” nothing to check.
        }

        let storage = match vage_storage::StorageEngine::new(storage_path) {
            Ok(s) => s,
            Err(error) => {
                error!("Storage corruption detected: {:?}", error);
                // Quarantine the corrupt file so it can be inspected later.
                let backup_path = format!("{}.corrupted", storage_path);
                std::fs::rename(storage_path, &backup_path)?;
                warn!(
                    "Corrupt database moved to {}.  Starting with a fresh storage engine.",
                    backup_path
                );
                vage_storage::StorageEngine::new(storage_path)?
            }
        };

        if !storage.check_integrity()? {
            bail!("Storage integrity check failed.  Manual intervention required.");
        }

        info!("Storage integrity check passed.");
        Ok(())
    }

    /// Step 2 â€” Restore from snapshot.
    ///
    /// Copies a previously-taken storage snapshot over the active database
    /// path so the node starts from a known-good state.  Typically called
    /// after `detect_and_repair_storage` has quarantined a corrupt file.
    pub fn restore_from_snapshot(
        snapshot_path: impl AsRef<Path>,
        storage_path: impl AsRef<Path>,
    ) -> Result<()> {
        info!(
            "Restoring storage from snapshot {:?}...",
            snapshot_path.as_ref()
        );
        if !snapshot_path.as_ref().exists() {
            bail!("Snapshot file not found: {:?}", snapshot_path.as_ref());
        }

        vage_storage::StorageEngine::restore_from_snapshot(
            snapshot_path,
            storage_path.as_ref(),
        )?;
        info!("Storage successfully restored from snapshot.");
        Ok(())
    }

    /// Step 3 â€” Replay recent blocks.
    ///
    /// Re-executes every stored block from `from_height` to the current chain
    /// tip against the in-memory state trie.  Use after restoring from a
    /// snapshot (which may be slightly behind the tip) or after detecting that
    /// the state root is inconsistent with the latest committed block.
    ///
    /// Returns the number of blocks replayed.
    pub async fn replay_recent_blocks(node: &mut Node, from_height: u64) -> Result<u64> {
        let latest_height = node.storage.latest_block_height()?;
        info!(
            "Replaying blocks {} to {} for state healing...",
            from_height, latest_height
        );

        let mut replayed = 0u64;
        for height in from_height..=latest_height {
            let Some(header) = node.storage.get_block_header(height)? else {
                continue;
            };
            let Some(body) = node.storage.get_block_body(height)? else {
                continue;
            };

            let block = Block::new(header, body);

            // Re-execute; on mismatch execution returns an error and replay
            // aborts so the caller can fall back to a full resync.
            node.execution.execute_block(block)?;
            replayed = replayed.saturating_add(1);
        }

        // Commit the rebuilt trie after all blocks have been applied.
        let final_root = node.state.commit()?;
        info!(
            "Block replay complete: replayed={}, final_state_root=0x{}",
            replayed,
            hex::encode(final_root)
        );
        Ok(replayed)
    }

    /// Step 4 â€” Recover consensus state.
    ///
    /// Reloads the last persisted HotStuff view number and validator-set
    /// snapshot from storage so the consensus engine can resume round
    /// advancement without re-requesting a full validator-set sync from peers.
    pub async fn recover_consensus_state(node: &mut Node) -> Result<u64> {
        info!("Recovering HotStuff consensus state from persistent storage...");
        let view = node.consensus.write().await.start()?;
        info!("Consensus state recovered at view {}.", view);
        Ok(view)
    }
}
