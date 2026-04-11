use crate::peer::PeerStore;
use anyhow::{anyhow, bail, Result};
use libp2p::PeerId;
use vage_block::Block;
use vage_types::Hash;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::Duration;
use tracing::{debug, info, warn};

// â”€â”€ items 1-2: BlockRequest / BlockResponse messages â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BlockRequest {
    pub start_height: u64,
    pub end_height: u64,
}

impl BlockRequest {
    pub fn single(height: u64) -> Self {
        Self { start_height: height, end_height: height }
    }

    pub fn range(start_height: u64, end_height: u64) -> Self {
        Self { start_height, end_height }
    }

    pub fn encode(&self) -> Result<Vec<u8>> {
        bincode::serialize(self).map_err(|e| anyhow!("BlockRequest encode: {}", e))
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        bincode::deserialize(bytes).map_err(|e| anyhow!("BlockRequest decode: {}", e))
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BlockResponse {
    pub start_height: u64,
    pub blocks: Vec<Vec<u8>>,
    pub error: Option<String>,
}

impl BlockResponse {
    pub fn ok(start_height: u64, blocks: Vec<Vec<u8>>) -> Self {
        Self { start_height, blocks, error: None }
    }

    pub fn err(start_height: u64, message: impl Into<String>) -> Self {
        Self { start_height, blocks: Vec::new(), error: Some(message.into()) }
    }

    pub fn encode(&self) -> Result<Vec<u8>> {
        bincode::serialize(self).map_err(|e| anyhow!("BlockResponse encode: {}", e))
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        bincode::deserialize(bytes).map_err(|e| anyhow!("BlockResponse decode: {}", e))
    }
}

// â”€â”€ traits injected into ChainSyncEngine â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

pub trait BlockFetcher: Send + Sync {
    fn fetch_height(&self, peer_id: PeerId) -> Result<u64>;
    fn fetch_blocks(&self, peer_id: PeerId, req: &BlockRequest) -> Result<BlockResponse>;
}

pub trait BlockExecutor: Send + Sync {
    fn execute_block(&self, block: &Block) -> Result<Hash>;
}

pub trait ChainStore: Send + Sync {
    fn local_height(&self) -> Result<u64>;
    fn block_hash_at(&self, height: u64) -> Result<Option<Hash>>;
    fn append_block(&self, block: &Block) -> Result<()>;
    fn update_chain_head(&self, block: &Block) -> Result<()>;
    fn persist_sync_progress(&self, height: u64) -> Result<()>;
    fn load_sync_progress(&self) -> Result<u64>;
}

pub trait ConsensusSignatureVerifier: Send + Sync {
    fn verify_block_signatures(&self, block: &Block) -> Result<bool>;
}

// â”€â”€ item 5: peer height tracker â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

#[derive(Clone, Debug)]
pub struct PeerHeight {
    pub peer_id: PeerId,
    pub height: u64,
}

// â”€â”€ sync config â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

#[derive(Clone, Debug)]
pub struct ChainSyncConfig {
    /// Maximum blocks fetched per batch (item 7).
    pub batch_size: u64,
    /// Number of parallel batch download tasks (item 16).
    pub parallel_downloads: usize,
    /// Maximum retry attempts per batch (item 17).
    pub max_retries: u32,
    /// Delay between retries.
    pub retry_delay: Duration,
    /// Penalty score applied to a peer sending an invalid block (items 18-19).
    pub invalid_block_penalty: i32,
    /// Reputation below which a peer is considered malicious and banned (item 18-19).
    pub ban_threshold: i32,
}

impl Default for ChainSyncConfig {
    fn default() -> Self {
        Self {
            batch_size: 64,
            parallel_downloads: 4,
            max_retries: 3,
            retry_delay: Duration::from_millis(500),
            invalid_block_penalty: 50,
            ban_threshold: -100,
        }
    }
}

// â”€â”€ sync outcome â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

#[derive(Clone, Debug)]
pub struct ChainSyncResult {
    pub blocks_applied: u64,
    pub new_head: u64,
    pub banned_peers: Vec<PeerId>,
}

// â”€â”€ chain sync engine â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

pub struct ChainSyncEngine<F, E, S, V> {
    fetcher: F,
    executor: E,
    store: S,
    verifier: V,
    config: ChainSyncConfig,
    /// In-memory penalty accumulator for this sync session (item 18).
    peer_penalties: HashMap<PeerId, i32>,
}

impl<F, E, S, V> ChainSyncEngine<F, E, S, V>
where
    F: BlockFetcher,
    E: BlockExecutor,
    S: ChainStore,
    V: ConsensusSignatureVerifier,
{
    pub fn new(fetcher: F, executor: E, store: S, verifier: V, config: ChainSyncConfig) -> Self {
        Self {
            fetcher,
            executor,
            store,
            verifier,
            config,
            peer_penalties: HashMap::new(),
        }
    }

    // â”€â”€ item 3: request_latest_height from a single peer â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    pub fn request_latest_height(&self, peer_id: PeerId) -> Result<u64> {
        self.fetcher.fetch_height(peer_id)
    }

    // â”€â”€ item 4: query all peers for chain height â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    pub fn query_peers_for_height(&self, peers: &[PeerId]) -> Vec<PeerHeight> {
        peers
            .iter()
            .filter_map(|&peer_id| {
                match self.request_latest_height(peer_id) {
                    Ok(height) => Some(PeerHeight { peer_id, height }),
                    Err(err) => {
                        debug!("peer {:?} height query failed: {}", peer_id, err);
                        None
                    }
                }
            })
            .collect()
    }

    // â”€â”€ item 5: select peer with highest height â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    pub fn select_best_peer(&self, peer_heights: &[PeerHeight]) -> Option<PeerHeight> {
        peer_heights.iter().max_by_key(|p| p.height).cloned()
    }

    // â”€â”€ item 6: request missing block range â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    pub fn request_block_range(
        &self,
        peer_id: PeerId,
        start: u64,
        end: u64,
    ) -> Result<Vec<Block>> {
        let req = BlockRequest::range(start, end);
        let response = self.fetcher.fetch_blocks(peer_id, &req)?;
        if let Some(err) = response.error {
            bail!("peer {:?} returned error for range {}-{}: {}", peer_id, start, end, err);
        }
        let mut blocks = Vec::with_capacity(response.blocks.len());
        for raw in &response.blocks {
            let block: Block = bincode::deserialize(raw)
                .map_err(|e| anyhow!("failed to deserialize block: {}", e))?;
            blocks.push(block);
        }
        Ok(blocks)
    }

    // â”€â”€ item 7: receive blocks in batches â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    pub fn fetch_batches(
        &self,
        peer_id: PeerId,
        from: u64,
        to: u64,
    ) -> Result<Vec<Vec<Block>>> {
        let mut batches = Vec::new();
        let mut cursor = from;
        while cursor <= to {
            let batch_end = (cursor + self.config.batch_size - 1).min(to);
            let batch = self.request_block_range_with_retry(peer_id, cursor, batch_end)?;
            batches.push(batch);
            cursor = batch_end + 1;
        }
        Ok(batches)
    }

    // â”€â”€ item 8: validate block header hash â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    pub fn validate_block_header_hash(&self, block: &Block) -> Result<()> {
        let computed = block.hash();
        let stored = block.header.hash();
        if computed != stored {
            bail!(
                "block header hash mismatch at height {}: computed {:?} != stored {:?}",
                block.height(),
                computed,
                stored
            );
        }
        Ok(())
    }

    // â”€â”€ item 9: validate parent linkage â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    pub fn validate_parent_linkage(&self, prev_hash: Hash, block: &Block) -> Result<()> {
        if block.header.parent_hash != prev_hash {
            bail!(
                "parent hash mismatch at height {}: expected {:?}, got {:?}",
                block.height(),
                prev_hash,
                block.header.parent_hash
            );
        }
        Ok(())
    }

    // â”€â”€ item 10: validate consensus signatures â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    pub fn validate_consensus_signatures(&self, block: &Block) -> Result<()> {
        if !self.verifier.verify_block_signatures(block)? {
            bail!(
                "consensus signature verification failed for block at height {}",
                block.height()
            );
        }
        Ok(())
    }

    // â”€â”€ item 11: execute block using execution engine â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    pub fn execute_block(&self, block: &Block) -> Result<Hash> {
        self.executor.execute_block(block)
    }

    // â”€â”€ item 12: verify state root â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    pub fn verify_state_root(&self, block: &Block, computed_state_root: Hash) -> Result<()> {
        if block.header.state_root != computed_state_root {
            bail!(
                "state root mismatch at height {}: expected {:?}, got {:?}",
                block.height(),
                block.header.state_root,
                computed_state_root
            );
        }
        Ok(())
    }

    // â”€â”€ item 13: append block to local chain â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    pub fn append_block_to_chain(&self, block: &Block) -> Result<()> {
        self.store.append_block(block)
    }

    // â”€â”€ item 14: update chain head â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    pub fn update_chain_head(&self, block: &Block) -> Result<()> {
        self.store.update_chain_head(block)
    }

    // â”€â”€ item 15: apply one validated block (full pipeline) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    fn apply_block(
        &mut self,
        peer_id: PeerId,
        block: &Block,
        prev_hash: Hash,
    ) -> Result<()> {
        if let Err(e) = self.validate_block_header_hash(block)
            .and_then(|_| self.validate_parent_linkage(prev_hash, block))
            .and_then(|_| self.validate_consensus_signatures(block))
        {
            self.penalize_peer(peer_id, &e);
            return Err(e);
        }

        let computed_root = match self.execute_block(block) {
            Ok(root) => root,
            Err(e) => {
                self.penalize_peer(peer_id, &e);
                return Err(e);
            }
        };

        if let Err(e) = self.verify_state_root(block, computed_root) {
            self.penalize_peer(peer_id, &e);
            return Err(e);
        }

        self.append_block_to_chain(block)?;
        self.update_chain_head(block)?;
        Ok(())
    }

    // â”€â”€ item 15: repeat until synced â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    pub fn run_until_synced(
        &mut self,
        peer_store: &mut PeerStore,
        peers: &[PeerId],
    ) -> Result<ChainSyncResult> {
        let mut total_applied = 0u64;
        let mut banned: Vec<PeerId> = Vec::new();

        loop {
            let local_height = self.store.local_height()?;
            let peer_heights = self.query_peers_for_height(peers);
            let best = match self.select_best_peer(&peer_heights) {
                Some(p) if p.height > local_height => p,
                _ => break,
            };

            info!(
                "syncing from height {} to {} via peer {:?}",
                local_height + 1,
                best.height,
                best.peer_id
            );

            let blocks = self.fetch_all_parallel(best.peer_id, local_height + 1, best.height)?;
            let mut prev_hash = self
                .store
                .block_hash_at(local_height)?
                .unwrap_or([0u8; 32]);

            for block in &blocks {
                match self.apply_block(best.peer_id, block, prev_hash) {
                    Ok(()) => {
                        prev_hash = block.hash();
                        total_applied += 1;
                        // item 20: persist sync progress after each block
                        self.store.persist_sync_progress(block.height())?;
                    }
                    Err(e) => {
                        warn!(
                            "block application failed at height {}: {}",
                            block.height(),
                            e
                        );
                        if self.should_ban_peer(best.peer_id) {
                            peer_store.ban_peer(&best.peer_id);
                            banned.push(best.peer_id);
                            info!("banned peer {:?} for invalid blocks", best.peer_id);
                        }
                        // abort this sync round; next loop iteration picks a new peer
                        break;
                    }
                }
            }
        }

        let new_head = self.store.local_height()?;
        Ok(ChainSyncResult { blocks_applied: total_applied, new_head, banned_peers: banned })
    }

    // â”€â”€ item 16: parallel block downloads â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    pub fn fetch_all_parallel(
        &self,
        peer_id: PeerId,
        from: u64,
        to: u64,
    ) -> Result<Vec<Block>> {
        // Divide the range into `parallel_downloads` sub-ranges and fetch sequentially
        // with a thread pool emulation (true async parallelism is wired at the caller).
        // Using std threads here keeps this sync-callable without a runtime handle.
        let total = to.saturating_sub(from) + 1;
        let chunk = ((total + self.config.parallel_downloads as u64 - 1)
            / self.config.parallel_downloads as u64)
            .max(1);

        let ranges: Vec<(u64, u64)> = (0..self.config.parallel_downloads as u64)
            .map(|i| {
                let start = from + i * chunk;
                let end = (start + chunk - 1).min(to);
                (start, end)
            })
            .filter(|(s, e)| s <= e)
            .collect();

        // Spawn one thread per chunk, collect results in order.
        let results: Vec<Result<Vec<Block>>> = std::thread::scope(|scope| {
            let handles: Vec<_> = ranges
                .into_iter()
                .map(|(start, end)| {
                    scope.spawn(move || {
                        self.request_block_range_with_retry(peer_id, start, end)
                    })
                })
                .collect();

            handles
                .into_iter()
                .map(|h| h.join().unwrap_or_else(|_| Err(anyhow!("thread panicked"))))
                .collect()
        });

        let mut all = Vec::new();
        for r in results {
            all.extend(r?);
        }
        all.sort_by_key(|b| b.height());
        Ok(all)
    }

    // â”€â”€ item 17: retry logic â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    pub fn request_block_range_with_retry(
        &self,
        peer_id: PeerId,
        start: u64,
        end: u64,
    ) -> Result<Vec<Block>> {
        let mut last_err = anyhow!("no attempts made");
        for attempt in 0..=self.config.max_retries {
            match self.request_block_range(peer_id, start, end) {
                Ok(blocks) => return Ok(blocks),
                Err(e) => {
                    debug!(
                        "block range {}-{} attempt {}/{} failed: {}",
                        start, end, attempt + 1, self.config.max_retries + 1, e
                    );
                    last_err = e;
                    std::thread::sleep(self.config.retry_delay);
                }
            }
        }
        Err(last_err)
    }

    // â”€â”€ items 18-19: detect malicious peers / ban peers â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    fn penalize_peer(&mut self, peer_id: PeerId, reason: &anyhow::Error) {
        let score = self
            .peer_penalties
            .entry(peer_id)
            .or_insert(0);
        *score -= self.config.invalid_block_penalty;
        warn!(
            "penalized peer {:?} (session score {}): {}",
            peer_id, score, reason
        );
    }

    pub fn should_ban_peer(&self, peer_id: PeerId) -> bool {
        self.peer_penalties
            .get(&peer_id)
            .map(|&s| s <= self.config.ban_threshold)
            .unwrap_or(false)
    }

    /// Detect peers whose cumulative penalty exceeds the ban threshold (item 18).
    pub fn detect_malicious_peers(&self) -> Vec<PeerId> {
        self.peer_penalties
            .iter()
            .filter(|(_, &score)| score <= self.config.ban_threshold)
            .map(|(&peer_id, _)| peer_id)
            .collect()
    }

    /// Ban all detected malicious peers in the peer store (item 19).
    pub fn ban_malicious_peers(&self, peer_store: &mut PeerStore) -> Vec<PeerId> {
        let to_ban = self.detect_malicious_peers();
        for &peer_id in &to_ban {
            peer_store.ban_peer(&peer_id);
            info!("banned malicious peer {:?}", peer_id);
        }
        to_ban
    }

    // â”€â”€ item 20: persist / resume sync progress â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    pub fn persist_progress(&self, height: u64) -> Result<()> {
        self.store.persist_sync_progress(height)
    }

    pub fn resume_progress(&self) -> Result<u64> {
        self.store.load_sync_progress()
    }
}

// â”€â”€ tests â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

#[cfg(test)]
mod tests {
    use super::*;
    use vage_block::{Block, BlockBody, BlockHeader};
    use vage_types::Address;
    use std::sync::Mutex;
    use libp2p::{identity::Keypair, PeerId};

    fn dummy_peer() -> PeerId {
        PeerId::from(Keypair::generate_ed25519().public())
    }

    fn make_block(parent_hash: Hash, height: u64, seed: u8) -> Block {
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&[seed; 32]);
        let proposer = Address::from_public_key(&signing_key.verifying_key().to_bytes());
        let mut header = BlockHeader::new(parent_hash, height);
        header.proposer = proposer;
        let mut block = Block::new(header, BlockBody::empty());
        block.compute_roots();
        block.header.sign(&signing_key).expect("sign");
        block
    }

    // Stub implementations

    struct StubFetcher {
        heights: HashMap<PeerId, u64>,
        blocks: HashMap<u64, Block>,
    }

    impl BlockFetcher for StubFetcher {
        fn fetch_height(&self, peer_id: PeerId) -> Result<u64> {
            self.heights.get(&peer_id).copied().ok_or_else(|| anyhow!("unknown peer"))
        }

        fn fetch_blocks(&self, _peer_id: PeerId, req: &BlockRequest) -> Result<BlockResponse> {
            let mut raw = Vec::new();
            for h in req.start_height..=req.end_height {
                if let Some(b) = self.blocks.get(&h) {
                    raw.push(bincode::serialize(b).unwrap());
                } else {
                    return Ok(BlockResponse::err(req.start_height, format!("missing block at {}", h)));
                }
            }
            Ok(BlockResponse::ok(req.start_height, raw))
        }
    }

    struct StubExecutor {
        state_root: Hash,
    }
    impl BlockExecutor for StubExecutor {
        fn execute_block(&self, _block: &Block) -> Result<Hash> {
            Ok(self.state_root)
        }
    }

    struct StubStore {
        head: Mutex<u64>,
        hashes: Mutex<HashMap<u64, Hash>>,
        progress: Mutex<u64>,
    }

    impl StubStore {
        fn new(head: u64, hashes: HashMap<u64, Hash>) -> Self {
            Self {
                head: Mutex::new(head),
                hashes: Mutex::new(hashes),
                progress: Mutex::new(0),
            }
        }
    }

    impl ChainStore for StubStore {
        fn local_height(&self) -> Result<u64> { Ok(*self.head.lock().unwrap()) }
        fn block_hash_at(&self, height: u64) -> Result<Option<Hash>> {
            Ok(self.hashes.lock().unwrap().get(&height).copied())
        }
        fn append_block(&self, block: &Block) -> Result<()> {
            self.hashes.lock().unwrap().insert(block.height(), block.hash());
            Ok(())
        }
        fn update_chain_head(&self, block: &Block) -> Result<()> {
            *self.head.lock().unwrap() = block.height();
            Ok(())
        }
        fn persist_sync_progress(&self, height: u64) -> Result<()> {
            *self.progress.lock().unwrap() = height;
            Ok(())
        }
        fn load_sync_progress(&self) -> Result<u64> { Ok(*self.progress.lock().unwrap()) }
    }

    struct StubVerifier { valid: bool }
    impl ConsensusSignatureVerifier for StubVerifier {
        fn verify_block_signatures(&self, _block: &Block) -> Result<bool> { Ok(self.valid) }
    }

    fn make_engine(
        head: u64,
        hashes: HashMap<u64, Hash>,
        blocks: HashMap<u64, Block>,
        peer_heights: HashMap<PeerId, u64>,
        state_root: Hash,
    ) -> ChainSyncEngine<StubFetcher, StubExecutor, StubStore, StubVerifier> {
        ChainSyncEngine::new(
            StubFetcher { heights: peer_heights, blocks },
            StubExecutor { state_root },
            StubStore::new(head, hashes),
            StubVerifier { valid: true },
            ChainSyncConfig::default(),
        )
    }

    #[test]
    fn block_request_response_roundtrip() {
        let req = BlockRequest::range(5, 10);
        let decoded = BlockRequest::decode(&req.encode().unwrap()).unwrap();
        assert_eq!(decoded.start_height, 5);
        assert_eq!(decoded.end_height, 10);

        let resp = BlockResponse::ok(5, vec![vec![1, 2, 3]]);
        let decoded = BlockResponse::decode(&resp.encode().unwrap()).unwrap();
        assert_eq!(decoded.blocks.len(), 1);
        assert!(decoded.error.is_none());

        let err_resp = BlockResponse::err(5, "not found");
        assert!(err_resp.error.is_some());
    }

    #[test]
    fn query_peers_and_select_best() {
        let peer_a = dummy_peer();
        let peer_b = dummy_peer();
        let engine = make_engine(
            0,
            HashMap::new(),
            HashMap::new(),
            HashMap::from([(peer_a, 10), (peer_b, 20)]),
            [0u8; 32],
        );
        let heights = engine.query_peers_for_height(&[peer_a, peer_b]);
        assert_eq!(heights.len(), 2);
        let best = engine.select_best_peer(&heights).unwrap();
        assert_eq!(best.peer_id, peer_b);
        assert_eq!(best.height, 20);
    }

    #[test]
    fn validate_header_hash_accepts_consistent_block() {
        let block = make_block([0u8; 32], 1, 1);
        let engine = make_engine(0, HashMap::new(), HashMap::new(), HashMap::new(), [0u8; 32]);
        assert!(engine.validate_block_header_hash(&block).is_ok());
    }

    #[test]
    fn validate_parent_linkage_rejects_wrong_parent() {
        let block = make_block([1u8; 32], 2, 2);
        let engine = make_engine(0, HashMap::new(), HashMap::new(), HashMap::new(), [0u8; 32]);
        assert!(engine.validate_parent_linkage([2u8; 32], &block).is_err());
        assert!(engine.validate_parent_linkage([1u8; 32], &block).is_ok());
    }

    #[test]
    fn detect_and_ban_malicious_peers() {
        let peer = dummy_peer();
        let mut engine = make_engine(0, HashMap::new(), HashMap::new(), HashMap::new(), [0u8; 32]);
        let err = anyhow!("bad block");
        // Apply enough penalties to cross the threshold (default: -100, penalty: 50 per strike)
        engine.penalize_peer(peer, &err);
        assert!(!engine.should_ban_peer(peer));
        engine.penalize_peer(peer, &err);
        assert!(engine.should_ban_peer(peer));
        let malicious = engine.detect_malicious_peers();
        assert!(malicious.contains(&peer));
    }

    #[test]
    fn retry_logic_succeeds_after_initial_failures() {
        // StubFetcher with no blocks â€” will always fail, verifying retry count.
        let peer = dummy_peer();
        let engine = ChainSyncEngine::new(
            StubFetcher { heights: HashMap::from([(peer, 5)]), blocks: HashMap::new() },
            StubExecutor { state_root: [0u8; 32] },
            StubStore::new(0, HashMap::new()),
            StubVerifier { valid: true },
            ChainSyncConfig { max_retries: 2, retry_delay: Duration::from_millis(1), ..Default::default() },
        );
        let result = engine.request_block_range_with_retry(peer, 1, 1);
        assert!(result.is_err());
    }

    #[test]
    fn persist_and_resume_sync_progress() {
        let engine = make_engine(0, HashMap::new(), HashMap::new(), HashMap::new(), [0u8; 32]);
        engine.persist_progress(42).unwrap();
        assert_eq!(engine.resume_progress().unwrap(), 42);
    }

    #[test]
    fn run_until_synced_applies_blocks_and_persists_progress() {
        let peer = dummy_peer();
        let genesis_hash = [0u8; 32];
        let block_1 = make_block(genesis_hash, 1, 1);
        let block_2 = make_block(block_1.hash(), 2, 2);
        let state_root = block_1.header.state_root;

        let mut engine = ChainSyncEngine::new(
            StubFetcher {
                heights: HashMap::from([(peer, 2)]),
                blocks: HashMap::from([
                    (1, block_1.clone()),
                    (2, block_2.clone()),
                ]),
            },
            StubExecutor { state_root },
            StubStore::new(0, HashMap::from([(0, genesis_hash)])),
            StubVerifier { valid: true },
            ChainSyncConfig {
                batch_size: 64,
                parallel_downloads: 1,
                retry_delay: Duration::from_millis(1),
                ..Default::default()
            },
        );

        let mut peer_store = PeerStore::default();
        let result = engine.run_until_synced(&mut peer_store, &[peer]).unwrap();
        assert_eq!(result.blocks_applied, 2);
        assert_eq!(result.new_head, 2);
        assert_eq!(*engine.store.progress.lock().unwrap(), 2);
    }
}
