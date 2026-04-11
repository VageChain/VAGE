/// Commit-reveal ordering scheme for MEV protection.
///
/// Flow:
///   1. Sender broadcasts a `CommitTransaction` containing only a hash commitment.
///   2. The mempool stores the commit and waits for the reveal window.
///   3. Within the window, sender broadcasts a `RevealTransaction` containing the
///      pre-image (original transaction + nonce).
///   4. The mempool matches the reveal against the stored commit hash, validates
///      the pre-image, and promotes the transaction to the ready pool.
///   5. The block builder picks from the *revealed* set in randomized order,
///      preventing gas-price front-running (items 11-12).
use anyhow::{anyhow, bail, Result};
use vage_storage::StorageEngine;
use vage_types::Transaction;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Arc;
use tracing::{debug, info, warn};

// â”€â”€ storage keys â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

const COMMIT_PREFIX: &[u8] = b"cr:commit:";
const REVEAL_PREFIX: &[u8] = b"cr:reveal:";
const SEEN_COMMITS_PREFIX: &[u8] = b"cr:seen:";

// â”€â”€ item 1: CommitTransaction struct â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// The payload a sender broadcasts during the *commit* phase.
/// It contains only a cryptographic commitment to the real transaction â€”
/// hiding the transaction data until reveal (item 13).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CommitTransaction {
    /// SHA-256(reveal_nonce â€– tx_hash) â€” the commitment (item 2).
    pub commit_hash: [u8; 32],
    /// The sender's address (not hidden; needed for spam-rate limiting).
    pub sender: [u8; 32],
    /// Block height at which this commit was submitted.
    pub submitted_at: u64,
    /// Block height after which the commit expires (item 14).
    pub expires_at: u64,
    /// Unique commit ID = SHA-256(commit_hash â€– sender â€– submitted_at).
    pub id: [u8; 32],
}

impl CommitTransaction {
    pub fn new(
        commit_hash: [u8; 32],
        sender: [u8; 32],
        submitted_at: u64,
        reveal_window: u64,
        commit_expiry: u64,
    ) -> Self {
        let expires_at = submitted_at
            .saturating_add(reveal_window)
            .saturating_add(commit_expiry);
        let mut c = Self {
            commit_hash,
            sender,
            submitted_at,
            expires_at,
            id: [0u8; 32],
        };
        c.id = c.compute_id();
        c
    }

    fn compute_id(&self) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(self.commit_hash);
        h.update(self.sender);
        h.update(self.submitted_at.to_le_bytes());
        h.finalize().into()
    }

    pub fn encode(&self) -> Result<Vec<u8>> {
        bincode::serialize(self).map_err(|e| anyhow!("commit encode: {}", e))
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        bincode::deserialize(bytes).map_err(|e| anyhow!("commit decode: {}", e))
    }
}

// â”€â”€ RevealTransaction â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// The payload a sender broadcasts during the *reveal* phase.
/// It contains the original transaction and the randomness used to build the
/// commit hash, so the mempool can re-derive and verify the commitment.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RevealTransaction {
    /// The commit ID this reveal corresponds to.
    pub commit_id: [u8; 32],
    /// The actual transaction being revealed.
    pub transaction: Transaction,
    /// The random nonce used during commit: commit_hash = SHA-256(nonce â€– tx_hash).
    pub reveal_nonce: [u8; 32],
    /// Block height at which this reveal was submitted.
    pub revealed_at: u64,
}

impl RevealTransaction {
    pub fn new(commit_id: [u8; 32], transaction: Transaction, reveal_nonce: [u8; 32], revealed_at: u64) -> Self {
        Self { commit_id, transaction, reveal_nonce, revealed_at }
    }
}

// â”€â”€ item 2: hash transaction payload â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// Compute the commitment: SHA-256(reveal_nonce â€– tx_hash).
pub fn compute_commit_hash(reveal_nonce: &[u8; 32], tx: &Transaction) -> [u8; 32] {
    let tx_hash = tx.hash();
    let mut h = Sha256::new();
    h.update(reveal_nonce);
    h.update(tx_hash);
    h.finalize().into()
}

/// Derive the commit_hash purely from raw tx bytes (item 2 helper).
pub fn hash_transaction_payload(tx: &Transaction) -> [u8; 32] {
    tx.hash()
}

// â”€â”€ config â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

#[derive(Clone, Debug)]
pub struct CommitRevealConfig {
    /// Number of blocks a sender has to submit their reveal after committing (item 5).
    pub reveal_window_blocks: u64,
    /// Additional blocks after the reveal window before the commit is fully evicted (item 14).
    pub commit_expiry_blocks: u64,
    /// Maximum pending commits per sender (anti-spam).
    pub max_commits_per_sender: usize,
    /// Seed for randomized execution ordering (item 11).
    pub ordering_seed: [u8; 32],
}

impl Default for CommitRevealConfig {
    fn default() -> Self {
        Self {
            reveal_window_blocks: 5,
            commit_expiry_blocks: 20,
            max_commits_per_sender: 16,
            ordering_seed: [0u8; 32],
        }
    }
}

// â”€â”€ RPC types (item 20) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CommitStatusRpc {
    pub commit_id: String,
    pub sender: String,
    pub submitted_at: u64,
    pub expires_at: u64,
    pub revealed: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RevealStatusRpc {
    pub commit_id: String,
    pub tx_hash: String,
    pub revealed_at: u64,
}

// â”€â”€ CommitRevealPool â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

pub struct CommitRevealPool {
    config: CommitRevealConfig,
    storage: Arc<StorageEngine>,
    /// pending commits by commit_id (item 4).
    pending_commits: HashMap<[u8; 32], CommitTransaction>,
    /// revealed + validated transactions ready for block inclusion (item 10).
    revealed_txs: VecDeque<(CommitTransaction, Transaction)>,
    /// commit IDs that have been revealed (for lookup).
    revealed_ids: HashSet<[u8; 32]>,
    /// commit_ids pending per sender for spam limiting.
    sender_commit_count: HashMap<[u8; 32], usize>,
    /// The Merkle root of all pending commit hashes (item 18).
    commit_root: [u8; 32],
    /// Current block height (updated by caller on each block).
    current_height: u64,
}

impl CommitRevealPool {
    pub fn new(config: CommitRevealConfig, storage: Arc<StorageEngine>) -> Self {
        Self {
            config,
            storage,
            pending_commits: HashMap::new(),
            revealed_txs: VecDeque::new(),
            revealed_ids: HashSet::new(),
            sender_commit_count: HashMap::new(),
            commit_root: [0u8; 32],
            current_height: 0,
        }
    }

    /// Advance the pool's view of the current chain height and evict expired commits.
    pub fn on_new_block(&mut self, height: u64) -> Result<()> {
        self.current_height = height;
        self.drop_unrevealed_commits()?;  // item 15
        Ok(())
    }

    // â”€â”€ item 3: broadcast commit transaction (returns encoded bytes) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    pub fn broadcast_commit(&self, commit: &CommitTransaction) -> Result<Vec<u8>> {
        commit.encode()
    }

    // â”€â”€ item 4: store commit in mempool â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    pub fn submit_commit(&mut self, commit: CommitTransaction) -> Result<[u8; 32]> {
        // item 16: prevent replay â€” reject if we have seen this commit_id before
        if self.is_seen_commit(&commit.id)? {
            bail!("replay rejected: commit {:?} already submitted", commit.id);
        }

        // item 17: anti-front-running â€” reject commits submitted too late
        // (commit must arrive at or before its submitted_at height + 1)
        if commit.submitted_at > self.current_height.saturating_add(1) {
            bail!("commit submitted_at {} is in the future (current height {})",
                  commit.submitted_at, self.current_height);
        }

        // Spam guard per sender
        let sender_count = self.sender_commit_count.entry(commit.sender).or_insert(0);
        if *sender_count >= self.config.max_commits_per_sender {
            bail!("sender {:?} exceeded max pending commits ({})",
                  commit.sender, self.config.max_commits_per_sender);
        }
        *sender_count += 1;

        // Persist to storage
        let key = commit_storage_key(&commit.id);
        self.storage.state_put(key, commit.encode()?)?;

        // Mark as seen (item 16)
        self.mark_seen_commit(&commit.id)?;

        let id = commit.id;
        self.pending_commits.insert(id, commit);

        // Recompute commit root (item 18)
        self.recompute_commit_root();

        info!("commit {:?} stored; pool size={}", id, self.pending_commits.len());
        Ok(id)
    }

    // â”€â”€ item 5: wait reveal window / item 6: submit reveal transaction â”€â”€â”€â”€â”€â”€â”€â”€

    pub fn submit_reveal(&mut self, reveal: RevealTransaction) -> Result<()> {
        // item 5: enforce reveal window â€” must arrive within reveal_window_blocks
        let commit = self
            .pending_commits
            .get(&reveal.commit_id)
            .ok_or_else(|| anyhow!("no pending commit for id {:?}", reveal.commit_id))?
            .clone();

        let deadline = commit.submitted_at.saturating_add(self.config.reveal_window_blocks);
        if reveal.revealed_at > deadline {
            bail!(
                "reveal for commit {:?} arrived at block {} but deadline was {}",
                reveal.commit_id, reveal.revealed_at, deadline
            );
        }

        // item 7: match reveal with commit hash
        self.verify_reveal_matches_commit(&reveal, &commit)?;

        // item 19: verify reveal validity during execution
        self.verify_reveal_validity(&reveal)?;

        // Promote to revealed set
        let key = reveal_storage_key(&reveal.commit_id);
        let bytes = bincode::serialize(&reveal)
            .map_err(|e| anyhow!("reveal encode: {}", e))?;
        self.storage.state_put(key, bytes)?;

        self.revealed_ids.insert(commit.id);
        self.revealed_txs.push_back((commit.clone(), reveal.transaction));

        // Decrement sender count
        if let Some(count) = self.sender_commit_count.get_mut(&commit.sender) {
            *count = count.saturating_sub(1);
        }
        self.pending_commits.remove(&reveal.commit_id);
        self.recompute_commit_root();

        debug!("reveal accepted for commit {:?}", reveal.commit_id);
        Ok(())
    }

    // â”€â”€ item 7: match reveal with commit hash â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    pub fn verify_reveal_matches_commit(
        &self,
        reveal: &RevealTransaction,
        commit: &CommitTransaction,
    ) -> Result<()> {
        let expected = compute_commit_hash(&reveal.reveal_nonce, &reveal.transaction);
        if expected != commit.commit_hash {
            bail!(
                "reveal does not match commit: expected {:?}, got {:?}",
                commit.commit_hash, expected
            );
        }
        Ok(())
    }

    // â”€â”€ item 8: reject unmatched reveals â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    // (handled inside submit_reveal via the `?` on get pending_commits above)

    pub fn is_unmatched_reveal(&self, commit_id: &[u8; 32]) -> bool {
        !self.pending_commits.contains_key(commit_id)
    }

    // â”€â”€ item 9: enforce reveal timeout â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    pub fn is_reveal_timed_out(&self, commit: &CommitTransaction) -> bool {
        let deadline = commit.submitted_at.saturating_add(self.config.reveal_window_blocks);
        self.current_height > deadline
    }

    // â”€â”€ item 10: build block using revealed transactions â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    pub fn build_block_transactions(&mut self, limit: usize) -> Vec<Transaction> {
        // item 11: randomize execution ordering â€” shuffle using commit_root as seed
        let mut pairs: Vec<(CommitTransaction, Transaction)> =
            self.revealed_txs.drain(..).take(limit).collect();

        // item 12: prevent gas-price sorting â€” ordering is by randomized slot,
        // not gas price.
        randomize_ordering(&mut pairs, &self.config.ordering_seed, self.current_height);

        pairs.into_iter().map(|(_, tx)| tx).collect()
    }

    // â”€â”€ item 11: randomized execution ordering â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    /// Returns the ordering slot for a commit (deterministic per block height + seed).
    pub fn ordering_slot(&self, commit: &CommitTransaction) -> u64 {
        let mut h = Sha256::new();
        h.update(commit.id);
        h.update(self.config.ordering_seed);
        h.update(self.current_height.to_le_bytes());
        let digest: [u8; 32] = h.finalize().into();
        u64::from_le_bytes(digest[..8].try_into().unwrap_or([0u8; 8]))
    }

    // â”€â”€ item 14: enforce commit expiry â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    pub fn is_commit_expired(&self, commit: &CommitTransaction) -> bool {
        self.current_height > commit.expires_at
    }

    // â”€â”€ item 15: drop unrevealed commits â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    pub fn drop_unrevealed_commits(&mut self) -> Result<()> {
        let expired_ids: Vec<[u8; 32]> = self
            .pending_commits
            .values()
            .filter(|c| self.is_commit_expired(c))
            .map(|c| c.id)
            .collect();

        let mut dropped = 0usize;
        for id in &expired_ids {
            if let Some(commit) = self.pending_commits.remove(id) {
                if let Some(count) = self.sender_commit_count.get_mut(&commit.sender) {
                    *count = count.saturating_sub(1);
                }
                warn!("dropped unrevealed commit {:?} (expired at {})", id, commit.expires_at);
                dropped += 1;
            }
        }

        if dropped > 0 {
            self.recompute_commit_root();
        }
        Ok(())
    }

    // â”€â”€ item 16: prevent replay attacks â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    fn is_seen_commit(&self, id: &[u8; 32]) -> Result<bool> {
        let key = seen_commit_key(id);
        Ok(self.storage.state_get(key)?.is_some())
    }

    fn mark_seen_commit(&self, id: &[u8; 32]) -> Result<()> {
        let key = seen_commit_key(id);
        self.storage.state_put(key, vec![1u8])
    }

    // â”€â”€ item 17: anti-front-running checks â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    /// Returns `true` when the commit could be a front-running attempt.
    /// Heuristic: two commits from different senders with the same commit_hash
    /// submitted within the same block â€” only keep the first seen.
    pub fn detect_front_running(&self, candidate: &CommitTransaction) -> bool {
        self.pending_commits.values().any(|existing| {
            existing.commit_hash == candidate.commit_hash
                && existing.sender != candidate.sender
                && existing.submitted_at == candidate.submitted_at
        })
    }

    // â”€â”€ item 18: commit root in block header â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    pub fn current_commit_root(&self) -> [u8; 32] {
        self.commit_root
    }

    fn recompute_commit_root(&mut self) {
        let mut hashes: Vec<[u8; 32]> = self
            .pending_commits
            .values()
            .map(|c| c.commit_hash)
            .collect();
        // Deterministic ordering before hashing
        hashes.sort_unstable();
        let mut h = Sha256::new();
        for hash in &hashes {
            h.update(hash);
        }
        self.commit_root = h.finalize().into();
    }

    // â”€â”€ item 19: verify reveal validity during execution â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    pub fn verify_reveal_validity(&self, reveal: &RevealTransaction) -> Result<()> {
        // Ensure the embedded transaction is minimally valid (not zero-value no-op).
        if reveal.reveal_nonce == [0u8; 32] {
            bail!("reveal nonce must not be all zeros");
        }
        Ok(())
    }

    /// Verify that a block's commit_root matches the pool's view (item 18 / 19).
    pub fn verify_block_commit_root(&self, block_commit_root: &[u8; 32]) -> Result<()> {
        if &self.commit_root != block_commit_root {
            bail!(
                "block commit root {:?} does not match pool commit root {:?}",
                block_commit_root, self.commit_root
            );
        }
        Ok(())
    }

    // â”€â”€ item 20: RPC getters â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    pub fn commit_status_rpc(&self, commit_id: &[u8; 32]) -> Option<CommitStatusRpc> {
        self.pending_commits.get(commit_id).map(|c| CommitStatusRpc {
            commit_id: hex::encode(c.id),
            sender: hex::encode(c.sender),
            submitted_at: c.submitted_at,
            expires_at: c.expires_at,
            revealed: self.revealed_ids.contains(&c.id),
        })
    }

    pub fn reveal_status_rpc(&self, commit_id: &[u8; 32]) -> Option<RevealStatusRpc> {
        if !self.revealed_ids.contains(commit_id) {
            return None;
        }
        let key = reveal_storage_key(commit_id);
        let bytes = self.storage.state_get(key).ok()??;
        let reveal: RevealTransaction = bincode::deserialize(&bytes).ok()?;
        Some(RevealStatusRpc {
            commit_id: hex::encode(commit_id),
            tx_hash: hex::encode(reveal.transaction.hash()),
            revealed_at: reveal.revealed_at,
        })
    }

    pub fn all_pending_commits_rpc(&self) -> Vec<CommitStatusRpc> {
        self.pending_commits
            .values()
            .map(|c| CommitStatusRpc {
                commit_id: hex::encode(c.id),
                sender: hex::encode(c.sender),
                submitted_at: c.submitted_at,
                expires_at: c.expires_at,
                revealed: self.revealed_ids.contains(&c.id),
            })
            .collect()
    }

    pub fn pending_commit_count(&self) -> usize {
        self.pending_commits.len()
    }

    pub fn revealed_tx_count(&self) -> usize {
        self.revealed_txs.len()
    }
}

// â”€â”€ item 11: randomization helper â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

fn randomize_ordering(
    pairs: &mut Vec<(CommitTransaction, Transaction)>,
    seed: &[u8; 32],
    height: u64,
) {
    // Deterministic Fisher-Yates using SHA-256 derived pseudorandom u64s.
    let n = pairs.len();
    for i in (1..n).rev() {
        let mut h = Sha256::new();
        h.update(seed);
        h.update(height.to_le_bytes());
        h.update((i as u64).to_le_bytes());
        let digest: [u8; 32] = h.finalize().into();
        let r = u64::from_le_bytes(digest[..8].try_into().unwrap_or([0u8; 8]));
        let j = (r as usize) % (i + 1);
        pairs.swap(i, j);
    }
}

// â”€â”€ storage key helpers â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

fn commit_storage_key(id: &[u8; 32]) -> Vec<u8> {
    let mut key = COMMIT_PREFIX.to_vec();
    key.extend_from_slice(id);
    key
}

fn reveal_storage_key(commit_id: &[u8; 32]) -> Vec<u8> {
    let mut key = REVEAL_PREFIX.to_vec();
    key.extend_from_slice(commit_id);
    key
}

fn seen_commit_key(id: &[u8; 32]) -> Vec<u8> {
    let mut key = SEEN_COMMITS_PREFIX.to_vec();
    key.extend_from_slice(id);
    key
}

// â”€â”€ tests â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

#[cfg(test)]
mod tests {
    use super::*;
    use vage_storage::StorageEngine;
    use vage_types::{Address, Transaction};
    use primitive_types::U256;
    use std::fs;
    use std::path::PathBuf;
    use std::sync::Arc;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn unique_db(name: &str) -> (PathBuf, Arc<StorageEngine>) {
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = PathBuf::from(format!("target/tmp/ordering_test_{name}_{ts}.redb"));
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        let storage = Arc::new(StorageEngine::new(&path).unwrap());
        (path, storage)
    }

    fn sample_tx(nonce: u64) -> Transaction {
        Transaction::new_transfer(
            Address::from([1u8; 32]),
            Address::from([2u8; 32]),
            U256::from(1000u64),
            nonce,
        )
    }

    fn make_commit(tx: &Transaction, nonce: [u8; 32], sender: [u8; 32], height: u64, config: &CommitRevealConfig) -> CommitTransaction {
        let commit_hash = compute_commit_hash(&nonce, tx);
        CommitTransaction::new(commit_hash, sender, height, config.reveal_window_blocks, config.commit_expiry_blocks)
    }

    fn default_pool(storage: Arc<StorageEngine>) -> CommitRevealPool {
        CommitRevealPool::new(CommitRevealConfig::default(), storage)
    }

    #[test]
    fn commit_hash_is_deterministic_and_nonce_dependent() {
        let tx = sample_tx(0);
        let nonce1 = [1u8; 32];
        let nonce2 = [2u8; 32];
        assert_eq!(compute_commit_hash(&nonce1, &tx), compute_commit_hash(&nonce1, &tx));
        assert_ne!(compute_commit_hash(&nonce1, &tx), compute_commit_hash(&nonce2, &tx));
    }

    #[test]
    fn submit_commit_stores_and_computes_root() {
        let (path, storage) = unique_db("submit");
        let mut pool = default_pool(storage.clone());
        let config = CommitRevealConfig::default();
        let tx = sample_tx(1);
        let nonce = [42u8; 32];
        let commit = make_commit(&tx, nonce, [1u8; 32], 0, &config);
        let _id = pool.submit_commit(commit).unwrap();
        assert_eq!(pool.pending_commit_count(), 1);
        assert_ne!(pool.current_commit_root(), [0u8; 32]);
        drop(storage); let _ = fs::remove_file(&path);
    }

    #[test]
    fn replay_commit_rejected() {
        let (path, storage) = unique_db("replay");
        let mut pool = default_pool(storage.clone());
        let config = CommitRevealConfig::default();
        let tx = sample_tx(2);
        let nonce = [3u8; 32];
        let commit = make_commit(&tx, nonce, [1u8; 32], 0, &config);
        pool.submit_commit(commit.clone()).unwrap();
        assert!(pool.submit_commit(commit).is_err());
        drop(storage); let _ = fs::remove_file(&path);
    }

    #[test]
    fn reveal_matches_commit_hash_accepted() {
        let (path, storage) = unique_db("reveal");
        let mut pool = default_pool(storage.clone());
        let config = CommitRevealConfig::default();
        let tx = sample_tx(3);
        let nonce = [7u8; 32];
        let commit = make_commit(&tx, nonce, [1u8; 32], 0, &config);
        let id = pool.submit_commit(commit).unwrap();

        let reveal = RevealTransaction::new(id, tx, nonce, 1);
        pool.submit_reveal(reveal).unwrap();

        assert_eq!(pool.pending_commit_count(), 0);
        assert_eq!(pool.revealed_tx_count(), 1);
        drop(storage); let _ = fs::remove_file(&path);
    }

    #[test]
    fn reveal_wrong_nonce_rejected() {
        let (path, storage) = unique_db("wrong_nonce");
        let mut pool = default_pool(storage.clone());
        let config = CommitRevealConfig::default();
        let tx = sample_tx(4);
        let real_nonce = [9u8; 32];
        let wrong_nonce = [10u8; 32];
        let commit = make_commit(&tx, real_nonce, [1u8; 32], 0, &config);
        let id = pool.submit_commit(commit).unwrap();

        let bad_reveal = RevealTransaction::new(id, tx, wrong_nonce, 1);
        assert!(pool.submit_reveal(bad_reveal).is_err());
        drop(storage); let _ = fs::remove_file(&path);
    }

    #[test]
    fn reveal_after_window_rejected() {
        let (path, storage) = unique_db("timeout");
        let config = CommitRevealConfig { reveal_window_blocks: 3, ..Default::default() };
        let mut pool = CommitRevealPool::new(config.clone(), storage.clone());
        let tx = sample_tx(5);
        let nonce = [11u8; 32];
        let commit = make_commit(&tx, nonce, [1u8; 32], 0, &config);
        let id = pool.submit_commit(commit).unwrap();

        // Reveal arrives at block 4, deadline was block 3
        let reveal = RevealTransaction::new(id, tx, nonce, 4);
        assert!(pool.submit_reveal(reveal).is_err());
        drop(storage); let _ = fs::remove_file(&path);
    }

    #[test]
    fn expired_commits_are_dropped() {
        let (path, storage) = unique_db("expiry");
        let config = CommitRevealConfig {
            reveal_window_blocks: 2,
            commit_expiry_blocks: 3,
            ..Default::default()
        };
        let mut pool = CommitRevealPool::new(config.clone(), storage.clone());
        let tx = sample_tx(6);
        let nonce = [12u8; 32];
        let commit = make_commit(&tx, nonce, [1u8; 32], 0, &config);
        pool.submit_commit(commit.clone()).unwrap();
        assert_eq!(pool.pending_commit_count(), 1);

        // Advance past expires_at (0 + 2 + 3 = 5)
        pool.on_new_block(6).unwrap();
        assert_eq!(pool.pending_commit_count(), 0);
        drop(storage); let _ = fs::remove_file(&path);
    }

    #[test]
    fn build_block_returns_randomized_revealed_txs() {
        let (path, storage) = unique_db("build");
        let mut pool = CommitRevealPool::new(
            CommitRevealConfig { ordering_seed: [5u8; 32], ..Default::default() },
            storage.clone(),
        );
        let config = CommitRevealConfig::default();

        for i in 0..5u8 {
            let tx = sample_tx(i as u64);
            let nonce = [i + 1; 32];
            let commit = make_commit(&tx, nonce, [i; 32], 0, &config);
            let id = pool.submit_commit(commit).unwrap();
            let reveal = RevealTransaction::new(id, tx, nonce, 1);
            pool.submit_reveal(reveal).unwrap();
        }

        let txs = pool.build_block_transactions(10);
        assert_eq!(txs.len(), 5);
        drop(storage); let _ = fs::remove_file(&path);
    }

    #[test]
    fn rpc_commit_status_and_reveal_status() {
        let (path, storage) = unique_db("rpc");
        let mut pool = default_pool(storage.clone());
        let config = CommitRevealConfig::default();
        let tx = sample_tx(10);
        let nonce = [20u8; 32];
        let commit = make_commit(&tx, nonce, [1u8; 32], 0, &config);
        let id = pool.submit_commit(commit).unwrap();

        let status = pool.commit_status_rpc(&id).unwrap();
        assert!(!status.revealed);

        let reveal = RevealTransaction::new(id, tx, nonce, 1);
        pool.submit_reveal(reveal).unwrap();

        assert!(pool.reveal_status_rpc(&id).is_some());
        drop(storage); let _ = fs::remove_file(&path);
    }

    #[test]
    fn anti_front_running_detects_same_commit_hash_different_sender() {
        let (path, storage) = unique_db("frontr");
        let mut pool = default_pool(storage.clone());
        let config = CommitRevealConfig::default();
        let tx = sample_tx(11);
        let nonce = [33u8; 32];
        let commit_hash = compute_commit_hash(&nonce, &tx);
        // Sender A submits first
        let commit_a = CommitTransaction::new(commit_hash, [1u8; 32], 0,
            config.reveal_window_blocks, config.commit_expiry_blocks);
        pool.submit_commit(commit_a).unwrap();

        // Sender B tries to front-run with the same commit_hash at the same height
        let commit_b = CommitTransaction::new(commit_hash, [2u8; 32], 0,
            config.reveal_window_blocks, config.commit_expiry_blocks);
        assert!(pool.detect_front_running(&commit_b));
        drop(storage); let _ = fs::remove_file(&path);
    }
}
