use crate::ordering::{CommitRevealConfig, CommitRevealPool, CommitTransaction, RevealTransaction};
use crate::pool::TransactionPool;
use crate::validation::{TransactionValidator, TxValidationConfig, MAX_TX_SIZE};
use anyhow::Result;
use parking_lot::{Mutex, RwLock};
use primitive_types::U256;
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::info;
use vage_block::Block;
use vage_execution::TransactionSource;
use vage_networking::{GossipMessage, TransactionPoolSink};
use vage_state::StateDb;
use vage_storage::StorageEngine;
use vage_types::{Hash, Transaction};

pub const MAX_MEMPOOL_SIZE: usize = 10_000;

#[derive(Clone, Debug)]
pub struct MempoolConfig {
    pub max_pending_transactions: usize,
    /// How long (seconds) a transaction may stay in the pool before expiry.
    pub transaction_ttl_secs: u64,
    /// Minimum interval (seconds) between periodic cleanup sweeps.
    pub cleanup_interval_secs: u64,
    /// Maximum pending transactions per sender address (spam guard).
    pub max_transactions_per_account: usize,
    /// Maximum transactions accepted from a single peer per rate-limit window.
    pub max_transactions_per_peer_per_window: usize,
    /// Duration (seconds) of the per-peer rate-limit sliding window.
    pub peer_rate_limit_window_secs: u64,
    /// Maximum admitted transactions per sender in one sender token-bucket window.
    pub max_transactions_per_sender_per_window: usize,
    /// Duration (seconds) of the sender token-bucket window.
    pub sender_rate_limit_window_secs: u64,
}

impl Default for MempoolConfig {
    fn default() -> Self {
        Self {
            max_pending_transactions: MAX_MEMPOOL_SIZE,
            transaction_ttl_secs: 60 * 60,
            cleanup_interval_secs: 30,
            max_transactions_per_account: 64,
            max_transactions_per_peer_per_window: 128,
            peer_rate_limit_window_secs: 1,
            max_transactions_per_sender_per_window: 64,
            sender_rate_limit_window_secs: 1,
        }
    }
}

#[derive(Clone, Debug)]
struct TokenBucket {
    capacity: usize,
    tokens: f64,
    refill_per_second: f64,
    last_refill_at: u64,
}

impl TokenBucket {
    fn new(capacity: usize, window_secs: u64, now: u64) -> Self {
        let window_secs = window_secs.max(1);
        Self {
            capacity,
            tokens: capacity as f64,
            refill_per_second: capacity as f64 / window_secs as f64,
            last_refill_at: now,
        }
    }

    fn try_consume(&mut self, now: u64) -> bool {
        let elapsed = now.saturating_sub(self.last_refill_at);
        if elapsed > 0 {
            let refilled = elapsed as f64 * self.refill_per_second;
            self.tokens = (self.tokens + refilled).min(self.capacity as f64);
            self.last_refill_at = now;
        }

        if self.tokens < 1.0 {
            return false;
        }

        self.tokens -= 1.0;
        true
    }
}

#[derive(Clone, Debug, Default)]
pub struct MempoolMetrics {
    /// Current number of transactions in the pool.
    pub mempool_size: usize,
    /// Transactions received per second (rolling 1-second window).
    pub transaction_arrival_rate: f64,
    /// Cumulative count of rejected transactions since startup.
    pub rejected_transactions: u64,
    /// Mean gas price across all pending transactions.
    pub average_gas_price: U256,
}

pub struct Mempool {
    pool: RwLock<TransactionPool>,
    validator: TransactionValidator,
    config: MempoolConfig,
    /// Optional durable storage backend for crash recovery.
    storage: Option<Arc<StorageEngine>>,
    /// Unix timestamp of the last expired-transaction sweep.
    last_cleanup_at: Mutex<u64>,
    /// Hashes received from peers (to suppress re-broadcast) and already
    /// broadcast by us; plus per-peer rate-limit counters.
    gossip_tracker: Mutex<GossipTracker>,
    /// In-process metrics state.
    metrics_tracker: Mutex<MetricsTracker>,
    /// MEV-protection commit-reveal pool. Present only when storage is available.
    commit_reveal: Option<Mutex<CommitRevealPool>>,
}

/// Tracks gossip state to prevent broadcast loops and enforce peer rate limits.
#[derive(Default)]
struct GossipTracker {
    /// Hashes of transactions we received from any peer.
    received_from_peers: HashSet<Hash>,
    /// Hashes of transactions we have already broadcast ourselves.
    broadcasted: HashSet<Hash>,
    /// peer_id -> (window_start_secs, count_in_window)
    peer_buckets: HashMap<String, TokenBucket>,
    /// sender address -> token bucket
    sender_buckets: HashMap<[u8; 32], TokenBucket>,
}

/// Rolling counters for the public metrics snapshot.
#[derive(Default)]
struct MetricsTracker {
    rejected_transactions: u64,
    /// Timestamps (Unix secs) of recent arrivals for rate calculation.
    arrival_timestamps: VecDeque<u64>,
}

impl Mempool {
    pub fn new(config: MempoolConfig, state: Arc<StateDb>) -> Self {
        Self {
            pool: RwLock::new(TransactionPool::new()),
            validator: TransactionValidator::new(state, TxValidationConfig::default()),
            config,
            storage: None,
            last_cleanup_at: Mutex::new(unix_timestamp()),
            gossip_tracker: Mutex::new(GossipTracker::default()),
            metrics_tracker: Mutex::new(MetricsTracker::default()),
            commit_reveal: None,
        }
    }

    /// Construct a `Mempool` backed by durable storage.
    pub fn with_storage(
        config: MempoolConfig,
        state: Arc<StateDb>,
        storage: Arc<StorageEngine>,
    ) -> Self {
        let cr_pool = CommitRevealPool::new(CommitRevealConfig::default(), Arc::clone(&storage));
        Self {
            pool: RwLock::new(TransactionPool::new()),
            validator: TransactionValidator::new(state, TxValidationConfig::default()),
            config,
            storage: Some(storage),
            last_cleanup_at: Mutex::new(unix_timestamp()),
            gossip_tracker: Mutex::new(GossipTracker::default()),
            metrics_tracker: Mutex::new(MetricsTracker::default()),
            commit_reveal: Some(Mutex::new(cr_pool)),
        }
    }

    /// Start the mempool. Logs capacity and returns immediately.
    pub fn start(&self) -> Result<()> {
        info!(
            "mempool started with capacity {}",
            self.config.max_pending_transactions
        );
        Ok(())
    }

    /// Validate and insert a transaction.
    ///
    /// Steps performed:
    /// 1. Reject transactions that exceed `MAX_TX_SIZE`.
    /// 2. Run full validator checks (signature, nonce, balance, gas, duplicates …).
    /// 3. If the pool is full, attempt to evict the lowest-priority incumbent;
    ///    reject the incoming transaction if it has lower-or-equal priority.
    /// 4. Trigger a periodic TTL cleanup before inserting.
    pub fn add_transaction(&self, tx: Transaction) -> Result<Hash> {
        self.enforce_sender_transaction_rate_limit(&tx)?;

        // 1. Hard size cap before any expensive checks.
        if tx.size_bytes() > MAX_TX_SIZE {
            self.record_rejected();
            anyhow::bail!(
                "transaction exceeds size limit ({} > {})",
                tx.size_bytes(),
                MAX_TX_SIZE
            );
        }

        // 2. Full validation (signature, nonce, balance, gas, duplicates).
        self.validator.validate(&tx).map_err(|e| {
            self.record_rejected();
            e
        })?;

        // 3. Capacity enforcement with priority-based eviction.
        let mut pool = self.pool.write();

        // Per-account spam guard.
        let sender_count = pool.sender_transaction_count(&tx.from);
        let replacing_existing = pool.contains_sender_nonce(&tx.from, tx.nonce);
        if !replacing_existing && sender_count >= self.config.max_transactions_per_account {
            drop(pool);
            self.record_rejected();
            anyhow::bail!(
                "account transaction limit exceeded ({} >= {})",
                sender_count,
                self.config.max_transactions_per_account
            );
        };

        if pool.len() >= self.config.max_pending_transactions {
            let new_priority = (tx.gas_price, tx.from, tx.nonce);
            let Some((evicted_hash, evicted_tx)) = pool.lowest_priority_transaction() else {
                anyhow::bail!("mempool is full");
            };

            let evicted_priority = (evicted_tx.gas_price, evicted_tx.from, evicted_tx.nonce);
            if new_priority <= evicted_priority {
                drop(pool);
                self.record_rejected();
                anyhow::bail!("mempool overflow: incoming transaction priority too low");
            }

            pool.remove(&evicted_hash);
        }

        let hash = pool.add(tx)?;
        let pending = pool.len();
        drop(pool);

        self.record_arrival(unix_timestamp());
        let _ = self.persist_transaction_to_disk(hash);

        // 4. Opportunistic TTL cleanup (no-op if interval hasn't elapsed).
        let _ = self.remove_expired_transactions_periodically();

        info!("transaction added to mempool: pending_count={}", pending);
        Ok(hash)
    }

    /// Remove transactions that have exceeded their TTL.
    /// Only performs a sweep when `cleanup_interval_secs` have elapsed since
    /// the last sweep; otherwise returns an empty list immediately.
    pub fn remove_expired_transactions_periodically(&self) -> Result<Vec<Hash>> {
        let now = unix_timestamp();
        let mut last_cleanup = self.last_cleanup_at.lock();

        if now.saturating_sub(*last_cleanup) < self.config.cleanup_interval_secs {
            return Ok(Vec::new());
        }

        let mut pool = self.pool.write();

        let removed = pool.remove_expired_transactions(self.config.transaction_ttl_secs, now);
        *last_cleanup = now;
        Ok(removed)
    }

    /// Select up to `limit` transactions for inclusion in a block.
    ///
    /// - Visits transactions in priority order (highest gas price first).
    /// - For each sender, only includes a transaction whose nonce immediately
    ///   follows the last accepted nonce for that sender (gap-free sequences).
    /// - Skips transactions that fail `validate_transaction_for_selection`
    ///   (e.g. balance changed since admission).
    pub fn select_transactions_for_block(&self, limit: usize) -> Result<Vec<Transaction>> {
        let pool = self.pool.read();

        let mut selected = Vec::with_capacity(limit);
        let mut last_nonce_per_sender: std::collections::HashMap<_, u64> =
            std::collections::HashMap::new();

        for tx in pool.prioritized_transactions() {
            if selected.len() >= limit {
                break;
            }

            // Filter out transactions that are no longer valid.
            if self
                .validator
                .validate_transaction_for_selection(&tx)
                .is_err()
            {
                continue;
            }

            // Enforce gap-free nonce ordering per account.
            let include = match last_nonce_per_sender.get(&tx.from).copied() {
                None => true,
                Some(last) => tx.nonce == last.saturating_add(1),
            };

            if include {
                last_nonce_per_sender.insert(tx.from, tx.nonce);
                selected.push(tx);
            }
        }

        Ok(selected)
    }

    // ── Disk persistence ───────────────────────────────────────────────────────────

    /// Write every pending transaction to the storage backend.
    /// Returns the number of transactions persisted.
    /// No-op if no storage backend is configured.
    pub fn persist_transactions_to_disk(&self) -> Result<usize> {
        let Some(storage) = &self.storage else {
            return Ok(0);
        };
        storage.mempool_clear()?;
        let transactions = {
            let pool = self.pool.read();
            pool.all_transactions()
        };
        for tx in &transactions {
            let bytes = bincode::serialize(tx)?;
            storage.mempool_insert(tx.hash(), &bytes)?;
        }
        Ok(transactions.len())
    }

    /// Read any previously persisted transactions from the storage backend
    /// and reinsert them into the in-memory pool.
    /// Returns the number of transactions restored.
    /// No-op if no storage backend is configured.
    pub fn restore_from_disk(&self) -> Result<usize> {
        let Some(storage) = &self.storage else {
            return Ok(0);
        };
        let entries = storage.mempool_iterate()?;
        let mut restored = 0usize;
        for (_, tx_bytes) in entries {
            let tx: Transaction = bincode::deserialize(&tx_bytes)?;
            if self.contains(tx.hash())? {
                continue;
            }
            if self.add_transaction(tx).is_ok() {
                restored = restored.saturating_add(1);
            }
        }
        Ok(restored)
    }

    /// Persist a single transaction. Called after every successful insertion.
    fn persist_transaction_to_disk(&self, tx_hash: Hash) -> Result<()> {
        let Some(storage) = &self.storage else {
            return Ok(());
        };
        let tx = self
            .get_transaction(tx_hash)?
            .ok_or_else(|| anyhow::anyhow!("transaction not found after insert"))?;
        let bytes = bincode::serialize(&tx)?;
        storage.mempool_insert(tx_hash, &bytes)?;
        Ok(())
    }

    /// Remove a single transaction from persistent storage after removal from pool.
    fn remove_persisted_transaction(&self, tx_hash: Hash) -> Result<()> {
        if let Some(storage) = &self.storage {
            let _ = storage.mempool_remove(tx_hash)?;
        }
        Ok(())
    }

    // ── Metrics ────────────────────────────────────────────────────────────────

    /// Return a point-in-time snapshot of the four tracked metrics.
    pub fn metrics_snapshot(&self) -> MempoolMetrics {
        let now = unix_timestamp();
        let mempool_size = self.pending_count().unwrap_or(0);
        let average_gas_price = self.average_gas_price();

        let mut tracker = self.metrics_tracker.lock();
        tracker.prune_arrival_window(now);
        MempoolMetrics {
            mempool_size,
            transaction_arrival_rate: tracker.arrival_timestamps.len() as f64,
            rejected_transactions: tracker.rejected_transactions,
            average_gas_price,
        }
    }

    /// Average gas price across all transactions currently in the pool.
    fn average_gas_price(&self) -> U256 {
        let pool = self.pool.read();
        if pool.txs.is_empty() {
            return U256::zero();
        }
        let total = pool
            .txs
            .values()
            .fold(U256::zero(), |sum, tx| sum.saturating_add(tx.gas_price));
        total / U256::from(pool.txs.len())
    }

    fn record_arrival(&self, timestamp: u64) {
        let mut t = self.metrics_tracker.lock();
        t.arrival_timestamps.push_back(timestamp);
        t.prune_arrival_window(timestamp);
    }

    fn record_rejected(&self) {
        let mut t = self.metrics_tracker.lock();
        t.rejected_transactions = t.rejected_transactions.saturating_add(1);
    }

    /// Accept a transaction that arrived via P2P gossip (no known source peer).
    pub fn receive_transaction_from_p2p_gossip(&self, tx: Transaction) -> Result<Hash> {
        self.receive_transaction_from_p2p_gossip_from_peer(None, tx)
    }

    /// Accept a transaction that arrived via P2P gossip from a specific peer.
    ///
    /// Enforces the per-peer rate limit before admission.
    pub fn receive_transaction_from_p2p_gossip_from_peer(
        &self,
        source_peer: Option<String>,
        tx: Transaction,
    ) -> Result<Hash> {
        if let Some(ref peer_id) = source_peer {
            self.enforce_peer_transaction_rate_limit(peer_id)?;
        }

        let hash = self.add_transaction(tx)?;

        let mut tracker = self.gossip_tracker.lock();
        tracker.received_from_peers.insert(hash);
        tracker.broadcasted.remove(&hash);
        Ok(hash)
    }

    /// Build a `GossipMessage` for `tx_hash` if it should be broadcast to peers.
    ///
    /// Returns `None` (suppressing broadcast) when:
    /// - the transaction was itself received from a peer, or
    /// - we have already broadcast it.
    pub fn broadcast_new_transaction_to_peers(
        &self,
        tx_hash: Hash,
    ) -> Result<Option<GossipMessage>> {
        let transaction = self
            .get_transaction(tx_hash)?
            .ok_or_else(|| anyhow::anyhow!("transaction not found in mempool"))?;

        let mut tracker = self.gossip_tracker.lock();

        if tracker.received_from_peers.contains(&tx_hash) || tracker.broadcasted.contains(&tx_hash)
        {
            return Ok(None);
        }

        tracker.broadcasted.insert(tx_hash);
        Ok(Some(GossipMessage::Transaction(bincode::serialize(
            &transaction,
        )?)))
    }

    // ── Spam-prevention helpers ───────────────────────────────────────────────

    /// Enforce a sliding-window rate limit per peer.
    /// Returns an error if the peer has exceeded
    /// `max_transactions_per_peer_per_window` in the current window.
    fn enforce_peer_transaction_rate_limit(&self, peer_id: &str) -> Result<()> {
        let now = unix_timestamp();
        let mut tracker = self.gossip_tracker.lock();

        let bucket = tracker
            .peer_buckets
            .entry(peer_id.to_owned())
            .or_insert_with(|| {
                TokenBucket::new(
                    self.config.max_transactions_per_peer_per_window,
                    self.config.peer_rate_limit_window_secs,
                    now,
                )
            });

        if !bucket.try_consume(now) {
            anyhow::bail!(
                "peer rate limit exceeded ({} tx per {}s)",
                self.config.max_transactions_per_peer_per_window,
                self.config.peer_rate_limit_window_secs
            );
        }
        Ok(())
    }

    fn enforce_sender_transaction_rate_limit(&self, tx: &Transaction) -> Result<()> {
        let now = unix_timestamp();
        let mut tracker = self.gossip_tracker.lock();
        let sender = *tx.from.as_bytes();
        let bucket = tracker.sender_buckets.entry(sender).or_insert_with(|| {
            TokenBucket::new(
                self.config.max_transactions_per_sender_per_window,
                self.config.sender_rate_limit_window_secs,
                now,
            )
        });

        if !bucket.try_consume(now) {
            anyhow::bail!(
                "sender rate limit exceeded ({} tx per {}s)",
                self.config.max_transactions_per_sender_per_window,
                self.config.sender_rate_limit_window_secs
            );
        }

        Ok(())
    }

    /// Returns the removed transaction, or `None`
    /// if it was not present.
    pub fn remove_transaction(&self, tx_hash: Hash) -> Result<Option<Transaction>> {
        let mut pool = self.pool.write();
        let removed = pool.remove(&tx_hash);
        drop(pool);
        if removed.is_some() {
            let _ = self.remove_persisted_transaction(tx_hash);
        }
        Ok(removed)
    }

    /// Look up a transaction by hash without removing it.
    pub fn get_transaction(&self, tx_hash: Hash) -> Result<Option<Transaction>> {
        let pool = self.pool.read();
        Ok(pool.get(&tx_hash).cloned())
    }

    /// Return `true` if the pool currently holds a transaction with the given hash.
    pub fn contains(&self, tx_hash: Hash) -> Result<bool> {
        let pool = self.pool.read();
        Ok(pool.contains(&tx_hash))
    }

    /// Return the number of transactions currently in the pool.
    pub fn pending_count(&self) -> Result<usize> {
        let pool = self.pool.read();
        Ok(pool.len())
    }

    /// Remove all transactions from the pool.
    pub fn clear(&self) -> Result<()> {
        let mut pool = self.pool.write();
        pool.clear();
        Ok(())
    }

    /// Return up to `limit` transactions ordered by priority (highest gas price first,
    /// then by sender address and nonce for determinism).
    pub fn get_pending_transactions(&self, limit: usize) -> Result<Vec<Transaction>> {
        let pool = self.pool.read();
        Ok(pool.get_top_n(limit))
    }

    // ── Node integration aliases ───────────────────────────────────────────────

    /// Alias for `persist_transactions_to_disk` — called by `Node::stop()`.
    pub fn persist_mempool_transactions_to_disk(&self) -> Result<usize> {
        self.persist_transactions_to_disk()
    }

    /// Alias for `select_transactions_for_block` — called by the block proposer.
    pub fn provide_transactions_to_block_proposer(&self, limit: usize) -> Result<Vec<Transaction>> {
        self.select_transactions_for_block(limit)
    }

    // ── MEV protection: commit-reveal interface ───────────────────────────────

    /// Submit a commit during the commit phase.
    /// Returns the commit ID on success, or an error if MEV protection is
    /// unavailable (no storage backend) or validation fails.
    pub fn submit_commit(&self, commit: CommitTransaction) -> Result<[u8; 32]> {
        let cr = self
            .commit_reveal
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("MEV protection requires a storage-backed mempool"))?;
        cr.lock().submit_commit(commit)
    }

    /// Submit a reveal that matches a previously submitted commit.
    /// Validates the reveal window, replays the commitment, and promotes the
    /// transaction to the MEV-protected ready pool.
    pub fn submit_reveal(&self, reveal: RevealTransaction) -> Result<()> {
        let cr = self
            .commit_reveal
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("MEV protection requires a storage-backed mempool"))?;
        cr.lock().submit_reveal(reveal)
    }

    /// Advance the commit-reveal pool's block height, evicting expired commits.
    /// Call this once per newly processed block.
    pub fn on_block_height(&self, height: u64) -> Result<()> {
        if let Some(cr) = &self.commit_reveal {
            cr.lock().on_new_block(height)?;
        }
        Ok(())
    }

    /// Build an ordered, MEV-protected transaction list for the next block.
    /// Transactions are drawn from *revealed* commits only and shuffled with a
    /// deterministic seed to prevent gas-price front-running.
    /// Falls back to standard `select_transactions_for_block` when MEV
    /// protection is not configured.
    pub fn build_mev_protected_transactions(&self, limit: usize) -> Result<Vec<Transaction>> {
        if let Some(cr) = &self.commit_reveal {
            let txs = cr.lock().build_block_transactions(limit);
            if !txs.is_empty() {
                return Ok(txs);
            }
        }
        // Fall back to standard priority ordering when the reveal pool is empty.
        self.select_transactions_for_block(limit)
    }

    /// Return the current commit-reveal pool statistics for monitoring.
    pub fn mev_pool_stats(&self) -> (usize, usize) {
        self.commit_reveal
            .as_ref()
            .map(|cr| {
                let pool = cr.lock();
                (pool.pending_commit_count(), pool.revealed_tx_count())
            })
            .unwrap_or((0, 0))
    }

    /// Remove all transactions that were included in a committed block from both
    /// the in-memory pool and the durable storage backend.
    pub fn remove_transactions_after_block_commit(&self, block: &Block) -> Result<()> {
        let hashes: Vec<Hash> = block.body.transactions.iter().map(|tx| tx.hash()).collect();
        let mut pool = self.pool.write();
        pool.remove_many(&hashes);
        drop(pool);
        for hash in &hashes {
            let _ = self.remove_persisted_transaction(*hash);
        }
        Ok(())
    }
}

impl TransactionPoolSink for Mempool {
    fn contains_transaction(&self, tx: &Transaction) -> Result<bool> {
        self.contains(tx.hash())
    }

    fn insert_transaction(&self, tx: Transaction, source_peer: Option<String>) -> Result<()> {
        self.receive_transaction_from_p2p_gossip_from_peer(source_peer, tx)
            .map(|_| ())
    }
}

impl TransactionSource for Mempool {
    fn pull_transactions(&self, limit: usize) -> Result<Vec<Transaction>> {
        self.select_transactions_for_block(limit)
    }

    fn acknowledge_transactions(&self, hashes: &[[u8; 32]]) -> Result<()> {
        let mut pool = self.pool.write();
        pool.remove_many(hashes);
        drop(pool);
        for hash in hashes {
            let _ = self.remove_persisted_transaction(*hash);
        }
        Ok(())
    }
}

fn unix_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

impl MetricsTracker {
    fn prune_arrival_window(&mut self, now: u64) {
        // Keep only timestamps within the last 1-second window.
        while let Some(&oldest) = self.arrival_timestamps.front() {
            if now.saturating_sub(oldest) >= 1 {
                self.arrival_timestamps.pop_front();
            } else {
                break;
            }
        }
    }
}
