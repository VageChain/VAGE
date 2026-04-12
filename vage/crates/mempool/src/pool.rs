use anyhow::Result;
use primitive_types::U256;
use std::collections::{BTreeMap, HashMap};
use std::time::{SystemTime, UNIX_EPOCH};
use vage_types::{Address, Hash, Transaction};

pub struct TransactionPool {
    pub txs: HashMap<Hash, Transaction>,
    /// sender -> nonce -> hash
    by_sender: HashMap<Address, BTreeMap<u64, Hash>>,
    /// nonce -> [hash, ...]
    by_nonce: BTreeMap<u64, Vec<Hash>>,
    /// gas_price -> [hash, ...]
    by_gas_price: BTreeMap<U256, Vec<Hash>>,
    /// monotonic arrival sequence -> hash
    by_arrival_time: BTreeMap<u64, Hash>,
    /// hash -> wall-clock insertion timestamp (secs)
    timestamps: HashMap<Hash, u64>,
    arrival_sequence: u64,
}

impl TransactionPool {
    pub fn new() -> Self {
        Self {
            txs: HashMap::new(),
            by_sender: HashMap::new(),
            by_nonce: BTreeMap::new(),
            by_gas_price: BTreeMap::new(),
            by_arrival_time: BTreeMap::new(),
            timestamps: HashMap::new(),
            arrival_sequence: 0,
        }
    }

    /// Insert a transaction, maintaining all secondary indexes.
    /// If a transaction from the same sender with the same nonce already exists,
    /// replace-by-fee is attempted before inserting the new one.
    /// Returns the transaction hash. Errors if the hash already exists after RBF.
    pub fn insert(&mut self, tx: Transaction) -> Result<Hash> {
        // Replace-by-fee: evict incumbent with same (sender, nonce) if present.
        if let Some(existing_hash) = self.lookup_by_sender_and_nonce(&tx.from, tx.nonce) {
            self.replace_by_fee(existing_hash, &tx)?;
        }

        let hash = tx.hash();
        if self.txs.contains_key(&hash) {
            anyhow::bail!("transaction already exists in pool");
        }

        //  secondary index maintenance
        self.by_sender
            .entry(tx.from)
            .or_default()
            .insert(tx.nonce, hash);
        self.by_nonce.entry(tx.nonce).or_default().push(hash);
        self.by_gas_price
            .entry(tx.gas_price)
            .or_default()
            .push(hash);
        self.by_arrival_time.insert(self.arrival_sequence, hash);
        self.timestamps.insert(hash, unix_timestamp());
        self.arrival_sequence = self.arrival_sequence.saturating_add(1);
        //

        self.txs.insert(hash, tx);
        Ok(hash)
    }

    /// Remove a transaction by hash, cleaning all secondary indexes.
    pub fn remove(&mut self, hash: &Hash) -> Option<Transaction> {
        let tx = self.txs.remove(hash)?;
        self.remove_from_sender_index(tx.from, tx.nonce);
        self.remove_from_nonce_index(tx.nonce, hash);
        self.remove_from_gas_price_index(tx.gas_price, hash);
        self.remove_from_arrival_index(hash);
        self.timestamps.remove(hash);
        Some(tx)
    }

    /// Look up a transaction by hash without removing it.
    pub fn get(&self, hash: &Hash) -> Option<&Transaction> {
        self.txs.get(hash)
    }

    /// Return `true` if the pool contains a transaction with the given hash.
    pub fn contains(&self, hash: &Hash) -> bool {
        self.txs.contains_key(hash)
    }

    /// Return the number of transactions currently in the pool.
    pub fn size(&self) -> usize {
        self.txs.len()
    }

    /// Remove all transactions and reset all indexes.
    pub fn clear(&mut self) {
        self.txs.clear();
        self.by_sender.clear();
        self.by_nonce.clear();
        self.by_gas_price.clear();
        self.by_arrival_time.clear();
        self.timestamps.clear();
        self.arrival_sequence = 0;
    }

    /// Return all transactions (order unspecified).
    pub fn all_transactions(&self) -> Vec<Transaction> {
        self.txs.values().cloned().collect()
    }

    //  Index-based lookups

    /// All transactions from a given sender, ordered by nonce (ascending).
    pub fn transactions_by_sender(&self, sender: &Address) -> Vec<Transaction> {
        self.by_sender
            .get(sender)
            .into_iter()
            .flat_map(|nonces| nonces.values())
            .filter_map(|hash| self.txs.get(hash))
            .cloned()
            .collect()
    }

    /// All transactions with an exact nonce value.
    pub fn transactions_by_nonce(&self, nonce: u64) -> Vec<Transaction> {
        self.by_nonce
            .get(&nonce)
            .into_iter()
            .flatten()
            .filter_map(|hash| self.txs.get(hash))
            .cloned()
            .collect()
    }

    /// All transactions with an exact gas price.
    pub fn transactions_by_gas_price(&self, gas_price: U256) -> Vec<Transaction> {
        self.by_gas_price
            .get(&gas_price)
            .into_iter()
            .flatten()
            .filter_map(|hash| self.txs.get(hash))
            .cloned()
            .collect()
    }

    /// All transactions in arrival order (oldest first).
    pub fn transactions_by_arrival_time(&self) -> Vec<Transaction> {
        self.by_arrival_time
            .values()
            .filter_map(|hash| self.txs.get(hash))
            .cloned()
            .collect()
    }

    /// Return the hash of the transaction from `sender` with `nonce`, if any.
    pub fn lookup_by_sender_and_nonce(&self, sender: &Address, nonce: u64) -> Option<Hash> {
        self.by_sender
            .get(sender)
            .and_then(|nonces| nonces.get(&nonce))
            .copied()
    }

    /// Number of pending transactions from a given sender.
    pub fn sender_transaction_count(&self, sender: &Address) -> usize {
        self.by_sender
            .get(sender)
            .map(|nonces| nonces.len())
            .unwrap_or(0)
    }

    /// `true` if the pool contains a transaction from `sender` at `nonce`.
    pub fn contains_sender_nonce(&self, sender: &Address, nonce: u64) -> bool {
        self.lookup_by_sender_and_nonce(sender, nonce).is_some()
    }

    // ── Replace-by-fee ────────────────────────────────────────────────────────

    /// Attempt to replace `existing_hash` with `replacement`.
    /// Requires `replacement.gas_price > existing.gas_price`.
    /// The incumbent is removed; the caller is responsible for inserting the
    /// replacement afterwards.
    pub fn replace_by_fee(&mut self, existing_hash: Hash, replacement: &Transaction) -> Result<()> {
        let existing = self
            .get(&existing_hash)
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("transaction to replace does not exist"))?;
        self.validate_replacement_gas_price(&existing, replacement)?;
        self.remove(&existing_hash);
        Ok(())
    }

    /// Return an error if `replacement` does not offer a strictly higher gas
    /// price than `existing`.
    pub fn validate_replacement_gas_price(
        &self,
        existing: &Transaction,
        replacement: &Transaction,
    ) -> Result<()> {
        if replacement.gas_price <= existing.gas_price {
            anyhow::bail!(
                "replace-by-fee rejected: replacement gas price ({}) must exceed incumbent ({})",
                replacement.gas_price,
                existing.gas_price
            );
        }
        Ok(())
    }

    //  Private index helpers

    fn remove_from_sender_index(&mut self, sender: Address, nonce: u64) {
        if let Some(nonces) = self.by_sender.get_mut(&sender) {
            nonces.remove(&nonce);
            if nonces.is_empty() {
                self.by_sender.remove(&sender);
            }
        }
    }

    fn remove_from_nonce_index(&mut self, nonce: u64, hash: &Hash) {
        if let Some(entries) = self.by_nonce.get_mut(&nonce) {
            entries.retain(|h| h != hash);
            if entries.is_empty() {
                self.by_nonce.remove(&nonce);
            }
        }
    }

    fn remove_from_gas_price_index(&mut self, gas_price: U256, hash: &Hash) {
        if let Some(entries) = self.by_gas_price.get_mut(&gas_price) {
            entries.retain(|h| h != hash);
            if entries.is_empty() {
                self.by_gas_price.remove(&gas_price);
            }
        }
    }

    fn remove_from_arrival_index(&mut self, hash: &Hash) {
        if let Some(seq) = self.arrival_seq_for_hash(hash) {
            self.by_arrival_time.remove(&seq);
        }
    }

    fn arrival_seq_for_hash(&self, hash: &Hash) -> Option<u64> {
        self.by_arrival_time
            .iter()
            .find_map(|(seq, h)| (h == hash).then_some(*seq))
    }

    //  Convenience aliases used by Mempool

    pub fn len(&self) -> usize {
        self.size()
    }

    pub fn add(&mut self, tx: Transaction) -> Result<Hash> {
        self.insert(tx)
    }

    pub fn get_top_n(&self, n: usize) -> Vec<Transaction> {
        self.block_selection_ordering(n)
    }

    pub fn remove_many(&mut self, hashes: &[Hash]) {
        for hash in hashes {
            self.remove(hash);
        }
    }

    /// The transaction with the lowest priority (candidate for eviction).
    /// Priority key (ascending worst-first): gas_price asc, sender desc,
    /// nonce desc, arrival_seq desc, hash desc — fully deterministic.
    pub fn lowest_priority_transaction(&self) -> Option<(Hash, Transaction)> {
        self.txs
            .iter()
            .filter_map(|(hash, tx)| {
                let seq = self.arrival_seq_for_hash(hash)?;
                Some((*hash, tx.clone(), tx.gas_price, tx.from, tx.nonce, seq))
            })
            .min_by(|a, b| {
                a.2.cmp(&b.2) // lowest gas price first
                    .then_with(|| b.3.cmp(&a.3)) // highest sender addr first (worst)
                    .then_with(|| b.4.cmp(&a.4)) // highest nonce first (worst)
                    .then_with(|| b.5.cmp(&a.5)) // latest arrival first (worst)
                    .then_with(|| b.0.cmp(&a.0)) // lexicographically largest hash
            })
            .map(|(hash, tx, _, _, _, _)| (hash, tx))
    }

    /// All transactions in deterministic priority order (best first).
    ///
    /// Sort key (descending best-first):
    ///   1. gas_price DESC  — higher fee preferred
    ///   2. sender ASC      — tie-break by address for determinism
    ///   3. nonce ASC       — lower nonce executes first within a sender
    ///   4. arrival_seq ASC — earlier arrival preferred among equals
    ///   5. hash ASC        — final byte-level tie-break
    pub fn prioritized_transactions(&self) -> Vec<Transaction> {
        let mut ordered: Vec<(U256, Address, u64, u64, Hash, Transaction)> = self
            .txs
            .iter()
            .filter_map(|(hash, tx)| {
                let seq = self.arrival_seq_for_hash(hash)?;
                Some((tx.gas_price, tx.from, tx.nonce, seq, *hash, tx.clone()))
            })
            .collect();

        ordered.sort_by(|a, b| {
            b.0.cmp(&a.0) // gas_price DESC
                .then_with(|| a.1.cmp(&b.1)) // sender ASC
                .then_with(|| a.2.cmp(&b.2)) // nonce ASC
                .then_with(|| a.3.cmp(&b.3)) // arrival_seq ASC
                .then_with(|| a.4.cmp(&b.4)) // hash ASC
        });

        ordered.into_iter().map(|(_, _, _, _, _, tx)| tx).collect()
    }

    // ── TTL / timestamp helpers ───────────────────────────────────────────────

    /// Return the wall-clock insertion timestamp (Unix seconds) for `hash`.
    pub fn transaction_timestamp(&self, hash: &Hash) -> Option<u64> {
        self.timestamps.get(hash).copied()
    }

    /// Return the hashes of all transactions older than `ttl_secs` seconds.
    pub fn expired_transactions(&self, ttl_secs: u64, now: u64) -> Vec<Hash> {
        self.timestamps
            .iter()
            .filter_map(|(hash, ts)| (now.saturating_sub(*ts) >= ttl_secs).then_some(*hash))
            .collect()
    }

    /// Remove all transactions whose TTL has elapsed and return their hashes.
    pub fn remove_expired_transactions(&mut self, ttl_secs: u64, now: u64) -> Vec<Hash> {
        let expired = self.expired_transactions(ttl_secs, now);
        self.remove_many(&expired);
        expired
    }

    /// Select up to `limit` transactions suitable for a block proposal.
    ///
    /// Rules enforced:
    /// - Transactions are visited in priority order (see `prioritized_transactions`).
    /// - Per sender, only transactions whose nonce is exactly
    ///   `last_included_nonce + 1` (or the first nonce seen for that sender)
    ///   are included, ensuring gap-free nonce sequences.
    /// - Selection stops once `limit` is reached.
    pub fn block_selection_ordering(&self, limit: usize) -> Vec<Transaction> {
        let mut selected = Vec::with_capacity(limit);
        let mut last_nonce_per_sender: HashMap<Address, u64> = HashMap::new();

        for tx in self.prioritized_transactions() {
            if selected.len() >= limit {
                break;
            }

            let include = match last_nonce_per_sender.get(&tx.from).copied() {
                // First transaction from this sender: always include.
                None => true,
                // Include only if it continues the nonce sequence without gaps.
                Some(last) => tx.nonce == last.saturating_add(1),
            };

            if include {
                last_nonce_per_sender.insert(tx.from, tx.nonce);
                selected.push(tx);
            }
        }

        selected
    }
}

impl Default for TransactionPool {
    fn default() -> Self {
        Self::new()
    }
}

fn unix_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
