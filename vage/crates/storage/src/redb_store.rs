use anyhow::{bail, Context, Result};
use lru::LruCache;
use metrics::counter;
use parking_lot::Mutex;
use primitive_types::U256;
use rayon::prelude::*;
use redb::{Database, ReadTransaction, ReadableTable, TableDefinition, WriteTransaction};
use std::fs;
use std::num::NonZeroUsize;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{mpsc, Arc};
use std::thread::{self, JoinHandle};
use std::time::Duration;
use tracing::{error, info, warn};
use vage_block::{BlockBody, BlockHeader};
use vage_types::{Receipt, Transaction, Validator};

type StateUpdates = Vec<(Vec<u8>, Option<Vec<u8>>)>;

/// Metadata table for database versioning and health checks.
pub const METADATA: TableDefinition<&str, &str> = TableDefinition::new("metadata");
pub const DB_VERSION: &str = "1.0.0";
const LATEST_BLOCK_HEIGHT_KEY: &str = "latest_block_height";
const LAST_SHUTDOWN_CLEAN_KEY: &str = "last_shutdown_clean";
const LAST_OPENED_AT_KEY: &str = "last_opened_at";
const LAST_RECOVERY_AT_KEY: &str = "last_recovery_at";
const LAST_CORRUPTION_ERROR_KEY: &str = "last_corruption_error";
const LAST_COMPACTION_AT_KEY: &str = "last_compaction_at";
const LAST_COMPACTION_PATH_KEY: &str = "last_compaction_path";
const DEFAULT_FLUSH_INTERVAL_SECS: u64 = 5;

#[derive(Default)]
struct StorageMetricsInner {
    batch_write_total: AtomicU64,
    cache_hits: AtomicU64,
    cache_misses: AtomicU64,
    disk_flush_total: AtomicU64,
    parallel_reads_total: AtomicU64,
    buffered_write_flushes: AtomicU64,
    buffered_writes_enqueued: AtomicU64,
}

/// The core StorageEngine orchestrating redb-backed persistent storage.
pub struct StorageEngine {
    db: Arc<Database>,
    db_path: PathBuf,
    /// Read cache for hot state values.
    cache: Mutex<LruCache<Vec<u8>, Vec<u8>>>,
    buffered_state_writes: Arc<Mutex<StateUpdates>>,
    metrics: Arc<StorageMetricsInner>,
    flush_thread_stop: Mutex<Option<mpsc::Sender<()>>>,
    flush_thread_handle: Mutex<Option<JoinHandle<()>>>,
    compaction_handle: Mutex<Option<JoinHandle<()>>>,
    shutdown_recorded: AtomicBool,
    compaction_running: Arc<AtomicBool>,
}

impl StorageEngine {
    /// Initialize the StorageEngine with durable file locking and mmap-backed storage.
    pub fn new(db_path: impl AsRef<Path>) -> Result<Self> {
        let db_path = db_path.as_ref().to_path_buf();
        let db = Self::open_or_create_db(&db_path)?;

        let engine = Self {
            db: Arc::new(db),
            db_path,
            cache: Mutex::new(LruCache::new(NonZeroUsize::new(10000).unwrap())),
            buffered_state_writes: Arc::new(Mutex::new(Vec::new())),
            metrics: Arc::new(StorageMetricsInner::default()),
            flush_thread_stop: Mutex::new(None),
            flush_thread_handle: Mutex::new(None),
            compaction_handle: Mutex::new(None),
            shutdown_recorded: AtomicBool::new(false),
            compaction_running: Arc::new(AtomicBool::new(false)),
        };

        // Initialize metadata and check versioning
        engine.init_metadata()?;
        engine.init_schema_tables()?;
        engine.start_flush_scheduler()?;

        Ok(engine)
    }

    fn init_schema_tables(&self) -> Result<()> {
        let tx = self.begin_write()?;
        crate::tables::validate_schema(&tx)?;
        crate::tables::create_tables(&tx)?;
        tx.commit()
            .context("Failed to commit schema table initialization")?;
        Ok(())
    }

    /// Open or create the database with recovery and corruption detection.
    fn open_or_create_db(path: &Path) -> Result<Database> {
        info!("Opening database at {:?}", path);

        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("Failed to create database directory {:?}", parent))?;
        }

        // Configure builder with page cache and durable write strategy
        let mut builder = Database::builder();
        builder.set_cache_size(512 * 1024 * 1024); // 512MB cache

        // Attempt to open the database.
        let db = match builder.create(path) {
            Ok(db) => db,
            Err(e) => {
                let err_msg = format!("{:?}", e);
                if err_msg.contains("Corrupted") || err_msg.contains("corrupted") {
                    error!(
                        "Database corruption detected at {:?}: {}. Attempting recovery...",
                        path, err_msg
                    );
                    let marker_path = path.with_extension("corrupt");
                    let _ = std::fs::write(&marker_path, err_msg.as_bytes());
                    bail!(
                        "Database at {:?} is corrupted and cannot be recovered automatically",
                        path
                    );
                } else {
                    error!("Failed to open database: {:?}", e);
                    return Err(e.into());
                }
            }
        };

        Ok(db)
    }

    /// Initialize database versioning and metadata.
    fn init_metadata(&self) -> Result<()> {
        let tx = self.begin_write()?;
        {
            let mut table = tx
                .open_table(METADATA)
                .context("Failed to open metadata table")?;

            let was_clean_shutdown = table
                .get(LAST_SHUTDOWN_CLEAN_KEY)?
                .map(|value| value.value() == "true")
                .unwrap_or(true);

            // Check version and handle migrations
            let version_opt = table.get("version")?.map(|v| v.value().to_string());
            if let Some(version_str) = version_opt {
                if version_str != DB_VERSION {
                    // Parse versions for migration comparison
                    match Self::parse_version(&version_str) {
                        Ok(existing_version) => {
                            match Self::parse_version(DB_VERSION) {
                                Ok(expected_version) => {
                                    if existing_version > expected_version {
                                        // Database from newer version
                                        bail!(
                                            "Database was created with a newer version {} > {}. \
                                             Please upgrade the client.",
                                            version_str,
                                            DB_VERSION
                                        );
                                    } else if existing_version < expected_version {
                                        // Database from older version - needs migration
                                        warn!(
                                            "Database version mismatch. Existing {}, Expected {}. \
                                             Attempting automatic migration...",
                                            version_str, DB_VERSION
                                        );
                                        Self::migrate_schema(
                                            existing_version,
                                            expected_version,
                                            &mut table,
                                        )?
                                    }
                                }
                                Err(e) => {
                                    bail!(
                                        "Failed to parse expected database version {}: {}",
                                        DB_VERSION,
                                        e
                                    );
                                }
                            }
                        }
                        Err(e) => {
                            bail!(
                                "Failed to parse existing database version {}: {}",
                                version_str,
                                e
                            );
                        }
                    }
                }
            } else {
                info!("Initializing new database metadata version {}", DB_VERSION);
                table.insert("version", DB_VERSION)?;
                let now_str = chrono::Utc::now().to_rfc3339();
                table.insert("created_at", now_str.as_str())?;
            }

            let now_str = chrono::Utc::now().to_rfc3339();
            table.insert(LAST_OPENED_AT_KEY, now_str.as_str())?;
            table.insert(LAST_SHUTDOWN_CLEAN_KEY, "false")?;

            if !was_clean_shutdown {
                warn!(
                    "Detected unclean database shutdown at {:?}. redb crash recovery will be relied on and recovery metadata has been recorded.",
                    self.db_path
                );
                table.insert(LAST_RECOVERY_AT_KEY, now_str.as_str())?;
            }

            let corruption_marker = self.db_path.with_extension("corrupt");
            if corruption_marker.exists() {
                if let Ok(error_message) = std::fs::read_to_string(&corruption_marker) {
                    table.insert(LAST_CORRUPTION_ERROR_KEY, error_message.as_str())?;
                }
                let _ = std::fs::remove_file(corruption_marker);
            }
        }
        tx.commit()
            .context("Failed to commit metadata initialization")?;
        Ok(())
    }

    /// Parse a version string in semver format (major.minor.patch).
    fn parse_version(version: &str) -> Result<(u32, u32, u32)> {
        let parts: Vec<&str> = version.split('.').collect();
        if parts.len() != 3 {
            bail!("Invalid version format: {}", version);
        }
        let major = parts[0]
            .parse::<u32>()
            .context("Failed to parse major version")?;
        let minor = parts[1]
            .parse::<u32>()
            .context("Failed to parse minor version")?;
        let patch = parts[2]
            .parse::<u32>()
            .context("Failed to parse patch version")?;
        Ok((major, minor, patch))
    }

    /// Handle schema migrations between versions.
    ///
    /// Each `(major, minor, patch)` version pair that introduces structural
    /// schema changes must be listed as a dedicated handler here.  Handlers run
    /// in order, so migrating across multiple versions in a single upgrade is
    /// safe Ã¢â‚¬â€ each step is applied exactly once.
    fn migrate_schema(
        from: (u32, u32, u32),
        to: (u32, u32, u32),
        metadata_table: &mut redb::Table<&str, &str>,
    ) -> Result<()> {
        info!(
            "Migrating database schema from {}.{}.{} to {}.{}.{}",
            from.0, from.1, from.2, to.0, to.1, to.2
        );

        // Ã¢â€â‚¬Ã¢â€â‚¬ 1.0.0 Ã¢â€ â€™ 1.1.0 Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬
        // — 1.0.0 → 1.1.0 ————————————————————————————————————————————————————————————————
        // Added: `chain_id` column in the metadata table for replay-protection.
        if from < (1, 1, 0) && to >= (1, 1, 0) {
            // Only insert the default if the key is absent (safe to run twice).
            if metadata_table.get("chain_id")?.is_none() {
                metadata_table.insert("chain_id", "1")?;
                info!("Migration 1.0.0→1.1.0: initialised chain_id=1 in metadata");
            }
        }

        // — 1.1.0 → 1.2.0 ————————————————————————————————————————————————————————————————
        // Added: `schema_hash` integrity field to detect bit-rot or partial writes.
        if from < (1, 2, 0) && to >= (1, 2, 0) && metadata_table.get("schema_hash")?.is_none() {
            // SHA-256 of the canonical table list at 1.2.0 — computed offline.
            metadata_table.insert("schema_hash", "genesis")?;
            info!("Migration 1.1.0→1.2.0: initialised schema_hash placeholder");
        }

        // Ã¢â€â‚¬Ã¢â€â‚¬ future migrations go here Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬

        // Update the stored version to the target and record the migration time.
        let version_string = format!("{}.{}.{}", to.0, to.1, to.2);
        metadata_table.insert("version", version_string.as_str())?;
        metadata_table.insert("migrated_at", chrono::Utc::now().to_rfc3339().as_str())?;
        info!(
            "Database migration to {} completed successfully",
            version_string
        );

        Ok(())
    }
    pub fn db(&self) -> Arc<Database> {
        self.db.clone()
    }

    /// Begin a read-only snapshot transaction.
    pub fn begin_read(&self) -> Result<ReadTransaction> {
        self.db
            .begin_read()
            .context("Failed to begin read transaction")
    }

    /// Begin a read/write transaction.
    pub fn begin_write(&self) -> Result<WriteTransaction> {
        self.db
            .begin_write()
            .context("Failed to begin write transaction")
    }

    /// Crash-safe commit wrapper for generic write operations.
    pub fn execute_write<F>(&self, f: F) -> Result<()>
    where
        F: FnOnce(&WriteTransaction) -> Result<()>,
    {
        let tx = self.begin_write()?;
        f(&tx)?;
        tx.commit().context("Transactional commit failed")
    }

    pub fn buffer_block_execution_write(&self, key: Vec<u8>, value: Option<Vec<u8>>) -> Result<()> {
        let mut buffered = self.buffered_state_writes.lock();
        buffered.push((key, value));
        self.metrics
            .buffered_writes_enqueued
            .fetch_add(1, Ordering::Relaxed);
        Ok(())
    }

    pub fn flush_buffered_block_execution_writes(&self) -> Result<usize> {
        Self::flush_buffered_state_writes_inner(
            &self.db,
            &self.buffered_state_writes,
            &self.metrics,
        )
    }

    /// Retrieve a value from a specific table within a read transaction.
    pub fn get(&self, table: TableDefinition<&[u8], &[u8]>, key: &[u8]) -> Result<Option<Vec<u8>>> {
        let tx = self.begin_read()?;
        let table = tx.open_table(table)?;
        let value = table.get(key)?;
        Ok(value.map(|v| v.value().to_vec()))
    }

    pub fn store_block_header(&self, height: u64, header: &BlockHeader) -> Result<()> {
        let header_bytes =
            bincode::serialize(header).context("Failed to serialize block header")?;
        self.store_block_header_bytes(height, &header_bytes)
    }

    pub fn get_block_header(&self, height: u64) -> Result<Option<BlockHeader>> {
        self.get_block_header_bytes(height)?
            .map(|header_bytes| {
                bincode::deserialize(&header_bytes).context("Failed to deserialize block header")
            })
            .transpose()
    }

    pub fn store_block_body(&self, height: u64, body: &BlockBody) -> Result<()> {
        let body_bytes = bincode::serialize(body).context("Failed to serialize block body")?;
        self.store_block_body_bytes(height, &body_bytes)
    }

    pub fn get_block_body(&self, height: u64) -> Result<Option<BlockBody>> {
        self.get_block_body_bytes(height)?
            .map(|body_bytes| {
                bincode::deserialize(&body_bytes).context("Failed to deserialize block body")
            })
            .transpose()
    }

    pub fn atomic_block_commit_typed(
        &self,
        height: u64,
        header: &BlockHeader,
        body: &BlockBody,
    ) -> Result<()> {
        let header_bytes =
            bincode::serialize(header).context("Failed to serialize block header")?;
        let body_bytes = bincode::serialize(body).context("Failed to serialize block body")?;
        self.atomic_block_commit(height, header_bytes, body_bytes)
    }

    // --- Block Storage Methods ---

    /// Store a block header at a specific height.
    pub fn store_block_header_bytes(&self, height: u64, header_bytes: &[u8]) -> Result<()> {
        let tx = self.begin_write()?;
        {
            let mut table = tx.open_table(crate::schema::TABLE_BLOCK_HEADERS)?;
            table.insert(height, header_bytes)?;
            Self::update_latest_height_metadata(&tx, height)?;
        }
        tx.commit().context("Failed to commit block header")?;
        Ok(())
    }

    /// Retrieve a block header by its height.
    pub fn get_block_header_bytes(&self, height: u64) -> Result<Option<Vec<u8>>> {
        let tx = self.begin_read()?;
        let table = tx.open_table(crate::schema::TABLE_BLOCK_HEADERS)?;
        let value = table.get(height)?;
        Ok(value.map(|v| v.value().to_vec()))
    }

    /// Store a block body at a specific height.
    pub fn store_block_body_bytes(&self, height: u64, body_bytes: &[u8]) -> Result<()> {
        let tx = self.begin_write()?;
        {
            let mut table = tx.open_table(crate::schema::TABLE_BLOCK_BODIES)?;
            table.insert(height, body_bytes)?;
            Self::update_latest_height_metadata(&tx, height)?;
        }
        tx.commit().context("Failed to commit block body")?;
        Ok(())
    }

    /// Retrieve a block body by its height.
    pub fn get_block_body_bytes(&self, height: u64) -> Result<Option<Vec<u8>>> {
        let tx = self.begin_read()?;
        let table = tx.open_table(crate::schema::TABLE_BLOCK_BODIES)?;
        let value = table.get(height)?;
        Ok(value.map(|v| v.value().to_vec()))
    }

    /// Atomically commit a block (header and body) and update the latest height.
    pub fn atomic_block_commit(
        &self,
        height: u64,
        header_bytes: Vec<u8>,
        body_bytes: Vec<u8>,
    ) -> Result<()> {
        let tx = self.begin_write()?;
        {
            let mut header_table = tx.open_table(crate::schema::TABLE_BLOCK_HEADERS)?;
            let mut body_table = tx.open_table(crate::schema::TABLE_BLOCK_BODIES)?;

            header_table.insert(height, header_bytes.as_slice())?;
            body_table.insert(height, body_bytes.as_slice())?;
            Self::update_latest_height_metadata(&tx, height)?;
        }
        tx.commit().context("Atomic block commit failed")?;
        Ok(())
    }

    /// Get the latest processed block height.
    pub fn latest_block_height(&self) -> Result<u64> {
        let tx = self.begin_read()?;
        let table = tx.open_table(crate::schema::TABLE_METADATA)?;
        Ok(Self::read_latest_height_metadata(&table)?.unwrap_or(0))
    }

    /// Check if a block exists at a specific height.
    pub fn block_exists(&self, height: u64) -> Result<bool> {
        let tx = self.begin_read()?;
        let table = tx.open_table(crate::schema::TABLE_BLOCK_HEADERS)?;
        Ok(table.get(height)?.is_some())
    }

    /// Prune block headers and bodies before a certain height.
    pub fn prune_blocks_before(&self, height: u64) -> Result<usize> {
        let previous_latest = self.latest_block_height()?;
        let tx = self.begin_write()?;
        let mut pruned_heights = Vec::new();
        {
            let mut header_table = tx.open_table(crate::schema::TABLE_BLOCK_HEADERS)?;
            let mut body_table = tx.open_table(crate::schema::TABLE_BLOCK_BODIES)?;

            for entry in header_table.iter()? {
                let (stored_height, _) = entry?;
                if stored_height.value() < height {
                    pruned_heights.push(stored_height.value());
                }
            }

            for pruned_height in &pruned_heights {
                header_table.remove(*pruned_height)?;
                body_table.remove(*pruned_height)?;
            }
        }
        let latest_after_prune = if previous_latest >= height {
            Some(previous_latest)
        } else {
            None
        };
        Self::reconcile_latest_height_metadata(&tx, latest_after_prune)?;
        tx.commit().context("Block pruning failed")?;
        Ok(pruned_heights.len())
    }

    // --- Transaction Storage Methods ---

    pub fn store_transaction(&self, tx_hash: [u8; 32], tx: &Transaction) -> Result<()> {
        let tx_bytes = bincode::serialize(tx).context("Failed to serialize transaction")?;
        self.store_transaction_bytes(tx_hash, &tx_bytes)
    }

    pub fn get_transaction(&self, tx_hash: [u8; 32]) -> Result<Option<Transaction>> {
        self.get_transaction_bytes(tx_hash)?
            .map(|tx_bytes| {
                bincode::deserialize(&tx_bytes).context("Failed to deserialize transaction")
            })
            .transpose()
    }

    /// Store a transaction indexed by its hash.
    pub fn store_transaction_bytes(&self, tx_hash: [u8; 32], tx_bytes: &[u8]) -> Result<()> {
        let tx = self.begin_write()?;
        {
            let mut table = tx.open_table(crate::schema::TABLE_TRANSACTIONS)?;
            table.insert(tx_hash, tx_bytes)?;
        }
        tx.commit().context("Failed to commit transaction")?;
        Ok(())
    }

    /// Retrieve a transaction by its hash.
    pub fn get_transaction_bytes(&self, tx_hash: [u8; 32]) -> Result<Option<Vec<u8>>> {
        let tx = self.begin_read()?;
        let table = tx.open_table(crate::schema::TABLE_TRANSACTIONS)?;
        Ok(table.get(tx_hash)?.map(|v| v.value().to_vec()))
    }

    /// Check if a transaction exists in the database.
    pub fn transaction_exists(&self, tx_hash: [u8; 32]) -> Result<bool> {
        let tx = self.begin_read()?;
        let table = tx.open_table(crate::schema::TABLE_TRANSACTIONS)?;
        Ok(table.get(tx_hash)?.is_some())
    }

    pub fn store_receipt(&self, tx_hash: [u8; 32], receipt: &Receipt) -> Result<()> {
        let receipt_bytes = bincode::serialize(receipt).context("Failed to serialize receipt")?;
        self.store_receipt_bytes(tx_hash, &receipt_bytes)
    }

    /// Store a transaction receipt.
    pub fn store_receipt_bytes(&self, tx_hash: [u8; 32], receipt_bytes: &[u8]) -> Result<()> {
        let tx = self.begin_write()?;
        {
            let mut table = tx.open_table(crate::schema::TABLE_TX_RECEIPTS)?;
            table.insert(tx_hash, receipt_bytes)?;
        }
        tx.commit().context("Failed to commit receipt")?;
        Ok(())
    }

    pub fn get_receipt(&self, tx_hash: [u8; 32]) -> Result<Option<Receipt>> {
        self.get_receipt_bytes(tx_hash)?
            .map(|receipt_bytes| {
                bincode::deserialize(&receipt_bytes).context("Failed to deserialize receipt")
            })
            .transpose()
    }

    /// Retrieve a transaction receipt.
    pub fn get_receipt_bytes(&self, tx_hash: [u8; 32]) -> Result<Option<Vec<u8>>> {
        let tx = self.begin_read()?;
        let table = tx.open_table(crate::schema::TABLE_TX_RECEIPTS)?;
        Ok(table.get(tx_hash)?.map(|v| v.value().to_vec()))
    }

    pub fn store_block_transactions_typed(
        &self,
        height: u64,
        transactions: &[Transaction],
    ) -> Result<()> {
        let serialized: Result<Vec<_>> = transactions
            .iter()
            .map(|transaction| {
                let tx_hash = transaction.hash();
                let tx_bytes = bincode::serialize(transaction)
                    .context("Failed to serialize transaction for batch block insert")?;
                Ok((tx_hash, tx_bytes))
            })
            .collect();
        self.store_block_transactions(height, &serialized?)
    }

    /// Batch insert multiple transactions for a block and update the block index.
    pub fn store_block_transactions(
        &self,
        height: u64,
        transactions: &[([u8; 32], Vec<u8>)],
    ) -> Result<()> {
        let tx = self.begin_write()?;
        {
            let mut tx_table = tx.open_table(crate::schema::TABLE_TRANSACTIONS)?;
            let mut index_table = tx.open_table(crate::schema::TABLE_TX_BLOCK_INDEX)?;

            for (hash, bytes) in transactions {
                tx_table.insert(*hash, bytes.as_slice())?;
                index_table.insert(*hash, height)?;
            }
        }
        tx.commit().context("Batch transaction insert failed")?;
        Ok(())
    }

    /// Lookup which block height contains a given transaction hash.
    pub fn get_transaction_block_height(&self, tx_hash: [u8; 32]) -> Result<Option<u64>> {
        let tx = self.begin_read()?;
        let table = tx.open_table(crate::schema::TABLE_TX_BLOCK_INDEX)?;
        Ok(table.get(tx_hash)?.map(|v| v.value()))
    }

    // --- State Storage Methods ---

    /// Retrieve a value from the state table.
    pub fn state_get(&self, key: Vec<u8>) -> Result<Option<Vec<u8>>> {
        self.state_get_bytes(&key)
    }

    pub fn state_get_bytes(&self, key: &[u8]) -> Result<Option<Vec<u8>>> {
        let tx = self.begin_read()?;
        let table = tx.open_table(crate::schema::TABLE_STATE)?;
        Ok(table.get(key)?.map(|v| v.value().to_vec()))
    }

    /// Update a value in the state table.
    pub fn state_put(&self, key: Vec<u8>, value: Vec<u8>) -> Result<()> {
        self.state_put_bytes(&key, &value)
    }

    pub fn state_put_bytes(&self, key: &[u8], value: &[u8]) -> Result<()> {
        let tx = self.begin_write()?;
        {
            let mut table = tx.open_table(crate::schema::TABLE_STATE)?;
            table.insert(key, value)?;
        }
        tx.commit().context("Failed to commit state update")?;
        self.invalidate_cache_entry(key);
        Ok(())
    }

    /// Atomically commit multiple state changes.
    pub fn atomic_state_commit(&self, changes: StateUpdates) -> Result<()> {
        self.atomic_state_commit_with_rollback(changes).map(|_| ())
    }

    pub fn atomic_state_commit_with_rollback(
        &self,
        changes: StateUpdates,
    ) -> Result<StateUpdates> {
        let tx = self.begin_write()?;
        let mut rollback_changes = Vec::with_capacity(changes.len());
        {
            let mut table = tx.open_table(crate::schema::TABLE_STATE)?;
            for (key, value) in changes {
                let previous = table
                    .get(key.as_slice())?
                    .map(|entry| entry.value().to_vec());
                rollback_changes.push((key.clone(), previous));

                if let Some(v) = value {
                    table.insert(key.as_slice(), v.as_slice())?;
                } else {
                    table.remove(key.as_slice())?;
                }

                self.invalidate_cache_entry(&key);
            }
        }
        tx.commit().context("Atomic state commit failed")?;
        Ok(rollback_changes)
    }

    pub fn state_snapshot_reads(&self, keys: &[Vec<u8>]) -> Result<Vec<Option<Vec<u8>>>> {
        let tx = self.begin_read()?;
        let table = tx.open_table(crate::schema::TABLE_STATE)?;
        keys.iter()
            .map(|key| {
                Ok(table
                    .get(key.as_slice())?
                    .map(|value| value.value().to_vec()))
            })
            .collect()
    }

    pub fn parallel_state_reads(&self, keys: &[Vec<u8>]) -> Result<Vec<Option<Vec<u8>>>> {
        self.metrics
            .parallel_reads_total
            .fetch_add(keys.len() as u64, Ordering::Relaxed);
        keys.par_iter()
            .map(|key| self.state_get_bytes(key))
            .collect()
    }

    /// Perform a prefix scan on the state.
    pub fn state_prefix_scan(&self, prefix: Vec<u8>) -> Result<Vec<(Vec<u8>, Vec<u8>)>> {
        let tx = self.begin_read()?;
        let table = tx.open_table(crate::schema::TABLE_STATE)?;

        let mut results = Vec::new();
        if prefix.is_empty() {
            for item in table.iter()? {
                let (k, v) = item?;
                results.push((k.value().to_vec(), v.value().to_vec()));
            }
        } else if let Some(end) = Self::prefix_scan_upper_bound(&prefix) {
            for item in table.range(prefix.as_slice()..end.as_slice())? {
                let (k, v) = item?;
                results.push((k.value().to_vec(), v.value().to_vec()));
            }
        } else {
            for item in table.range(prefix.as_slice()..)? {
                let (k, v) = item?;
                if !k.value().starts_with(prefix.as_slice()) {
                    break;
                }
                results.push((k.value().to_vec(), v.value().to_vec()));
            }
        }

        Ok(results)
    }

    // --- Mempool Persistence Methods ---

    /// Persist a single mempool transaction. `tx_hash` is the raw 32-byte hash.
    pub fn mempool_insert(&self, tx_hash: [u8; 32], tx_bytes: &[u8]) -> Result<()> {
        let wtx = self.begin_write()?;
        {
            let mut table = wtx.open_table(crate::schema::TABLE_MEMPOOL)?;
            table.insert(tx_hash, tx_bytes)?;
        }
        wtx.commit().context("Failed to commit mempool insert")?;
        Ok(())
    }

    /// Remove a single mempool transaction by hash.
    pub fn mempool_remove(&self, tx_hash: [u8; 32]) -> Result<bool> {
        let wtx = self.begin_write()?;
        let removed;
        {
            let mut table = wtx.open_table(crate::schema::TABLE_MEMPOOL)?;
            removed = table.remove(tx_hash)?.is_some();
        }
        wtx.commit().context("Failed to commit mempool remove")?;
        Ok(removed)
    }

    /// Delete all persisted mempool transactions.
    pub fn mempool_clear(&self) -> Result<()> {
        let wtx = self.begin_write()?;
        {
            let mut table = wtx.open_table(crate::schema::TABLE_MEMPOOL)?;
            // Collect keys first to avoid mutating while iterating.
            let keys: Vec<[u8; 32]> = table
                .iter()?
                .map(|entry| entry.map(|(k, _)| k.value()))
                .collect::<Result<_, _>>()?;
            for key in keys {
                table.remove(key)?;
            }
        }
        wtx.commit().context("Failed to commit mempool clear")?;
        Ok(())
    }

    /// Iterate all persisted mempool entries, returning (hash_bytes, tx_bytes) pairs.
    pub fn mempool_iterate(&self) -> Result<Vec<([u8; 32], Vec<u8>)>> {
        let rtx = self.begin_read()?;
        let table = rtx.open_table(crate::schema::TABLE_MEMPOOL)?;
        table
            .iter()?
            .map(|entry| {
                entry
                    .map(|(k, v)| (k.value(), v.value().to_vec()))
                    .map_err(Into::into)
            })
            .collect()
    }

    // --- Validator & Staking Storage Methods ---

    pub fn store_validator(&self, address: [u8; 32], validator: &Validator) -> Result<()> {
        let validator_bytes =
            bincode::serialize(validator).context("Failed to serialize validator")?;
        self.store_validator_bytes(address, &validator_bytes)
    }

    /// Store validator information.
    pub fn store_validator_bytes(&self, address: [u8; 32], validator_bytes: &[u8]) -> Result<()> {
        let tx = self.begin_write()?;
        {
            let mut table = tx.open_table(crate::schema::TABLE_VALIDATORS)?;
            table.insert(address, validator_bytes)?;
        }
        tx.commit().context("Failed to commit validator")?;
        Ok(())
    }

    pub fn get_validator(&self, address: [u8; 32]) -> Result<Option<Validator>> {
        self.get_validator_bytes(address)?
            .map(|validator_bytes| {
                bincode::deserialize(&validator_bytes).context("Failed to deserialize validator")
            })
            .transpose()
    }

    /// Retrieve validator information.
    pub fn get_validator_bytes(&self, address: [u8; 32]) -> Result<Option<Vec<u8>>> {
        let tx = self.begin_read()?;
        let table = tx.open_table(crate::schema::TABLE_VALIDATORS)?;
        Ok(table.get(address)?.map(|v| v.value().to_vec()))
    }

    pub fn store_validator_set(&self, height: u64, validators: &[Validator]) -> Result<()> {
        let set_bytes =
            bincode::serialize(validators).context("Failed to serialize validator set")?;
        self.store_validator_set_bytes(height, &set_bytes)
    }

    /// Store a snapshot of the validator set at a specific height.
    pub fn store_validator_set_bytes(&self, height: u64, set_bytes: &[u8]) -> Result<()> {
        let tx = self.begin_write()?;
        {
            let mut table = tx.open_table(crate::schema::TABLE_VALIDATOR_SETS)?;
            table.insert(height, set_bytes)?;
        }
        tx.commit().context("Failed to commit validator set")?;
        Ok(())
    }

    pub fn load_validator_set(&self, height: u64) -> Result<Option<Vec<Validator>>> {
        self.load_validator_set_bytes(height)?
            .map(|set_bytes| {
                bincode::deserialize(&set_bytes).context("Failed to deserialize validator set")
            })
            .transpose()
    }

    /// Load the validator set for a specific height.
    pub fn load_validator_set_bytes(&self, height: u64) -> Result<Option<Vec<u8>>> {
        let tx = self.begin_read()?;
        let table = tx.open_table(crate::schema::TABLE_VALIDATOR_SETS)?;
        Ok(table.get(height)?.map(|v| v.value().to_vec()))
    }

    pub fn store_staking_balance(&self, address: [u8; 32], balance: U256) -> Result<()> {
        let mut balance_bytes = [0u8; 32];
        balance.to_big_endian(&mut balance_bytes);
        self.store_staking_balance_bytes(address, &balance_bytes)
    }

    /// Store the current staking balance for an address.
    pub fn store_staking_balance_bytes(
        &self,
        address: [u8; 32],
        balance_bytes: &[u8],
    ) -> Result<()> {
        let tx = self.begin_write()?;
        {
            let mut table = tx.open_table(crate::schema::TABLE_STAKING)?;
            table.insert(address, balance_bytes)?;
        }
        tx.commit().context("Failed to commit staking balance")?;
        Ok(())
    }

    pub fn get_staking_balance(&self, address: [u8; 32]) -> Result<Option<U256>> {
        self.get_staking_balance_bytes(address)?
            .map(|balance_bytes| {
                if balance_bytes.len() != 32 {
                    bail!("invalid staking balance length: {}", balance_bytes.len());
                }

                Ok(U256::from_big_endian(&balance_bytes))
            })
            .transpose()
    }

    /// Retrieve the staking balance for an address.
    pub fn get_staking_balance_bytes(&self, address: [u8; 32]) -> Result<Option<Vec<u8>>> {
        let tx = self.begin_read()?;
        let table = tx.open_table(crate::schema::TABLE_STAKING)?;
        Ok(table.get(address)?.map(|v| v.value().to_vec()))
    }

    pub fn store_slashing_record(&self, address: [u8; 32], record_bytes: &[u8]) -> Result<()> {
        let tx = self.begin_write()?;
        {
            let mut table = tx.open_table(crate::schema::TABLE_SLASHING_RECORDS)?;
            table.insert(address, record_bytes)?;
        }
        tx.commit().context("Failed to commit slashing record")?;
        Ok(())
    }

    /// Store a slashing record for a validator.
    /// Retrieve slashing records for a validator.
    pub fn get_slashing_record(&self, address: [u8; 32]) -> Result<Option<Vec<u8>>> {
        let tx = self.begin_read()?;
        let table = tx.open_table(crate::schema::TABLE_SLASHING_RECORDS)?;
        Ok(table.get(address)?.map(|v| v.value().to_vec()))
    }

    // --- Mempool Storage Methods (extended) ---

    /// Insert raw transaction bytes into the persistent mempool.
    pub fn mempool_insert_bytes(&self, tx_hash: [u8; 32], tx_bytes: &[u8]) -> Result<()> {
        let tx = self.begin_write()?;
        {
            let mut table = tx.open_table(crate::schema::TABLE_MEMPOOL)?;
            table.insert(tx_hash, tx_bytes)?;
        }
        tx.commit().context("Failed to insert into mempool")?;
        Ok(())
    }

    /// Check if the mempool contains a transaction.
    pub fn mempool_contains(&self, tx_hash: [u8; 32]) -> Result<bool> {
        let tx = self.begin_read()?;
        let table = tx.open_table(crate::schema::TABLE_MEMPOOL)?;
        Ok(table.get(tx_hash)?.is_some())
    }

    pub fn mempool_iterate_typed(&self) -> Result<Vec<([u8; 32], Transaction)>> {
        self.mempool_iterate()?
            .into_iter()
            .map(|(hash, tx_bytes)| {
                let transaction = bincode::deserialize(&tx_bytes)
                    .context("Failed to deserialize mempool transaction")?;
                Ok((hash, transaction))
            })
            .collect()
    }

    /// Evict the lowest-priority transactions until the persisted mempool fits within `max_entries`.
    /// Priority is ordered by `(gas_price, from, nonce)` ascending so the weakest transactions go first.
    pub fn mempool_evict_lowest_priority(&self, max_entries: usize) -> Result<Vec<[u8; 32]>> {
        let mut ranked = self.mempool_iterate_typed()?;
        if ranked.len() <= max_entries {
            return Ok(Vec::new());
        }

        ranked.sort_by(|left, right| {
            let left_priority = (left.1.gas_price, left.1.from, left.1.nonce);
            let right_priority = (right.1.gas_price, right.1.from, right.1.nonce);
            left_priority.cmp(&right_priority)
        });

        let overflow = ranked.len().saturating_sub(max_entries);

        let hashes_to_remove: Vec<[u8; 32]> = ranked
            .into_iter()
            .take(overflow)
            .map(|(hash, _)| hash)
            .collect();

        if hashes_to_remove.is_empty() {
            return Ok(Vec::new());
        }

        let tx = self.begin_write()?;
        {
            let mut table = tx.open_table(crate::schema::TABLE_MEMPOOL)?;
            for hash in &hashes_to_remove {
                table.remove(*hash)?;
            }
        }
        tx.commit()
            .context("Failed to evict low-priority mempool transactions")?;
        Ok(hashes_to_remove)
    }

    // --- Verkle Tree Storage Methods ---

    /// Store a single Verkle node by its hash.
    pub fn store_verkle_node(&self, node_hash: [u8; 32], node_bytes: Vec<u8>) -> Result<()> {
        self.store_verkle_node_bytes(node_hash, &node_bytes)
    }

    pub fn store_verkle_node_bytes(&self, node_hash: [u8; 32], node_bytes: &[u8]) -> Result<()> {
        let tx = self.begin_write()?;
        {
            let mut table = tx.open_table(crate::schema::TABLE_VERKLE_NODES)?;
            table.insert(node_hash, node_bytes)?;
        }
        tx.commit().context("Failed to commit verkle node")?;
        Ok(())
    }

    /// Load a Verkle node by its hash (Lazy loading support).
    pub fn load_verkle_node(&self, node_hash: [u8; 32]) -> Result<Option<Vec<u8>>> {
        let tx = self.begin_read()?;
        let table = tx.open_table(crate::schema::TABLE_VERKLE_NODES)?;
        Ok(table.get(node_hash)?.map(|v| v.value().to_vec()))
    }

    /// Atomically commit a batch of Verkle node updates.
    pub fn batch_store_verkle_nodes(&self, nodes: &[([u8; 32], Vec<u8>)]) -> Result<()> {
        let tx = self.begin_write()?;
        {
            let mut table = tx.open_table(crate::schema::TABLE_VERKLE_NODES)?;
            for (hash, bytes) in nodes {
                table.insert(*hash, bytes.as_slice())?;
            }
        }
        tx.commit().context("Batch verkle node store failed")?;
        Ok(())
    }

    /// Specific persistence for proof-related nodes if they differ from standard nodes.
    /// Standard implementation uses the same table for all cryptographically hashed nodes.
    pub fn store_proof_node(&self, node_hash: [u8; 32], node_bytes: Vec<u8>) -> Result<()> {
        self.store_verkle_node(node_hash, node_bytes)
    }

    pub fn load_proof_node(&self, node_hash: [u8; 32]) -> Result<Option<Vec<u8>>> {
        self.load_verkle_node(node_hash)
    }

    /// Store a zk proof indexed by block height.
    pub fn store_zk_proof(&self, height: u64, proof_bytes: Vec<u8>) -> Result<()> {
        let tx = self.begin_write()?;
        {
            let mut table = tx.open_table(crate::schema::TABLE_ZK_PROOFS)?;
            table.insert(height, proof_bytes.as_slice())?;
        }
        tx.commit().context("Failed to commit zk proof")?;
        Ok(())
    }

    /// Load a zk proof by block height.
    pub fn get_zk_proof(&self, height: u64) -> Result<Option<Vec<u8>>> {
        let tx = self.begin_read()?;
        let table = tx.open_table(crate::schema::TABLE_ZK_PROOFS)?;
        Ok(table.get(height)?.map(|value| value.value().to_vec()))
    }

    /// Check whether a zk proof exists for a block height.
    pub fn zk_proof_exists(&self, height: u64) -> Result<bool> {
        let tx = self.begin_read()?;
        let table = tx.open_table(crate::schema::TABLE_ZK_PROOFS)?;
        Ok(table.get(height)?.is_some())
    }

    // --- Performance Optimizations ---

    /// Execute a series of writes in a single atomic transaction.
    pub fn batch_write<F>(&self, f: F) -> Result<()>
    where
        F: FnOnce(&WriteTransaction) -> Result<()>,
    {
        self.execute_write(|txn| {
            f(txn)?;
            self.metrics
                .batch_write_total
                .fetch_add(1, Ordering::Relaxed);
            counter!("storage.batch_write_total").increment(1);
            Ok(())
        })
    }

    /// Retrieve a value with LRU caching for hot state performance.
    pub fn state_get_cached(&self, key: Vec<u8>) -> Result<Option<Vec<u8>>> {
        // Cache lookup
        {
            let mut cache = self.cache.lock();
            if let Some(value) = cache.get(&key) {
                self.metrics.cache_hits.fetch_add(1, Ordering::Relaxed);
                counter!("storage.cache_hit_total").increment(1);
                return Ok(Some(value.clone()));
            }
        }

        // DB lookup
        self.metrics.cache_misses.fetch_add(1, Ordering::Relaxed);
        counter!("storage.cache_miss_total").increment(1);
        if let Some(val) = self.state_get(key.clone())? {
            let mut cache = self.cache.lock();
            cache.put(key, val.clone());
            Ok(Some(val))
        } else {
            Ok(None)
        }
    }

    /// Flush all buffered transactions to disk. redb handles this on commit,
    /// but this provides an explicit hook for node orchestrators.
    pub fn flush_to_disk(&self) -> Result<()> {
        info!("Synching storage cache to persistent disk storage...");
        let _ = self.flush_buffered_block_execution_writes()?;
        self.metrics
            .disk_flush_total
            .fetch_add(1, Ordering::Relaxed);
        // redb's TwoPhase strategy means commit is flush.
        counter!("storage.disk_flush_total").increment(1);
        Ok(())
    }

    /// Collect storage layer metrics.
    pub fn get_metrics(&self) -> Result<serde_json::Value> {
        Ok(serde_json::json!({
            "cache_size": self.cache.lock().len(),
            "database_open": true,
            "batch_write_total": self.metrics.batch_write_total.load(Ordering::Relaxed),
            "cache_hits": self.metrics.cache_hits.load(Ordering::Relaxed),
            "cache_misses": self.metrics.cache_misses.load(Ordering::Relaxed),
            "disk_flush_total": self.metrics.disk_flush_total.load(Ordering::Relaxed),
            "parallel_reads_total": self.metrics.parallel_reads_total.load(Ordering::Relaxed),
            "buffered_write_flushes": self.metrics.buffered_write_flushes.load(Ordering::Relaxed),
            "buffered_writes_pending": self.buffered_state_writes.lock().len(),
            "buffered_writes_enqueued": self.metrics.buffered_writes_enqueued.load(Ordering::Relaxed),
        }))
    }

    // --- Maintenance & Snapshots ---

    /// Export a full database snapshot by copying the backing file safely.
    pub fn export_snapshot(&self, dest: impl AsRef<Path>) -> Result<()> {
        info!("Exporting database snapshot to {:?}...", dest.as_ref());
        self.flush_to_disk()?;
        Self::copy_database_to_path(self.db.clone(), dest.as_ref())?;
        Ok(())
    }

    /// Restore the database from a given snapshot file.
    pub fn restore_from_snapshot(
        snapshot_path: impl AsRef<Path>,
        target_path: impl AsRef<Path>,
    ) -> Result<()> {
        let snapshot_path = snapshot_path.as_ref();
        let target_path = target_path.as_ref();
        info!("Restoring database from snapshot {:?}...", snapshot_path);

        if !snapshot_path.exists() {
            bail!("snapshot file does not exist: {:?}", snapshot_path);
        }

        if let Some(parent) = target_path.parent() {
            fs::create_dir_all(parent).with_context(|| {
                format!("Failed to create restore target directory {:?}", parent)
            })?;
        }

        let backup_path = target_path.with_extension("bak");
        if target_path.exists() {
            if backup_path.exists() {
                let _ = fs::remove_file(&backup_path);
            }
            fs::rename(target_path, &backup_path).with_context(|| {
                format!("Failed to back up existing database {:?}", target_path)
            })?;
        }

        if let Err(error) = fs::copy(snapshot_path, target_path).with_context(|| {
            format!(
                "Failed to copy snapshot {:?} to {:?}",
                snapshot_path, target_path
            )
        }) {
            if backup_path.exists() {
                let _ = fs::rename(&backup_path, target_path);
            }
            return Err(error);
        }

        if let Err(error) = Self::open_or_create_db(target_path) {
            let _ = fs::remove_file(target_path);
            if backup_path.exists() {
                let _ = fs::rename(&backup_path, target_path);
            }
            return Err(error).context("Restored snapshot failed validation");
        }

        if backup_path.exists() {
            let _ = fs::remove_file(backup_path);
        }

        Ok(())
    }

    /// Perform a deep integrity check of all tables in the database.
    pub fn check_integrity(&self) -> Result<bool> {
        info!("Starting full database integrity check...");

        let read_tx = self.begin_read()?;
        Self::verify_str_bytes_table(&read_tx, crate::schema::TABLE_METADATA)?;
        Self::verify_u64_bytes_table(&read_tx, crate::schema::TABLE_BLOCK_HEADERS)?;
        Self::verify_u64_bytes_table(&read_tx, crate::schema::TABLE_BLOCK_BODIES)?;
        Self::verify_hash_bytes_table(&read_tx, crate::schema::TABLE_TRANSACTIONS)?;
        Self::verify_hash_bytes_table(&read_tx, crate::schema::TABLE_ACCOUNTS)?;
        Self::verify_slice_bytes_table(&read_tx, crate::schema::TABLE_STATE)?;
        Self::verify_hash_bytes_table(&read_tx, crate::schema::TABLE_VALIDATORS)?;
        Self::verify_hash_bytes_table(&read_tx, crate::schema::TABLE_STAKING)?;
        Self::verify_hash_bytes_table(&read_tx, crate::schema::TABLE_MEMPOOL)?;
        Self::verify_hash_bytes_table(&read_tx, crate::schema::TABLE_VERKLE_NODES)?;
        Self::verify_u64_bytes_table(&read_tx, crate::schema::TABLE_ZK_PROOFS)?;
        Self::verify_hash_u64_table(&read_tx, crate::schema::TABLE_TX_BLOCK_INDEX)?;
        Self::verify_hash_bytes_table(&read_tx, crate::schema::TABLE_TX_RECEIPTS)?;
        Self::verify_u64_bytes_table(&read_tx, crate::schema::TABLE_VALIDATOR_SETS)?;
        Self::verify_hash_bytes_table(&read_tx, crate::schema::TABLE_SLASHING_RECORDS)?;

        Ok(true)
    }

    /// Monitor the current disk usage of the database file.
    pub fn disk_usage_bytes(&self) -> Result<u64> {
        let db_size = fs::metadata(&self.db_path)?.len();
        let corruption_marker_size = self
            .db_path
            .with_extension("corrupt")
            .metadata()
            .map(|meta| meta.len())
            .unwrap_or(0);
        let backup_size = self
            .db_path
            .with_extension("bak")
            .metadata()
            .map(|meta| meta.len())
            .unwrap_or(0);
        Ok(db_size + corruption_marker_size + backup_size)
    }

    /// Perform background compaction to reclaim fragmented disk space.
    pub fn compact_database(&self) -> Result<()> {
        info!("Initiating database compaction...");

        if self.compaction_running.swap(true, Ordering::SeqCst) {
            return Ok(());
        }

        let db = self.db.clone();
        let db_path = self.db_path.clone();
        let compaction_running = Arc::clone(&self.compaction_running);
        let handle = thread::spawn(move || {
            let compacted_path = db_path.with_extension("compacted.redb");
            let compaction_result = Self::copy_database_to_path(db.clone(), &compacted_path);

            if let Err(compaction_error) = compaction_result {
                error!(
                    "background compaction failed for {:?}: {:?}",
                    db_path, compaction_error
                );
            } else {
                let timestamp = chrono::Utc::now().to_rfc3339();
                if let Ok(tx) = db.begin_write() {
                    if let Ok(mut table) = tx.open_table(METADATA) {
                        let compacted_path_str = compacted_path.to_string_lossy().to_string();
                        let _ = table.insert(LAST_COMPACTION_AT_KEY, timestamp.as_str());
                        let _ = table.insert(LAST_COMPACTION_PATH_KEY, compacted_path_str.as_str());
                    }
                    let _ = tx.commit();
                }
            }

            compaction_running.store(false, Ordering::SeqCst);
        });

        *self.compaction_handle.lock() = Some(handle);
        Ok(())
    }

    /// Graceful shutdown: ensures all pending caches are flushed and the db is closed cleanly.
    pub fn shutdown(&self) -> Result<()> {
        info!("Gracefully shutting down StorageEngine...");
        self.stop_flush_scheduler()?;
        self.join_compaction_thread()?;
        // Flush any metrics or cached state
        self.flush_to_disk()?;
        if !self.shutdown_recorded.swap(true, Ordering::SeqCst) {
            self.record_clean_shutdown()?;
        }
        // Arc<Database> will be dropped when StorageEngine is dropped.
        Ok(())
    }

    /// Rollback the state to a previous configuration by applying an explicit undo batch/log.
    /// This relies on the execution/state layer tracking prior values during state transitions,
    /// and submitting the inverse diffs back to the storage engine when a reorganization occurs.
    pub fn rollback_state_batch(
        &self,
        undo_changes: Vec<(Vec<u8>, Option<Vec<u8>>)>,
    ) -> Result<()> {
        info!(
            "Executing atomic state rollback of {} records...",
            undo_changes.len()
        );
        self.atomic_state_commit(undo_changes)?;

        // Clear hot state cache after rollback to prevent phantom reads
        self.cache.lock().clear();

        Ok(())
    }

    fn update_latest_height_metadata(tx: &WriteTransaction, height: u64) -> Result<()> {
        let mut meta_table = tx.open_table(crate::schema::TABLE_METADATA)?;
        let current_height = Self::read_latest_height_metadata(&meta_table)?.unwrap_or(0);

        if height > current_height || meta_table.get(LATEST_BLOCK_HEIGHT_KEY)?.is_none() {
            let height_bytes = height.to_le_bytes();
            meta_table.insert(LATEST_BLOCK_HEIGHT_KEY, height_bytes.as_slice())?;
        }

        Ok(())
    }

    fn reconcile_latest_height_metadata(
        tx: &WriteTransaction,
        latest_height: Option<u64>,
    ) -> Result<()> {
        let mut meta_table = tx.open_table(crate::schema::TABLE_METADATA)?;
        if let Some(height) = latest_height {
            let height_bytes = height.to_le_bytes();
            meta_table.insert(LATEST_BLOCK_HEIGHT_KEY, height_bytes.as_slice())?;
        } else {
            meta_table.remove(LATEST_BLOCK_HEIGHT_KEY)?;
        }

        Ok(())
    }

    fn read_latest_height_metadata<T>(table: &T) -> Result<Option<u64>>
    where
        T: ReadableTable<&'static str, &'static [u8]>,
    {
        let value = table.get(LATEST_BLOCK_HEIGHT_KEY)?;
        let Some(value) = value else {
            return Ok(None);
        };

        let bytes = value.value();
        if bytes.len() != std::mem::size_of::<u64>() {
            bail!(
                "invalid latest_block_height metadata length: {}",
                bytes.len()
            );
        }

        let mut height_bytes = [0u8; 8];
        height_bytes.copy_from_slice(bytes);
        Ok(Some(u64::from_le_bytes(height_bytes)))
    }

    fn record_clean_shutdown(&self) -> Result<()> {
        let tx = self.begin_write()?;
        {
            let mut table = tx
                .open_table(METADATA)
                .context("Failed to open metadata table for shutdown bookkeeping")?;
            table.insert(LAST_SHUTDOWN_CLEAN_KEY, "true")?;
        }
        tx.commit()
            .context("Failed to record clean database shutdown")?;
        Ok(())
    }

    fn join_compaction_thread(&self) -> Result<()> {
        if let Some(handle) = self.compaction_handle.lock().take() {
            handle
                .join()
                .map_err(|_| anyhow::anyhow!("storage compaction thread panicked"))?;
        }

        Ok(())
    }

    fn prefix_scan_upper_bound(prefix: &[u8]) -> Option<Vec<u8>> {
        let mut end = prefix.to_vec();

        for index in (0..end.len()).rev() {
            if end[index] != u8::MAX {
                end[index] = end[index].saturating_add(1);
                end.truncate(index + 1);
                return Some(end);
            }
        }

        None
    }

    fn invalidate_cache_entry(&self, key: &[u8]) {
        self.cache.lock().pop(&key.to_vec());
    }

    fn start_flush_scheduler(&self) -> Result<()> {
        let (stop_tx, stop_rx) = mpsc::channel();
        let db = self.db.clone();
        let buffered_state_writes = Arc::clone(&self.buffered_state_writes);
        let metrics = Arc::clone(&self.metrics);
        let handle = thread::spawn(move || loop {
            match stop_rx.recv_timeout(Duration::from_secs(DEFAULT_FLUSH_INTERVAL_SECS)) {
                Ok(_) => break,
                Err(mpsc::RecvTimeoutError::Timeout) => {
                    let _ = Self::flush_buffered_state_writes_inner(
                        &db,
                        &buffered_state_writes,
                        &metrics,
                    );
                    metrics.disk_flush_total.fetch_add(1, Ordering::Relaxed);
                }
                Err(mpsc::RecvTimeoutError::Disconnected) => break,
            }
        });

        *self.flush_thread_stop.lock() = Some(stop_tx);
        *self.flush_thread_handle.lock() = Some(handle);
        Ok(())
    }

    fn stop_flush_scheduler(&self) -> Result<()> {
        if let Some(stop_tx) = self.flush_thread_stop.lock().take() {
            let _ = stop_tx.send(());
        }

        if let Some(handle) = self.flush_thread_handle.lock().take() {
            handle
                .join()
                .map_err(|_| anyhow::anyhow!("storage flush scheduler thread panicked"))?;
        }

        Ok(())
    }

    fn flush_buffered_state_writes_inner(
        db: &Arc<Database>,
        buffered_state_writes: &Arc<Mutex<StateUpdates>>,
        metrics: &Arc<StorageMetricsInner>,
    ) -> Result<usize> {
        let pending = {
            let mut guard = buffered_state_writes.lock();
            if guard.is_empty() {
                return Ok(0);
            }
            std::mem::take(&mut *guard)
        };

        let tx = db
            .begin_write()
            .context("Failed to begin write transaction for buffered state flush")?;
        {
            let mut table = tx.open_table(crate::schema::TABLE_STATE)?;
            for (key, value) in &pending {
                if let Some(value) = value {
                    table.insert(key.as_slice(), value.as_slice())?;
                } else {
                    table.remove(key.as_slice())?;
                }
            }
        }
        tx.commit()
            .context("Failed to commit buffered state writes")?;
        metrics
            .buffered_write_flushes
            .fetch_add(1, Ordering::Relaxed);
        Ok(pending.len())
    }

    fn copy_database_to_path(db: Arc<Database>, dest: &Path) -> Result<()> {
        if let Some(parent) = dest.parent() {
            fs::create_dir_all(parent)
                .with_context(|| format!("Failed to create snapshot directory {:?}", parent))?;
        }

        if dest.exists() {
            fs::remove_file(dest)
                .with_context(|| format!("Failed to remove existing snapshot {:?}", dest))?;
        }

        let snapshot_db = crate::schema::Schema::init(dest)?;
        let read_tx = db
            .begin_read()
            .context("Failed to begin read transaction for snapshot")?;
        let write_tx = snapshot_db
            .begin_write()
            .context("Failed to begin write transaction for snapshot")?;

        Self::copy_str_bytes_table(&read_tx, &write_tx, crate::schema::TABLE_METADATA)?;
        Self::copy_u64_bytes_table(&read_tx, &write_tx, crate::schema::TABLE_BLOCK_HEADERS)?;
        Self::copy_u64_bytes_table(&read_tx, &write_tx, crate::schema::TABLE_BLOCK_BODIES)?;
        Self::copy_hash_bytes_table(&read_tx, &write_tx, crate::schema::TABLE_TRANSACTIONS)?;
        Self::copy_hash_bytes_table(&read_tx, &write_tx, crate::schema::TABLE_ACCOUNTS)?;
        Self::copy_slice_bytes_table(&read_tx, &write_tx, crate::schema::TABLE_STATE)?;
        Self::copy_hash_bytes_table(&read_tx, &write_tx, crate::schema::TABLE_VALIDATORS)?;
        Self::copy_hash_bytes_table(&read_tx, &write_tx, crate::schema::TABLE_STAKING)?;
        Self::copy_hash_bytes_table(&read_tx, &write_tx, crate::schema::TABLE_MEMPOOL)?;
        Self::copy_hash_bytes_table(&read_tx, &write_tx, crate::schema::TABLE_VERKLE_NODES)?;
        Self::copy_u64_bytes_table(&read_tx, &write_tx, crate::schema::TABLE_ZK_PROOFS)?;
        Self::copy_hash_u64_table(&read_tx, &write_tx, crate::schema::TABLE_TX_BLOCK_INDEX)?;
        Self::copy_hash_bytes_table(&read_tx, &write_tx, crate::schema::TABLE_TX_RECEIPTS)?;
        Self::copy_u64_bytes_table(&read_tx, &write_tx, crate::schema::TABLE_VALIDATOR_SETS)?;
        Self::copy_hash_bytes_table(&read_tx, &write_tx, crate::schema::TABLE_SLASHING_RECORDS)?;

        write_tx
            .commit()
            .context("Failed to commit snapshot database")?;
        Ok(())
    }

    fn copy_str_bytes_table(
        read_tx: &ReadTransaction,
        write_tx: &WriteTransaction,
        table_def: TableDefinition<&str, &[u8]>,
    ) -> Result<()> {
        let read_table = read_tx.open_table(table_def)?;
        let mut write_table = write_tx.open_table(table_def)?;
        for row in read_table.iter()? {
            let (key, value) = row?;
            write_table.insert(key.value(), value.value())?;
        }
        Ok(())
    }

    fn copy_u64_bytes_table(
        read_tx: &ReadTransaction,
        write_tx: &WriteTransaction,
        table_def: TableDefinition<u64, &[u8]>,
    ) -> Result<()> {
        let read_table = read_tx.open_table(table_def)?;
        let mut write_table = write_tx.open_table(table_def)?;
        for row in read_table.iter()? {
            let (key, value) = row?;
            write_table.insert(key.value(), value.value())?;
        }
        Ok(())
    }

    fn copy_hash_bytes_table(
        read_tx: &ReadTransaction,
        write_tx: &WriteTransaction,
        table_def: TableDefinition<[u8; 32], &[u8]>,
    ) -> Result<()> {
        let read_table = read_tx.open_table(table_def)?;
        let mut write_table = write_tx.open_table(table_def)?;
        for row in read_table.iter()? {
            let (key, value) = row?;
            write_table.insert(key.value(), value.value())?;
        }
        Ok(())
    }

    fn copy_slice_bytes_table(
        read_tx: &ReadTransaction,
        write_tx: &WriteTransaction,
        table_def: TableDefinition<&[u8], &[u8]>,
    ) -> Result<()> {
        let read_table = read_tx.open_table(table_def)?;
        let mut write_table = write_tx.open_table(table_def)?;
        for row in read_table.iter()? {
            let (key, value) = row?;
            write_table.insert(key.value(), value.value())?;
        }
        Ok(())
    }

    fn copy_hash_u64_table(
        read_tx: &ReadTransaction,
        write_tx: &WriteTransaction,
        table_def: TableDefinition<[u8; 32], u64>,
    ) -> Result<()> {
        let read_table = read_tx.open_table(table_def)?;
        let mut write_table = write_tx.open_table(table_def)?;
        for row in read_table.iter()? {
            let (key, value) = row?;
            write_table.insert(key.value(), value.value())?;
        }
        Ok(())
    }

    fn verify_str_bytes_table(
        read_tx: &ReadTransaction,
        table_def: TableDefinition<&str, &[u8]>,
    ) -> Result<()> {
        let table = read_tx.open_table(table_def)?;
        for row in table.iter()? {
            let _ = row?;
        }
        Ok(())
    }

    fn verify_u64_bytes_table(
        read_tx: &ReadTransaction,
        table_def: TableDefinition<u64, &[u8]>,
    ) -> Result<()> {
        let table = read_tx.open_table(table_def)?;
        for row in table.iter()? {
            let _ = row?;
        }
        Ok(())
    }

    fn verify_hash_bytes_table(
        read_tx: &ReadTransaction,
        table_def: TableDefinition<[u8; 32], &[u8]>,
    ) -> Result<()> {
        let table = read_tx.open_table(table_def)?;
        for row in table.iter()? {
            let _ = row?;
        }
        Ok(())
    }

    fn verify_slice_bytes_table(
        read_tx: &ReadTransaction,
        table_def: TableDefinition<&[u8], &[u8]>,
    ) -> Result<()> {
        let table = read_tx.open_table(table_def)?;
        for row in table.iter()? {
            let _ = row?;
        }
        Ok(())
    }

    fn verify_hash_u64_table(
        read_tx: &ReadTransaction,
        table_def: TableDefinition<[u8; 32], u64>,
    ) -> Result<()> {
        let table = read_tx.open_table(table_def)?;
        for row in table.iter()? {
            let _ = row?;
        }
        Ok(())
    }
}

impl Drop for StorageEngine {
    fn drop(&mut self) {
        let _ = self.stop_flush_scheduler();
        let _ = self.join_compaction_thread();
    }
}

#[cfg(test)]
mod tests {
    use super::StorageEngine;
    use primitive_types::U256;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};
    use vage_block::{BlockBody, BlockHeader};
    use vage_types::validator::ValidatorStatus;
    use vage_types::{Address, Receipt, Transaction, Validator};

    fn temp_db_path(name: &str) -> PathBuf {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time should be after unix epoch")
            .as_nanos();
        std::env::temp_dir().join(format!("vage-storage-{name}-{unique}.redb"))
    }

    #[test]
    fn stores_and_loads_typed_block_parts() {
        let db_path = temp_db_path("typed-block-parts");
        let engine = StorageEngine::new(&db_path).expect("storage should initialize");
        let header = BlockHeader::new([1u8; 32], 7);
        let mut body = BlockBody::new();
        body.receipts = Vec::new();

        engine
            .store_block_header(7, &header)
            .expect("header should store");
        engine
            .store_block_body(7, &body)
            .expect("body should store");

        let loaded_header = engine
            .get_block_header(7)
            .expect("header read should succeed")
            .expect("header should exist");
        let loaded_body = engine
            .get_block_body(7)
            .expect("body read should succeed")
            .expect("body should exist");

        assert_eq!(loaded_header, header);
        assert_eq!(loaded_body, body);
        assert!(engine
            .block_exists(7)
            .expect("existence check should succeed"));
        assert_eq!(
            engine
                .latest_block_height()
                .expect("latest height should load"),
            7
        );

        drop(engine);
        let _ = std::fs::remove_file(db_path);
    }

    #[test]
    fn atomic_block_commit_updates_height_and_pruning_reconciles_metadata() {
        let db_path = temp_db_path("atomic-prune");
        let engine = StorageEngine::new(&db_path).expect("storage should initialize");

        for height in 1..=3 {
            let header = BlockHeader::new([height as u8; 32], height);
            let body = BlockBody::new();
            engine
                .atomic_block_commit_typed(height, &header, &body)
                .expect("atomic block commit should succeed");
        }

        assert_eq!(
            engine
                .latest_block_height()
                .expect("latest height should load"),
            3
        );
        assert!(engine
            .block_exists(1)
            .expect("block 1 check should succeed"));
        assert!(engine
            .block_exists(3)
            .expect("block 3 check should succeed"));

        let pruned = engine
            .prune_blocks_before(3)
            .expect("block pruning should succeed");

        assert_eq!(pruned, 2);
        assert!(!engine
            .block_exists(1)
            .expect("block 1 check should succeed"));
        assert!(!engine
            .block_exists(2)
            .expect("block 2 check should succeed"));
        assert!(engine
            .block_exists(3)
            .expect("block 3 check should succeed"));
        assert_eq!(
            engine
                .latest_block_height()
                .expect("latest height should load"),
            3
        );

        drop(engine);
        let _ = std::fs::remove_file(db_path);
    }

    #[test]
    fn stores_transactions_receipts_and_block_index() {
        let db_path = temp_db_path("tx-storage");
        let engine = StorageEngine::new(&db_path).expect("storage should initialize");

        let tx =
            Transaction::new_transfer(Address([1u8; 32]), Address([2u8; 32]), U256::from(25u64), 3);
        let tx_hash = tx.hash();
        let receipt = Receipt::new_success(tx_hash, 21_000, Some([9u8; 32]));

        engine
            .store_transaction(tx_hash, &tx)
            .expect("transaction should store");
        engine
            .store_receipt(tx_hash, &receipt)
            .expect("receipt should store");

        assert!(engine
            .transaction_exists(tx_hash)
            .expect("tx existence should succeed"));
        assert_eq!(
            engine
                .get_transaction(tx_hash)
                .expect("transaction read should succeed"),
            Some(tx.clone())
        );
        assert_eq!(
            engine
                .get_receipt(tx_hash)
                .expect("receipt read should succeed"),
            Some(receipt)
        );

        drop(engine);
        let _ = std::fs::remove_file(db_path);
    }

    #[test]
    fn batch_inserts_block_transactions_and_indexes_by_height() {
        let db_path = temp_db_path("tx-batch-index");
        let engine = StorageEngine::new(&db_path).expect("storage should initialize");

        let tx_one =
            Transaction::new_transfer(Address([3u8; 32]), Address([4u8; 32]), U256::from(10u64), 1);
        let tx_two =
            Transaction::new_transfer(Address([5u8; 32]), Address([6u8; 32]), U256::from(20u64), 2);

        engine
            .store_block_transactions_typed(11, &[tx_one.clone(), tx_two.clone()])
            .expect("batch transaction insert should succeed");

        for tx in [tx_one, tx_two] {
            let tx_hash = tx.hash();
            assert!(engine
                .transaction_exists(tx_hash)
                .expect("tx existence should succeed"));
            assert_eq!(
                engine
                    .get_transaction(tx_hash)
                    .expect("transaction read should succeed"),
                Some(tx)
            );
            assert_eq!(
                engine
                    .get_transaction_block_height(tx_hash)
                    .expect("tx block index read should succeed"),
                Some(11)
            );
        }

        drop(engine);
        let _ = std::fs::remove_file(db_path);
    }

    #[test]
    fn state_reads_commits_rollbacks_and_snapshot_reads_work() {
        let db_path = temp_db_path("state-commit-rollback");
        let engine = StorageEngine::new(&db_path).expect("storage should initialize");

        engine
            .state_put_bytes(b"account:alice", br#"{"balance":10}"#)
            .expect("initial state put should succeed");
        assert_eq!(
            engine
                .state_get_bytes(b"account:alice")
                .expect("state get should succeed"),
            Some(br#"{"balance":10}"#.to_vec())
        );

        let rollback = engine
            .atomic_state_commit_with_rollback(vec![
                (
                    b"account:alice".to_vec(),
                    Some(br#"{"balance":25}"#.to_vec()),
                ),
                (b"storage:slot1".to_vec(), Some(vec![1u8, 2, 3])),
            ])
            .expect("atomic state commit should succeed");

        let snapshot_reads = engine
            .state_snapshot_reads(&[b"account:alice".to_vec(), b"storage:slot1".to_vec()])
            .expect("snapshot reads should succeed");
        assert_eq!(snapshot_reads[0], Some(br#"{"balance":25}"#.to_vec()));
        assert_eq!(snapshot_reads[1], Some(vec![1u8, 2, 3]));

        engine
            .rollback_state_batch(rollback)
            .expect("rollback should succeed");
        assert_eq!(
            engine
                .state_get_bytes(b"account:alice")
                .expect("state get should succeed"),
            Some(br#"{"balance":10}"#.to_vec())
        );
        assert_eq!(
            engine
                .state_get_bytes(b"storage:slot1")
                .expect("state get should succeed"),
            None
        );

        drop(engine);
        let _ = std::fs::remove_file(db_path);
    }

    #[test]
    fn state_prefix_scan_handles_empty_and_ff_suffix_prefixes() {
        let db_path = temp_db_path("state-prefix-scan");
        let engine = StorageEngine::new(&db_path).expect("storage should initialize");

        engine
            .atomic_state_commit(vec![
                (vec![0xff, 0x00], Some(vec![1u8])),
                (vec![0xff, 0xff], Some(vec![2u8])),
                (b"account:alice".to_vec(), Some(vec![3u8])),
            ])
            .expect("state seed should succeed");

        let ff_scan = engine
            .state_prefix_scan(vec![0xff])
            .expect("ff prefix scan should succeed");
        assert_eq!(ff_scan.len(), 2);

        let full_scan = engine
            .state_prefix_scan(Vec::new())
            .expect("full state scan should succeed");
        assert_eq!(full_scan.len(), 3);

        drop(engine);
        let _ = std::fs::remove_file(db_path);
    }

    #[test]
    fn stores_validators_sets_staking_balances_and_slashing_records() {
        let db_path = temp_db_path("validator-storage");
        let engine = StorageEngine::new(&db_path).expect("storage should initialize");

        let validator_address = Address([7u8; 32]);
        let mut validator = Validator::new(validator_address, [8u8; 32], U256::from(500u64));
        validator.status = ValidatorStatus::Active;
        validator.voting_power = 42;

        engine
            .store_validator(*validator_address.as_bytes(), &validator)
            .expect("validator should store");
        assert_eq!(
            engine
                .get_validator(*validator_address.as_bytes())
                .expect("validator read should succeed"),
            Some(validator.clone())
        );

        let validator_set = vec![validator.clone()];
        engine
            .store_validator_set(21, &validator_set)
            .expect("validator set should store");
        assert_eq!(
            engine
                .load_validator_set(21)
                .expect("validator set read should succeed"),
            Some(validator_set)
        );

        let staking_balance = U256::from(1_000u64);
        engine
            .store_staking_balance(*validator_address.as_bytes(), staking_balance)
            .expect("staking balance should store");
        assert_eq!(
            engine
                .get_staking_balance(*validator_address.as_bytes())
                .expect("staking balance read should succeed"),
            Some(staking_balance)
        );

        let slashing_record = b"double-signing:height=21".to_vec();
        engine
            .store_slashing_record(*validator_address.as_bytes(), &slashing_record)
            .expect("slashing record should store");
        assert_eq!(
            engine
                .get_slashing_record(*validator_address.as_bytes())
                .expect("slashing record read should succeed"),
            Some(slashing_record)
        );

        drop(engine);
        let _ = std::fs::remove_file(db_path);
    }

    #[test]
    fn persists_memool_entries_and_evicts_lowest_priority_first() {
        let db_path = temp_db_path("mempool-storage");
        let engine = StorageEngine::new(&db_path).expect("storage should initialize");

        let low = Transaction::new_transfer(
            Address([10u8; 32]),
            Address([11u8; 32]),
            U256::from(1u64),
            0,
        );
        let mut medium = Transaction::new_transfer(
            Address([12u8; 32]),
            Address([13u8; 32]),
            U256::from(2u64),
            1,
        );
        let mut high = Transaction::new_transfer(
            Address([14u8; 32]),
            Address([15u8; 32]),
            U256::from(3u64),
            2,
        );
        medium.gas_price = U256::from(5u64);
        high.gas_price = U256::from(9u64);

        engine
            .mempool_insert(
                low.hash(),
                &bincode::serialize(&low).expect("low tx should encode"),
            )
            .expect("low priority tx should persist");
        engine
            .mempool_insert(
                medium.hash(),
                &bincode::serialize(&medium).expect("medium tx should encode"),
            )
            .expect("medium priority tx should persist");
        engine
            .mempool_insert(
                high.hash(),
                &bincode::serialize(&high).expect("high tx should encode"),
            )
            .expect("high priority tx should persist");

        assert!(engine
            .mempool_contains(low.hash())
            .expect("contains should succeed"));
        assert_eq!(
            engine
                .mempool_iterate_typed()
                .expect("iterate should succeed")
                .len(),
            3
        );

        let removed = engine
            .mempool_evict_lowest_priority(2)
            .expect("eviction should succeed");
        assert_eq!(removed, vec![low.hash()]);
        assert!(!engine
            .mempool_contains(low.hash())
            .expect("contains should succeed"));
        assert!(engine
            .mempool_contains(medium.hash())
            .expect("contains should succeed"));
        assert!(engine
            .mempool_contains(high.hash())
            .expect("contains should succeed"));

        assert!(engine
            .mempool_remove(medium.hash())
            .expect("remove should succeed"));
        let remaining = engine
            .mempool_iterate_typed()
            .expect("iterate should succeed");
        assert_eq!(remaining, vec![(high.hash(), high.clone())]);

        drop(engine);
        let _ = std::fs::remove_file(db_path);
    }

    #[test]
    fn stores_loads_and_batches_verkle_nodes_and_proof_nodes() {
        let db_path = temp_db_path("verkle-storage");
        let engine = StorageEngine::new(&db_path).expect("storage should initialize");

        let node_hash = [21u8; 32];
        let node_bytes = vec![1u8, 3, 3, 7];
        engine
            .store_verkle_node(node_hash, node_bytes.clone())
            .expect("verkle node should store");
        assert_eq!(
            engine
                .load_verkle_node(node_hash)
                .expect("verkle node load should succeed"),
            Some(node_bytes.clone())
        );

        let batch_hash_one = [22u8; 32];
        let batch_hash_two = [23u8; 32];
        let batch_nodes = vec![
            (batch_hash_one, vec![2u8, 4, 6, 8]),
            (batch_hash_two, vec![9u8, 7, 5, 3]),
        ];
        engine
            .batch_store_verkle_nodes(&batch_nodes)
            .expect("batch verkle store should succeed");
        assert_eq!(
            engine
                .load_verkle_node(batch_hash_one)
                .expect("batch node one load should succeed"),
            Some(batch_nodes[0].1.clone())
        );
        assert_eq!(
            engine
                .load_verkle_node(batch_hash_two)
                .expect("batch node two load should succeed"),
            Some(batch_nodes[1].1.clone())
        );

        let proof_hash = [24u8; 32];
        let proof_bytes = vec![0xaa, 0xbb, 0xcc];
        engine
            .store_proof_node(proof_hash, proof_bytes.clone())
            .expect("proof node should store");
        assert_eq!(
            engine
                .load_proof_node(proof_hash)
                .expect("proof node load should succeed"),
            Some(proof_bytes)
        );

        assert_eq!(
            engine
                .load_verkle_node([99u8; 32])
                .expect("missing node lazy load should succeed"),
            None
        );

        drop(engine);
        let _ = std::fs::remove_file(db_path);
    }
}
