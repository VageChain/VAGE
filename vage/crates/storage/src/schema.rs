use anyhow::{Context, Result};
use redb::{Database, TableDefinition};
use std::path::Path;

/// Core blockchain tables
pub const TABLE_BLOCK_HEADERS: TableDefinition<u64, &[u8]> =
    TableDefinition::new("block_headers");
pub const TABLE_BLOCK_BODIES: TableDefinition<u64, &[u8]> = TableDefinition::new("block_bodies");
pub const TABLE_TRANSACTIONS: TableDefinition<[u8; 32], &[u8]> =
    TableDefinition::new("transactions");
pub const TABLE_ACCOUNTS: TableDefinition<[u8; 32], &[u8]> = TableDefinition::new("accounts");
pub const TABLE_STATE: TableDefinition<&[u8], &[u8]> = TableDefinition::new("state");
pub const TABLE_VALIDATORS: TableDefinition<[u8; 32], &[u8]> = TableDefinition::new("validators");
pub const TABLE_STAKING: TableDefinition<[u8; 32], &[u8]> = TableDefinition::new("staking");
pub const TABLE_MEMPOOL: TableDefinition<[u8; 32], &[u8]> = TableDefinition::new("mempool");
pub const TABLE_METADATA: TableDefinition<&str, &[u8]> = TableDefinition::new("metadata_v2");
pub const TABLE_VERKLE_NODES: TableDefinition<[u8; 32], &[u8]> =
    TableDefinition::new("verkle_nodes_v2");
pub const TABLE_ZK_PROOFS: TableDefinition<u64, &[u8]> = TableDefinition::new("zk_proofs");
pub const TABLE_TX_BLOCK_INDEX: TableDefinition<[u8; 32], u64> =
    TableDefinition::new("tx_block_index");
pub const TABLE_TX_RECEIPTS: TableDefinition<[u8; 32], &[u8]> =
    TableDefinition::new("tx_receipts");
pub const TABLE_VALIDATOR_SETS: TableDefinition<u64, &[u8]> =
    TableDefinition::new("validator_sets");
pub const TABLE_SLASHING_RECORDS: TableDefinition<[u8; 32], &[u8]> =
    TableDefinition::new("slashing_records");

pub struct Schema;

impl Schema {
    /// Initialize the database and ensure all static tables exist.
    pub fn init(db_path: impl AsRef<Path>) -> Result<Database> {
        let db = Database::builder()
            .create(db_path)
            .context("Failed to create database")?;

        let tx = db
            .begin_write()
            .context("Failed to begin write transaction")?;

        // 1. Validate metadata/schema compatibility before opening the full table set.
        crate::tables::validate_schema(&tx)?;

        // 2. Create tables idempotently after the schema gate passes.
        crate::tables::create_tables(&tx)?;

        tx.commit()
            .context("Failed to commit tables initialization")?;

        Ok(db)
    }
}
