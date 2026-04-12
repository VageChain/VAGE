use crate::schema::*;
use anyhow::{bail, Context, Result};
use redb::{ReadableTable, WriteTransaction};
use tracing::{info, warn};

pub const SCHEMA_VERSION: u64 = 1;

fn ensure_metadata_table(txn: &WriteTransaction) -> Result<()> {
    txn.open_table(TABLE_METADATA)
        .context("Failed to open metadata table")?;
    Ok(())
}

/// Initialize all database tables on first startup. This operation is idempotent.
pub fn create_tables(txn: &WriteTransaction) -> Result<()> {
    info!("Bootstrapping blockchain database tables...");

    // 1. Metadata & Versioning (always initialized first)
    ensure_metadata_table(txn)?;

    // 2. Core ledger tables
    txn.open_table(TABLE_BLOCK_HEADERS)
        .context("Failed to open block_headers")?;
    txn.open_table(TABLE_BLOCK_BODIES)
        .context("Failed to open block_bodies")?;
    txn.open_table(TABLE_TRANSACTIONS)
        .context("Failed to open transactions")?;

    // 3. State & Consensus tables
    txn.open_table(TABLE_ACCOUNTS)
        .context("Failed to open accounts")?;
    txn.open_table(TABLE_STATE)
        .context("Failed to open state")?;
    txn.open_table(TABLE_VALIDATORS)
        .context("Failed to open validators")?;
    txn.open_table(TABLE_STAKING)
        .context("Failed to open staking")?;
    txn.open_table(TABLE_VERKLE_NODES)
        .context("Failed to open verkle_nodes")?;
    txn.open_table(TABLE_ZK_PROOFS)
        .context("Failed to open zk_proofs")?;
    txn.open_table(TABLE_TX_BLOCK_INDEX)
        .context("Failed to open tx_block_index")?;
    txn.open_table(TABLE_TX_RECEIPTS)
        .context("Failed to open tx_receipts")?;
    txn.open_table(TABLE_VALIDATOR_SETS)
        .context("Failed to open validator_sets")?;
    txn.open_table(TABLE_SLASHING_RECORDS)
        .context("Failed to open slashing_records")?;

    // 4. Node ephemeral tables
    txn.open_table(TABLE_MEMPOOL)
        .context("Failed to open mempool")?;

    info!("All database tables registered successfully.");
    Ok(())
}

/// Validate schema compatibility and handle potential upgrades.
pub fn validate_schema(txn: &WriteTransaction) -> Result<()> {
    let mut table = txn
        .open_table(TABLE_METADATA)
        .context("Failed to open metadata table")?;
    let version_opt = table
        .get("schema_version")?
        .map(|version_bytes| version_bytes.value().to_vec());

    if let Some(version_bytes) = version_opt {
        let version_str = std::str::from_utf8(&version_bytes).unwrap_or_default();
        let version: u64 = version_str.parse().unwrap_or(0);

        if version < SCHEMA_VERSION {
            warn!(
                "Found legacy schema version {}. Upgrading to {}...",
                version, SCHEMA_VERSION
            );
            // Upgrade logic here
        } else if version > SCHEMA_VERSION {
            bail!("Database schema version {} is newer than node version {}. Please upgrade your node.", version, SCHEMA_VERSION);
        }
    } else {
        // New database, set version
        let ver = SCHEMA_VERSION.to_string();
        table.insert("schema_version", ver.as_bytes())?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{create_tables, validate_schema, SCHEMA_VERSION};
    use crate::schema::{TABLE_BLOCK_HEADERS, TABLE_METADATA, TABLE_STATE, TABLE_TX_RECEIPTS};
    use redb::Database;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_db_path(name: &str) -> PathBuf {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time should be after unix epoch")
            .as_nanos();
        std::env::temp_dir().join(format!("vage-storage-tables-{name}-{unique}.redb"))
    }

    #[test]
    fn create_tables_is_idempotent_and_registers_core_tables() {
        let db_path = temp_db_path("bootstrap");
        let db = Database::create(&db_path).expect("database should create");

        let tx = db.begin_write().expect("write tx should open");
        validate_schema(&tx).expect("schema validation should initialize metadata");
        create_tables(&tx).expect("table bootstrap should succeed");
        create_tables(&tx).expect("table bootstrap should be idempotent");
        tx.commit().expect("bootstrap transaction should commit");

        let read_tx = db.begin_read().expect("read tx should open");
        read_tx
            .open_table(TABLE_METADATA)
            .expect("metadata table should exist");
        read_tx
            .open_table(TABLE_BLOCK_HEADERS)
            .expect("block headers table should exist");
        read_tx
            .open_table(TABLE_STATE)
            .expect("state table should exist");
        read_tx
            .open_table(TABLE_TX_RECEIPTS)
            .expect("tx receipts table should exist");

        let version_table = read_tx
            .open_table(TABLE_METADATA)
            .expect("metadata table should open");
        let schema_version = version_table
            .get("schema_version")
            .expect("schema version lookup should succeed")
            .expect("schema version should be recorded");
        assert_eq!(
            std::str::from_utf8(schema_version.value()).expect("schema version should be utf8"),
            SCHEMA_VERSION.to_string()
        );

        drop(read_tx);
        drop(db);
        let _ = std::fs::remove_file(db_path);
    }

    #[test]
    fn validate_schema_rejects_newer_database_versions() {
        let db_path = temp_db_path("future-schema");
        let db = Database::create(&db_path).expect("database should create");

        let tx = db.begin_write().expect("write tx should open");
        create_tables(&tx).expect("table bootstrap should succeed");
        {
            let mut table = tx
                .open_table(TABLE_METADATA)
                .expect("metadata table should open");
            let future_version = (SCHEMA_VERSION + 1).to_string();
            table
                .insert("schema_version", future_version.as_bytes())
                .expect("future schema version should write");
        }

        let error = validate_schema(&tx).expect_err("future schema version should be rejected");
        assert!(error.to_string().contains("newer than node version"));

        drop(tx);
        drop(db);
        let _ = std::fs::remove_file(db_path);
    }
}
