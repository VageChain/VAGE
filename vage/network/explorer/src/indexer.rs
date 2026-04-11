use anyhow::Result;
use vage_block::Block;
use vage_types::BlockHeight;
use sqlx::{SqlitePool, sqlite::SqliteConnectOptions};
use std::time::Duration;
use tracing::{info, warn};

/// The BlockIndexer crawls the VageChain RPC node and populates a high-performance 
/// relational database for the frontend dashboard.
pub struct BlockIndexer {
    pool: SqlitePool,
    rpc_url: String,
    current_height: BlockHeight,
}

impl BlockIndexer {
    pub async fn new(db_url: &str, rpc_url: &str) -> Result<Self> {
        let options = SqliteConnectOptions::new()
            .filename(db_url)
            .create_if_missing(true);
        let pool = SqlitePool::connect_with(options).await?;
        
        Self::initialize_schema(&pool).await?;
        
        Ok(Self {
            pool,
            rpc_url: rpc_url.to_owned(),
            current_height: 0,
        })
    }

    async fn initialize_schema(pool: &SqlitePool) -> Result<()> {
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS blocks (
                height INTEGER PRIMARY KEY,
                hash BLOB NOT NULL,
                parent_hash BLOB NOT NULL,
                timestamp INTEGER NOT NULL,
                tx_count INTEGER NOT NULL,
                proposer BLOB NOT NULL
            );
            CREATE TABLE IF NOT EXISTS transactions (
                hash BLOB PRIMARY KEY,
                block_height INTEGER NOT NULL,
                from_addr BLOB NOT NULL,
                to_addr BLOB,
                value TEXT NOT NULL,
                gas_used INTEGER NOT NULL,
                FOREIGN KEY(block_height) REFERENCES blocks(height)
            );
            CREATE TABLE IF NOT EXISTS accounts (
                address BLOB PRIMARY KEY,
                balance TEXT NOT NULL,
                nonce INTEGER NOT NULL,
                last_updated_height INTEGER NOT NULL
            );"
        ).execute(pool).await?;
        
        Ok(())
    }

    pub async fn run(&mut self) -> Result<()> {
        info!("Starting Block Explorer Indexer... RPC: {}", self.rpc_url);
        
        loop {
            match self.fetch_latest_height().await {
                Ok(latest) if latest > self.current_height => {
                    info!("Syncing from height {} to {}", self.current_height + 1, latest);
                    for height in (self.current_height + 1)..=latest {
                        if let Err(e) = self.index_block(height).await {
                             warn!("Failed to index block at height {}: {:?}", height, e);
                             break;
                        }
                        self.current_height = height;
                    }
                }
                _ => {
                    tokio::time::sleep(Duration::from_secs(1)).await;
                }
            }
        }
    }

    async fn fetch_latest_height(&self) -> Result<BlockHeight> {
        let client = reqwest::Client::new();
        let response: serde_json::Value = client.post(&self.rpc_url)
            .json(&serde_json::json!({
                "jsonrpc": "2.0",
                "method": "eth_blockNumber",
                "params": [],
                "id": 1
            }))
            .send().await?.json().await?;
            
        let height_hex = response["result"].as_str().unwrap_or("0x0");
        Ok(u64::from_str_radix(height_hex.trim_start_matches("0x"), 16)?)
    }

    async fn index_block(&self, height: BlockHeight) -> Result<()> {
        // Fetch full block details from RPC
        let block: Block = self.fetch_block_from_rpc(height).await?;
        
        let hash = block.hash();
        let parent_hash = block.parent_hash();
        let proposer = block.header.proposer.as_bytes();

        sqlx::query(
            "INSERT OR REPLACE INTO blocks (height, hash, parent_hash, timestamp, tx_count, proposer) 
             VALUES (?, ?, ?, ?, ?, ?)"
        )
        .bind(height as i64)
        .bind(&hash[..])
        .bind(&parent_hash[..])
        .bind(block.header.timestamp as i64)
        .bind(block.body.transactions.len() as i64)
        .bind(&proposer[..])
        .execute(&self.pool).await?;

        // Index transactions sequentially
        for tx in &block.body.transactions {
            let tx_hash = tx.hash();
            sqlx::query(
                "INSERT OR REPLACE INTO transactions (hash, block_height, from_addr, to_addr, value, gas_used) 
                 VALUES (?, ?, ?, ?, ?, ?)"
            )
            .bind(&tx_hash[..])
            .bind(height as i64)
            .bind(&tx.from.as_bytes()[..])
            .bind(tx.to.map(|a| a.to_hex()))
            .bind(tx.value.to_string())
            .bind(0i64) // Gas used to be filled from receipts later
            .execute(&self.pool).await?;
        }

        Ok(())
    }

    async fn fetch_block_from_rpc(&self, height: BlockHeight) -> Result<Block> {
        let client = reqwest::Client::new();
        let response: serde_json::Value = client.post(&self.rpc_url)
            .json(&serde_json::json!({
                "jsonrpc": "2.0",
                "method": "vage_getBlockByNumber",
                "params": [format!("0x{:x}", height), true],
                "id": 1
            }))
            .send().await?.json().await?;
            
        Ok(serde_json::from_value(response["result"].clone())?)
    }
}
