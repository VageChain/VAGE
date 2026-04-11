mod indexer;
mod server;

use anyhow::Result;
use std::net::SocketAddr;
use sqlx::{SqlitePool, sqlite::SqliteConnectOptions};
use tracing::info;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();

    let db_path = "explorer.db";
    let rpc_url = "http://127.0.0.1:8080/rpc";
    let server_addr: SocketAddr = "127.0.0.1:3000".parse()?;

    info!("VageChain Explorer starting...");

    // Initialize Database Pool
    let options = SqliteConnectOptions::new()
        .filename(db_path)
        .create_if_missing(true);
    let pool = SqlitePool::connect_with(options).await?;

    let rpc_url_for_indexer = rpc_url.to_string();

    // Start Indexer in background
    tokio::spawn(async move {
        match indexer::BlockIndexer::new(db_path, &rpc_url_for_indexer).await {
            Ok(mut indexer) => {
                if let Err(e) = indexer.run().await {
                    tracing::error!("Indexer fatal error: {:?}", e);
                }
            }
            Err(e) => tracing::error!("Failed to initialize indexer: {:?}", e),
        }
    });

    // Start Web Server
    info!("Starting Explorer UI at http://{}", server_addr);
    server::start_explorer_server(pool, server_addr).await?;

    Ok(())
}
