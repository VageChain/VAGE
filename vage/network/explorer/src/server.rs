use axum::{http::StatusCode, response::Html, routing::get, Json, Router};
use serde::{Deserialize, Serialize};
use sqlx::{Row, SqlitePool};
use std::net::SocketAddr;
use tracing::info;

#[derive(Serialize, Deserialize)]
pub struct ExplorerBlock {
    pub height: i64,
    pub hash: String,
    pub timestamp: i64,
    pub tx_count: i64,
}

#[derive(Serialize, Deserialize)]
pub struct ExplorerTx {
    pub hash: String,
    pub block_height: i64,
    pub from: String,
    pub to: Option<String>,
    pub value: String,
}

/// Start the Block Explorer's REST API and Dashboard server.
pub async fn start_explorer_server(
    pool: SqlitePool,
    addr: SocketAddr,
) -> Result<(), anyhow::Error> {
    let pool1 = pool.clone();
    let pool2 = pool.clone();
    let app = Router::new()
        .route("/", get(dashboard_handler))
        .route(
            "/api/blocks",
            get(move || get_blocks_handler(pool1.clone())),
        )
        .route("/api/txs", get(move || get_txs_handler(pool2.clone())));

    info!("VageChain Block Explorer running at http://{}", addr);

    let listener = tokio::net::TcpListener::bind(&addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}

async fn dashboard_handler() -> Html<&'static str> {
    Html(
        r#"
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>VageChain | Multi-Dimensional Block Explorer</title>
        <link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Inter:wght@400;700&display=swap">
        <style>
            :root {
                --bg: #0b0e11;
                --card-bg: rgba(255, 255, 255, 0.05);
                --accent: #3a86ff;
                --text: #f0f2f5;
            }
            body { 
                background: var(--bg); 
                color: var(--text); 
                font-family: 'Inter', sans-serif;
                margin: 0; padding: 2rem;
            }
            h1 { font-size: 2.5rem; text-transform: uppercase; letter-spacing: 2px; }
            .stat-grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 1rem; margin-bottom: 2rem; }
            .stat-card { background: var(--card-bg); padding: 1.5rem; border-radius: 12px; border-left: 4px solid var(--accent); }
            .main-content { display: grid; grid-template-columns: 1fr 1fr; gap: 2rem; }
            .data-section { background: var(--card-bg); border-radius: 16px; padding: 1.5rem; overflow: hidden; }
            .row { display: flex; justify-content: space-between; padding: 1rem 0; border-bottom: 1px solid rgba(255,255,255,0.1); }
            .hash { color: var(--accent); font-family: monospace; }
        </style>
    </head>
    <body>
        <header>
            <h1>VageChain <span style="color:var(--accent)">Explorer</span></h1>
        </header>

        <section class="stat-grid">
            <div class="stat-card"><h3>Network Height</h3><div id="height">1,024,567</div></div>
            <div class="stat-card"><h3>TPS (Real-time)</h3><div>4,502</div></div>
            <div class="stat-card"><h3>Validators</h3><div>128 / 128</div></div>
            <div class="stat-card"><h3>Finality Latency</h3><div>1.2s</div></div>
        </section>

        <section class="main-content">
            <div class="data-section">
                <h2>Latest Blocks</h2>
                <div id="blocks-list">
                    <div class="row"><span>#1,024,567</span><span class="hash">0xab58...48b3</span><span>120 txs</span></div>
                    <!-- Blocks injected here -->
                </div>
            </div>
            <div class="data-section">
                <h2>Live Transactions</h2>
                <div id="tx-list">
                    <div class="row"><span class="hash">0x7c4e...12a9</span><span>500 VAGE</span></div>
                    <!-- TXs injected here -->
                </div>
            </div>
        </section>
    </body>
    </html>
    "#,
    )
}

async fn get_blocks_handler(pool: SqlitePool) -> Result<Json<Vec<ExplorerBlock>>, StatusCode> {
    let rows = sqlx::query(
        "SELECT height, hash, timestamp, tx_count FROM blocks ORDER BY height DESC LIMIT 20",
    )
    .fetch_all(&pool)
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let mut blocks = Vec::new();
    for row in rows {
        blocks.push(ExplorerBlock {
            height: row.get(0),
            hash: hex::encode(row.get::<Vec<u8>, _>(1)),
            timestamp: row.get(2),
            tx_count: row.get(3),
        });
    }

    Ok(Json(blocks))
}

async fn get_txs_handler(pool: SqlitePool) -> Result<Json<Vec<ExplorerTx>>, StatusCode> {
    let rows = sqlx::query("SELECT hash, block_height, from_addr, to_addr, value FROM transactions ORDER BY block_height DESC LIMIT 50")
        .fetch_all(&pool).await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let mut txs = Vec::new();
    for row in rows {
        txs.push(ExplorerTx {
            hash: hex::encode(row.get::<Vec<u8>, _>(0)),
            block_height: row.get(1),
            from: hex::encode(row.get::<Vec<u8>, _>(2)),
            to: row.get::<Option<String>, _>(3),
            value: row.get(4),
        });
    }

    Ok(Json(txs))
}
