use crate::context::RpcContext;
use axum::{extract::State, Json};
use serde_json::{json, Value};
use std::sync::Arc;

/// Simple health check handler for REST /health endpoint.
pub async fn health_check(State(context): State<Arc<RpcContext>>) -> Json<Value> {
    let mut health_info = json!({
        "status": "healthy",
        "timestamp": chrono::Utc::now().to_rfc3339(),
        "services": {}
    });

    // 1. Check Storage Engine
    let storage_ok = context.storage.get_metrics().is_ok();
    health_info["services"]["storage"] = json!({
        "ok": storage_ok,
    });

    // 2. Check Networking (P2P Connectivity)
    let peer_count = context.networking.lock().await.peer_count();
    health_info["services"]["networking"] = json!({
        "ok": peer_count > 0, // In a bootstrap-only node, 0 might be OK, but usually we expect peers.
        "peer_count": peer_count,
    });

    // 3. Check Consensus (HotStuff Status)
    let consensus_ok = context.consensus.read().await.current_view() > 0;
    health_info["services"]["consensus"] = json!({
        "ok": consensus_ok,
    });

    // 4. Mempool
    let mempool_size = context.mempool.pending_count().unwrap_or(0);
    health_info["services"]["mempool"] = json!({
        "ok": true,
        "size": mempool_size,
    });

    // Final Node Status
    if !storage_ok || !consensus_ok {
        health_info["status"] = json!("degraded");
    }

    Json(health_info)
}
