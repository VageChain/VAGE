use serde_json::{Value, json};
use std::sync::Arc;
use crate::context::RpcContext;
use crate::error::RpcError;

/// JSON-RPC dispatcher for all network and node-status related methods.
pub async fn handle_network_method(
    method: &str,
    _params: Option<Value>,
    context: &Arc<RpcContext>,
) -> Result<Value, RpcError> {
    match method {
        "vage_peerCount" => {
            let count = get_peer_count_internal(context).await?;
            Ok(json!(format!("0x{:x}", count)))
        }
        "vage_getPeers" => {
            let peers = get_peers_internal(context).await?;
            Ok(json!(peers))
        }
        "vage_getNetworkInfo" => {
            let info = get_network_info_internal(context).await?;
            Ok(json!(info))
        }
        "vage_syncing" => {
            let status = get_sync_status_internal(context).await?;
            Ok(json!(status))
        }
        "vage_nodeVersion" => {
            let version = get_node_version_internal().await?;
            Ok(json!(version))
        }
        "vage_getValidatorSet" => {
            let validators = get_validator_set_internal(context).await?;
            Ok(json!(validators))
        }
        _ => Err(RpcError::MethodNotFound(method.to_string())),
    }
}

async fn get_peer_count_internal(context: &Arc<RpcContext>) -> Result<usize, RpcError> {
    Ok(context.networking.lock().await.peer_count())
}

async fn get_peers_internal(context: &Arc<RpcContext>) -> Result<Vec<Value>, RpcError> {
    let network = context.networking.lock().await;
    let peers = network.peer_store.connected_peers();
    Ok(peers.into_iter().map(|p| json!({
        "id": p.peer_id.to_string(),
        "address": p.address.to_string(),
        "last_seen": p.last_seen,
        "reputation": p.reputation,
    })).collect())
}

async fn get_network_info_internal(context: &Arc<RpcContext>) -> Result<Value, RpcError> {
    let network = context.networking.lock().await;
    Ok(json!({
        "peer_count": network.peer_count(),
        "protocol_version": "vage/1.0",
        "listen_addr": network.swarm.listeners().next().map(|a| a.to_string()),
        "local_peer_id": network.swarm.local_peer_id().to_string(),
    }))
}

async fn get_sync_status_internal(context: &Arc<RpcContext>) -> Result<Value, RpcError> {
    let latest_height = context.storage.latest_block_height()
        .map_err(|e| RpcError::InternalError(format!("failed to fetch latest height: {}", e)))?;
    
    // In a real implementation, we would check if we are significantly behind the highest peer.
    // For now, return false (meaning we are synced) if we have ANY blocks.
    if latest_height > 0 {
        Ok(json!(false))
    } else {
        Ok(json!({
            "startingBlock": "0x0",
            "currentBlock": format!("0x{:x}", latest_height),
            "highestBlock": "0x0", // Placeholder
        }))
    }
}

async fn get_node_version_internal() -> Result<Value, RpcError> {
    Ok(json!({
        "name": "VageChain Node",
        "version": "0.1.0-alpha",
        "build": "vage-vage",
        "rustc": "1.75.0"
    }))
}

async fn get_validator_set_internal(context: &Arc<RpcContext>) -> Result<Vec<Value>, RpcError> {
    let consensus = context.consensus();
    let guard = consensus.read().await;

    let validators = guard.validator_set.active_validators();
    Ok(validators.into_iter().map(|v| json!({
        "address": v.address.to_string(),
        "voting_power": v.voting_power,
        "public_key": hex::encode(v.pubkey),
    })).collect())
}
