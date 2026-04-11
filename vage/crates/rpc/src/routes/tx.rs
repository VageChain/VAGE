use serde_json::{Value, json};
use std::sync::Arc;
use crate::context::RpcContext;
use crate::error::RpcError;
use vage_types::{Transaction, Hash};
use vage_mempool::{CommitTransaction, RevealTransaction};

/// JSON-RPC dispatcher for all transaction-related methods.
pub async fn handle_tx_method(
    method: &str,
    params: Option<Value>,
    context: &Arc<RpcContext>,
) -> Result<Value, RpcError> {
    match method {
        "vage_sendTransaction" => {
            let tx = parse_transaction_param(params)?;
            let tx_hash = send_transaction_internal(tx, context).await?;
            Ok(json!(tx_hash))
        }
        "vage_getTransactionByHash" => {
            let hash = parse_hash_param(params)?;
            let tx = get_transaction_internal(hash, context).await?;
            Ok(json!(tx))
        }
        "vage_getTransactionReceipt" => {
            let hash = parse_hash_param(params)?;
            let receipt = get_transaction_receipt_internal(hash, context).await?;
            Ok(json!(receipt))
        }
        "vage_getPendingTransactions" => {
            let limit = parse_limit_param(params)?;
            let txs = get_pending_transactions_internal(limit, context).await?;
            Ok(json!(txs))
        }
        "vage_estimateGas" => {
            let tx = parse_transaction_param(params)?;
            let gas = estimate_gas_internal(tx, context).await?;
            Ok(json!(gas))
        }
        // â”€â”€ MEV protection (commit-reveal) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
        "vage_submitCommit" => {
            let commit = parse_commit_param(params)?;
            let commit_id = submit_commit_internal(commit, context).await?;
            Ok(json!(hex::encode(commit_id)))
        }
        "vage_submitReveal" => {
            let reveal = parse_reveal_param(params)?;
            submit_reveal_internal(reveal, context).await?;
            Ok(json!({ "status": "accepted" }))
        }
        "vage_getCommitStatus" => {
            let commit_id = parse_commit_id_param(params)?;
            let status = get_commit_status_internal(commit_id, context).await?;
            Ok(json!(status))
        }
        "vage_getMevPoolStats" => {
            let (pending, revealed) = context.mempool().mev_pool_stats();
            Ok(json!({ "pending_commits": pending, "revealed_txs": revealed }))
        }
        _ => Err(RpcError::MethodNotFound(method.to_string())),
    }
}

async fn send_transaction_internal(tx: Transaction, context: &Arc<RpcContext>) -> Result<Hash, RpcError> {
    // 1. Basic validation (format, size)
    tx.validate_basic()
        .map_err(|e| RpcError::InvalidParams(format!("transaction validation failed: {}", e)))?;

    let tx_hash = tx.hash();

    context.mempool()
        .add_transaction(tx)
        .map_err(|e| RpcError::InternalError(format!("failed to submit transaction: {}", e)))?;

    Ok(tx_hash)
}

async fn get_transaction_internal(hash: Hash, context: &Arc<RpcContext>) -> Result<Option<Value>, RpcError> {
    // 1. Check persistent storage first (for committed transactions)
    if let Ok(Some(tx)) = context.storage().get_transaction(hash) {
        return Ok(Some(json!(tx)));
    }

    // 2. Check mempool (for pending transactions)
    if let Ok(Some(tx)) = context.mempool().get_transaction(hash) {
        return Ok(Some(json!(tx)));
    }

    Ok(None)
}

async fn get_transaction_receipt_internal(hash: Hash, context: &Arc<RpcContext>) -> Result<Option<Value>, RpcError> {
    if let Ok(Some(receipt)) = context.storage().get_receipt(hash) {
        return Ok(Some(json!(receipt)));
    }
    
    Ok(None)
}

async fn get_pending_transactions_internal(limit: usize, context: &Arc<RpcContext>) -> Result<Vec<Value>, RpcError> {
    let txs = context.mempool().get_pending_transactions(limit)
        .map_err(|e| RpcError::InternalError(format!("failed to fetch pending transactions: {}", e)))?;
    
    Ok(txs.into_iter().map(|tx| json!(tx)).collect())
}

async fn estimate_gas_internal(tx: Transaction, context: &Arc<RpcContext>) -> Result<u64, RpcError> {
    context
        .executor
        .estimate_gas(&tx)
        .map_err(|e| RpcError::InternalError(format!("gas estimation failed: {}", e)))
}

// --- MEV handler functions ---

async fn submit_commit_internal(commit: CommitTransaction, context: &Arc<RpcContext>) -> Result<[u8; 32], RpcError> {
    context
        .mempool()
        .submit_commit(commit)
        .map_err(|e| RpcError::InternalError(format!("commit rejected: {}", e)))
}

async fn submit_reveal_internal(reveal: RevealTransaction, context: &Arc<RpcContext>) -> Result<(), RpcError> {
    context
        .mempool()
        .submit_reveal(reveal)
        .map_err(|e| RpcError::InternalError(format!("reveal rejected: {}", e)))
}

async fn get_commit_status_internal(commit_id: [u8; 32], context: &Arc<RpcContext>) -> Result<Value, RpcError> {
    let mempool = context.mempool();
    let (pending, revealed) = mempool.mev_pool_stats();
    // Return lightweight status; full per-commit lookup available via CommitRevealPool RPC types
    Ok(json!({
        "commit_id": hex::encode(commit_id),
        "pool_pending_commits": pending,
        "pool_revealed_txs": revealed,
    }))
}

// --- Parameter Parsers ---

fn parse_transaction_param(params: Option<Value>) -> Result<Transaction, RpcError> {
    let val = params.and_then(|v| {
        if v.is_array() { v.get(0).cloned() } else { Some(v) }
    }).ok_or_else(|| RpcError::InvalidParams("missing transaction parameter".into()))?;

    serde_json::from_value(val)
        .map_err(|e| RpcError::InvalidParams(format!("invalid transaction format: {}", e)))
}

fn parse_hash_param(params: Option<Value>) -> Result<Hash, RpcError> {
    let val = params.and_then(|v| {
        if v.is_array() { v.get(0).cloned() } else { Some(v) }
    }).ok_or_else(|| RpcError::InvalidParams("missing hash parameter".into()))?;

    let s = val.as_str().ok_or_else(|| RpcError::InvalidParams("hash must be a string".into()))?;
    let mut hash_bytes = [0u8; 32];
    hex::decode(s.trim_start_matches("0x"))
        .map_err(|_| RpcError::InvalidParams("invalid hex string".into()))?
        .copy_to_slice_ext(&mut hash_bytes)?;
    
    Ok(hash_bytes)
}

fn parse_limit_param(params: Option<Value>) -> Result<usize, RpcError> {
    let limit = params.and_then(|v| {
        if v.is_array() { v.get(0).and_then(|i| i.as_u64()) } else { v.as_u64() }
    }).unwrap_or(100) as usize;
    Ok(limit)
}

fn parse_commit_param(params: Option<Value>) -> Result<CommitTransaction, RpcError> {
    let val = params.and_then(|v| {
        if v.is_array() { v.get(0).cloned() } else { Some(v) }
    }).ok_or_else(|| RpcError::InvalidParams("missing commit parameter".into()))?;
    serde_json::from_value(val)
        .map_err(|e| RpcError::InvalidParams(format!("invalid commit format: {}", e)))
}

fn parse_reveal_param(params: Option<Value>) -> Result<RevealTransaction, RpcError> {
    let val = params.and_then(|v| {
        if v.is_array() { v.get(0).cloned() } else { Some(v) }
    }).ok_or_else(|| RpcError::InvalidParams("missing reveal parameter".into()))?;
    serde_json::from_value(val)
        .map_err(|e| RpcError::InvalidParams(format!("invalid reveal format: {}", e)))
}

fn parse_commit_id_param(params: Option<Value>) -> Result<[u8; 32], RpcError> {
    parse_hash_param(params)
}

trait CopyToSliceExt {
    fn copy_to_slice_ext(self, target: &mut [u8; 32]) -> Result<(), RpcError>;
}

impl CopyToSliceExt for Vec<u8> {
    fn copy_to_slice_ext(self, target: &mut [u8; 32]) -> Result<(), RpcError> {
        if self.len() != 32 {
            return Err(RpcError::InvalidParams("invalid hash length; expected 32 bytes".into()));
        }
        target.copy_from_slice(&self);
        Ok(())
    }
}
