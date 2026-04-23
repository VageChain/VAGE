use crate::context::RpcContext;
use crate::error::RpcError;
use serde_json::{json, Value};
use std::sync::Arc;
use vage_block::BlockBody;

/// JSON-RPC dispatcher for all block-related methods.
pub async fn handle_block_method(
    method: &str,
    params: Option<Value>,
    context: &Arc<RpcContext>,
) -> Result<Value, RpcError> {
    match method {
        "vage_getBlockByNumber" => {
            let height = parse_height_param(params)?;
            let block = get_block_by_height(height, context).await?;
            Ok(json!(block))
        }
        "vage_getBlockByHash" => {
            let hash = parse_hash_param(params)?;
            let block = get_block_by_hash(hash, context).await?;
            Ok(json!(block))
        }
        "vage_latestBlock" => {
            let block = get_latest_block(context).await?;
            Ok(json!(block))
        }
        "vage_getBlockHeader" => {
            let height = parse_height_param(params)?;
            let header = get_block_header_internal(height, context).await?;
            Ok(json!(header))
        }
        "vage_getBlockTransactions" => {
            let (height, limit, offset) = parse_pagination_params(params)?;
            let txs = get_block_transactions_internal(height, limit, offset, context).await?;
            Ok(json!(txs))
        }
        "vage_getBlockReceipts" => {
            let height = parse_height_param(params)?;
            let receipts = get_block_receipts_internal(height, context).await?;
            Ok(json!(receipts))
        }
        _ => Err(RpcError::MethodNotFound(method.to_string())),
    }
}

pub async fn get_block_by_height(
    height: u64,
    context: &Arc<RpcContext>,
) -> Result<Value, RpcError> {
    let header = context
        .storage()
        .get_block_header(height)
        .map_err(RpcError::DatabaseError)?
        .ok_or_else(|| RpcError::BlockNotFound(height))?;

    let body = context
        .storage()
        .get_block_body(height)
        .map_err(RpcError::DatabaseError)?
        .unwrap_or_else(BlockBody::new);

    Ok(json!({
        "header": header,
        "body": body,
    }))
}

pub async fn get_block_by_hash(
    _hash: [u8; 32],
    _context: &Arc<RpcContext>,
) -> Result<Value, RpcError> {
    // In many blockchains, the block hash is mapped to a height in a separate index table.
    // Lacking that index here, we return a placeholder or scan.
    Err(RpcError::InternalError(
        "get_block_by_hash mapping not yet indexed in storage".into(),
    ))
}

pub async fn get_latest_block(context: &Arc<RpcContext>) -> Result<Value, RpcError> {
    let height = context
        .storage()
        .latest_block_height()
        .map_err(RpcError::DatabaseError)?;
    get_block_by_height(height, context).await
}

async fn get_block_header_internal(
    height: u64,
    context: &Arc<RpcContext>,
) -> Result<Value, RpcError> {
    let header = context
        .storage()
        .get_block_header(height)
        .map_err(RpcError::DatabaseError)?
        .ok_or_else(|| RpcError::BlockNotFound(height))?;

    Ok(json!(header))
}

async fn get_block_transactions_internal(
    height: u64,
    limit: usize,
    offset: usize,
    context: &Arc<RpcContext>,
) -> Result<Value, RpcError> {
    let body = context
        .storage()
        .get_block_body(height)
        .map_err(RpcError::DatabaseError)?
        .ok_or_else(|| RpcError::BlockNotFound(height))?;

    let txs: Vec<_> = body
        .transactions
        .into_iter()
        .skip(offset)
        .take(limit)
        .collect();

    Ok(json!(txs))
}

async fn get_block_receipts_internal(
    height: u64,
    context: &Arc<RpcContext>,
) -> Result<Value, RpcError> {
    // This requires fetching the body to get tx hashes, then looking up receipts.
    let body = context
        .storage()
        .get_block_body(height)
        .map_err(RpcError::DatabaseError)?
        .ok_or_else(|| RpcError::BlockNotFound(height))?;

    let mut receipts = Vec::new();
    for tx in body.transactions {
        if let Ok(Some(receipt)) = context.storage().get_receipt(tx.hash()) {
            receipts.push(json!(receipt));
        }
    }

    Ok(json!(receipts))
}

// --- Internal Parameter Parsers ---

fn parse_height_param(params: Option<Value>) -> Result<u64, RpcError> {
    let val = params
        .and_then(|v| {
            if v.is_array() {
                v.get(0).cloned()
            } else {
                Some(v)
            }
        })
        .ok_or_else(|| RpcError::InvalidParams("missing height parameter".into()))?;

    if let Some(h) = val.as_u64() {
        Ok(h)
    } else if let Some(s) = val.as_str() {
        // Handle hex string height (e.g., "0x1")
        u64::from_str_radix(s.trim_start_matches("0x"), 16)
            .map_err(|_| RpcError::InvalidParams("invalid height format".into()))
    } else {
        Err(RpcError::InvalidParams(
            "height must be a number or hex string".into(),
        ))
    }
}

fn parse_hash_param(params: Option<Value>) -> Result<[u8; 32], RpcError> {
    let val = params
        .and_then(|v| {
            if v.is_array() {
                v.get(0).cloned()
            } else {
                Some(v)
            }
        })
        .ok_or_else(|| RpcError::InvalidParams("missing hash parameter".into()))?;

    let s = val
        .as_str()
        .ok_or_else(|| RpcError::InvalidParams("hash must be a string".into()))?;
    let mut hash = [0u8; 32];
    hex::decode(s.trim_start_matches("0x"))
        .map_err(|_| RpcError::InvalidParams("invalid hex string".into()))?
        .copy_to_slice(&mut hash)?;

    Ok(hash)
}

fn parse_pagination_params(params: Option<Value>) -> Result<(u64, usize, usize), RpcError> {
    let params = params.ok_or_else(|| RpcError::InvalidParams("missing parameters".into()))?;
    if !params.is_array() {
        return Err(RpcError::InvalidParams(
            "parameters must be an array".into(),
        ));
    }

    let height = params
        .get(0)
        .and_then(|v| v.as_u64())
        .ok_or_else(|| RpcError::InvalidParams("missing/invalid height".into()))?;
    let limit = params.get(1).and_then(|v| v.as_u64()).unwrap_or(100) as usize;
    let offset = params.get(2).and_then(|v| v.as_u64()).unwrap_or(0) as usize;

    Ok((height, limit, offset))
}

trait CopyToSliceExt {
    fn copy_to_slice(self, target: &mut [u8; 32]) -> Result<(), RpcError>;
}

impl CopyToSliceExt for Vec<u8> {
    fn copy_to_slice(self, target: &mut [u8; 32]) -> Result<(), RpcError> {
        if self.len() != 32 {
            return Err(RpcError::InvalidParams("invalid hash length".into()));
        }
        target.copy_from_slice(&self);
        Ok(())
    }
}
