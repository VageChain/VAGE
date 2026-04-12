use crate::context::RpcContext;
use crate::error::RpcError;
use primitive_types::U256;
use serde_json::{json, Value};
use std::sync::Arc;
use vage_types::Address;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ProofKind {
    Account,
    Storage,
    Minimal,
}

#[derive(Clone, Debug)]
struct ProofRequest {
    kind: ProofKind,
    address: Option<Address>,
    key: Option<[u8; 32]>,
    minimal: bool,
}

/// JSON-RPC dispatcher for all state-related methods.
pub async fn handle_state_method(
    method: &str,
    params: Option<Value>,
    context: &Arc<RpcContext>,
) -> Result<Value, RpcError> {
    match method {
        "vage_getBalance" => {
            let address = parse_address_param(params)?;
            let balance = get_balance_internal(address, context).await?;
            Ok(json!(balance.to_string())) // Return as string to avoid U256 precision issues in JSON
        }
        "vage_getAccount" => {
            let address = parse_address_param(params)?;
            let account = get_account_internal(address, context).await?;
            Ok(json!(account))
        }
        "vage_getNonce" => {
            let address = parse_address_param(params)?;
            let nonce = get_nonce_internal(address, context).await?;
            Ok(json!(nonce))
        }
        "vage_getStorageAt" => {
            let (address, key) = parse_address_and_key_params(params)?;
            let storage = get_storage_internal(address, key, context).await?;
            Ok(json!(storage))
        }
        "vage_getStateRoot" => {
            let root = get_state_root_internal(context).await?;
            Ok(json!(hex::encode(root)))
        }
        "vage_getProof" => {
            let request = parse_proof_params(params, ProofKind::Account)?;
            let proof = get_proof_internal(request, context).await?;
            Ok(json!(proof))
        }
        "vage_getStorageProof" => {
            let request = parse_proof_params(params, ProofKind::Storage)?;
            let proof = get_proof_internal(request, context).await?;
            Ok(json!(proof))
        }
        "vage_getMinimalProof" => {
            let request = parse_proof_params(params, ProofKind::Minimal)?;
            let proof = get_proof_internal(request, context).await?;
            Ok(json!(proof))
        }
        "vage_getCode" => {
            let address = parse_address_param(params)?;
            let code = get_contract_code_internal(address, context).await?;
            Ok(json!(code))
        }
        _ => Err(RpcError::MethodNotFound(method.to_string())),
    }
}

async fn get_balance_internal(
    address: Address,
    context: &Arc<RpcContext>,
) -> Result<U256, RpcError> {
    context
        .state()
        .get_balance(&address)
        .map_err(|e| RpcError::InternalError(format!("failed to fetch balance: {}", e)))
}

async fn get_account_internal(
    address: Address,
    context: &Arc<RpcContext>,
) -> Result<Option<Value>, RpcError> {
    let account = context
        .state()
        .get_account(&address)
        .map_err(|e| RpcError::InternalError(format!("failed to fetch account: {}", e)))?;
    Ok(account.map(|a| json!(a)))
}

async fn get_nonce_internal(address: Address, context: &Arc<RpcContext>) -> Result<u64, RpcError> {
    context
        .state()
        .get_nonce(&address)
        .map_err(|e| RpcError::InternalError(format!("failed to fetch nonce: {}", e)))
}

async fn get_storage_internal(
    address: Address,
    key: [u8; 32],
    context: &Arc<RpcContext>,
) -> Result<String, RpcError> {
    let value = context
        .state()
        .get_storage(&address, key)
        .map_err(|e| RpcError::InternalError(format!("failed to fetch storage: {}", e)))?;

    Ok(value
        .map(|v| hex::encode(v))
        .unwrap_or_else(|| "0x0000".to_string()))
}

async fn get_state_root_internal(context: &Arc<RpcContext>) -> Result<[u8; 32], RpcError> {
    Ok(context.state().state_root())
}

async fn get_proof_internal(
    request: ProofRequest,
    context: &Arc<RpcContext>,
) -> Result<Value, RpcError> {
    let state = context.state();
    let proof = match request.kind {
        ProofKind::Account => {
            let address = request.address.ok_or_else(|| {
                RpcError::InvalidParams("missing address for account proof".into())
            })?;
            if request.minimal {
                state.export_minimal_proof_for_rpc(*address.as_bytes())
            } else {
                state.export_account_proof_for_rpc(&address)
            }
        }
        ProofKind::Storage => {
            let address = request.address.ok_or_else(|| {
                RpcError::InvalidParams("missing address for storage proof".into())
            })?;
            let key = request.key.ok_or_else(|| {
                RpcError::InvalidParams("missing storage key for storage proof".into())
            })?;
            if request.minimal {
                state.export_minimal_proof_for_rpc(vage_state::storage_proof_key(&address, &key))
            } else {
                state.export_storage_proof_for_rpc(&address, key)
            }
        }
        ProofKind::Minimal => {
            let key = request
                .key
                .ok_or_else(|| RpcError::InvalidParams("missing key for minimal proof".into()))?;
            state.export_minimal_proof_for_rpc(key)
        }
    }
    .map_err(|e| RpcError::InternalError(format!("failed to generate proof: {}", e)))?;

    Ok(json!(proof))
}

async fn get_contract_code_internal(
    address: Address,
    context: &Arc<RpcContext>,
) -> Result<String, RpcError> {
    let account = context
        .state()
        .get_account(&address)
        .map_err(|e| RpcError::InternalError(format!("failed to fetch account for code: {}", e)))?;

    if let Some(account) = account {
        if account.is_contract() {
            // In a real implementation, we would look up the actual bytecode using account.code_hash.
            // For now, return the hash as a placeholder for the code itself.
            return Ok(hex::encode(account.code_hash));
        }
    }

    Ok("0x".to_string())
}

// --- Parameter Parsers ---

fn parse_address_param(params: Option<Value>) -> Result<Address, RpcError> {
    let val = params
        .and_then(|v| {
            if v.is_array() {
                v.get(0).cloned()
            } else {
                Some(v)
            }
        })
        .ok_or_else(|| RpcError::InvalidParams("missing address parameter".into()))?;

    let s = val
        .as_str()
        .ok_or_else(|| RpcError::InvalidParams("address must be a string".into()))?;
    Address::from_str_ext(s)
}

fn parse_address_and_key_params(params: Option<Value>) -> Result<(Address, [u8; 32]), RpcError> {
    let params = params.ok_or_else(|| RpcError::InvalidParams("missing parameters".into()))?;
    if !params.is_array() {
        return Err(RpcError::InvalidParams(
            "parameters must be an array".into(),
        ));
    }

    let addr_str = params
        .get(0)
        .and_then(|v| v.as_str())
        .ok_or_else(|| RpcError::InvalidParams("missing/invalid address".into()))?;
    let key_str = params
        .get(1)
        .and_then(|v| v.as_str())
        .ok_or_else(|| RpcError::InvalidParams("missing/invalid storage key".into()))?;

    let address = Address::from_str_ext(addr_str)?;
    let mut key = [0u8; 32];
    hex::decode(key_str.trim_start_matches("0x"))
        .map_err(|_| RpcError::InvalidParams("invalid storage key format".into()))?
        .copy_to_slice_ext(&mut key)?;

    Ok((address, key))
}

fn parse_proof_params(
    params: Option<Value>,
    default_kind: ProofKind,
) -> Result<ProofRequest, RpcError> {
    match params {
        None => Err(RpcError::InvalidParams("missing proof parameters".into())),
        Some(Value::String(address)) => Ok(ProofRequest {
            kind: default_kind,
            address: Some(Address::from_str_ext(&address)?),
            key: None,
            minimal: matches!(default_kind, ProofKind::Minimal),
        }),
        Some(Value::Array(items)) => parse_proof_params_from_array(items, default_kind),
        Some(Value::Object(map)) => {
            let kind = match map.get("type").and_then(|v| v.as_str()) {
                Some("account") => ProofKind::Account,
                Some("storage") => ProofKind::Storage,
                Some("minimal") => ProofKind::Minimal,
                Some(other) => {
                    return Err(RpcError::InvalidParams(format!(
                        "unsupported proof type: {}",
                        other
                    )))
                }
                None => default_kind,
            };

            let address = map
                .get("address")
                .and_then(|v| v.as_str())
                .map(Address::from_str_ext)
                .transpose()?;
            let key = map.get("key").map(parse_hex_key_value).transpose()?;
            let minimal = map
                .get("minimal")
                .and_then(|v| v.as_bool())
                .unwrap_or(matches!(kind, ProofKind::Minimal));

            Ok(ProofRequest {
                kind,
                address,
                key,
                minimal,
            })
        }
        Some(_) => Err(RpcError::InvalidParams(
            "unsupported proof parameter format".into(),
        )),
    }
}

fn parse_proof_params_from_array(
    items: Vec<Value>,
    default_kind: ProofKind,
) -> Result<ProofRequest, RpcError> {
    match default_kind {
        ProofKind::Account => {
            let address = items
                .first()
                .and_then(|v| v.as_str())
                .ok_or_else(|| RpcError::InvalidParams("missing/invalid address".into()))?;
            let minimal = items.get(1).and_then(|v| v.as_bool()).unwrap_or(false);
            Ok(ProofRequest {
                kind: ProofKind::Account,
                address: Some(Address::from_str_ext(address)?),
                key: None,
                minimal,
            })
        }
        ProofKind::Storage => {
            let address = items
                .first()
                .and_then(|v| v.as_str())
                .ok_or_else(|| RpcError::InvalidParams("missing/invalid address".into()))?;
            let key = items
                .get(1)
                .ok_or_else(|| RpcError::InvalidParams("missing/invalid storage key".into()))?;
            let minimal = items.get(2).and_then(|v| v.as_bool()).unwrap_or(false);
            Ok(ProofRequest {
                kind: ProofKind::Storage,
                address: Some(Address::from_str_ext(address)?),
                key: Some(parse_hex_key_value(key)?),
                minimal,
            })
        }
        ProofKind::Minimal => {
            let key = items
                .first()
                .ok_or_else(|| RpcError::InvalidParams("missing/invalid proof key".into()))?;
            Ok(ProofRequest {
                kind: ProofKind::Minimal,
                address: None,
                key: Some(parse_hex_key_value(key)?),
                minimal: true,
            })
        }
    }
}

fn parse_hex_key_value(value: &Value) -> Result<[u8; 32], RpcError> {
    let key_str = value
        .as_str()
        .ok_or_else(|| RpcError::InvalidParams("proof key must be a string".into()))?;
    let mut key = [0u8; 32];
    hex::decode(key_str.trim_start_matches("0x"))
        .map_err(|_| RpcError::InvalidParams("invalid storage key format".into()))?
        .copy_to_slice_ext(&mut key)?;
    Ok(key)
}

trait AddressExt {
    fn from_str_ext(s: &str) -> Result<Address, RpcError>;
}

impl AddressExt for Address {
    fn from_str_ext(s: &str) -> Result<Address, RpcError> {
        let bytes = hex::decode(s.trim_start_matches("0x"))
            .map_err(|_| RpcError::InvalidParams("invalid hex address".into()))?;
        if bytes.len() != 32 {
            return Err(RpcError::InvalidParams("address must be 32 bytes".into()));
        }
        let mut addr_bytes = [0u8; 32];
        addr_bytes.copy_from_slice(&bytes);
        Ok(Address(addr_bytes))
    }
}

trait CopyToSliceExt {
    fn copy_to_slice_ext(self, target: &mut [u8; 32]) -> Result<(), RpcError>;
}

impl CopyToSliceExt for Vec<u8> {
    fn copy_to_slice_ext(self, target: &mut [u8; 32]) -> Result<(), RpcError> {
        if self.len() != 32 {
            return Err(RpcError::InvalidParams(
                "invalid key length; expected 32 bytes".into(),
            ));
        }
        target.copy_from_slice(&self);
        Ok(())
    }
}
