use anyhow::Result;
use ed25519_dalek::SigningKey;
use rand::Rng;
use serde_json::json;
use vage_types::Address;

/// Call a JSON-RPC method on the VageChain node
pub async fn call_rpc(
    client: &reqwest::Client,
    url: &str,
    method: &str,
    params: Vec<serde_json::Value>,
) -> Result<serde_json::Value> {
    let response: serde_json::Value = client
        .post(url)
        .json(&json!({
            "jsonrpc": "2.0",
            "method": method,
            "params": params,
            "id": 1
        }))
        .send()
        .await?
        .json()
        .await?;

    if let Some(err) = response.get("error") {
        anyhow::bail!("RPC Error: {}", err);
    }

    Ok(response["result"].clone())
}

/// Generate a new random Ed25519 keypair
pub fn generate_keypair() -> (String, String) {
    let mut rng = rand::thread_rng();
    let mut seed = [0u8; 32];
    rng.fill(&mut seed);

    let signing_key = SigningKey::from_bytes(&seed);
    let verifying_key = signing_key.verifying_key();

    let privkey_hex = format!("0x{}", hex::encode(&seed));
    let pubkey_hex = format!("0x{}", hex::encode(verifying_key.as_bytes()));

    (privkey_hex, pubkey_hex)
}

/// Derive an address from a public key
pub fn derive_address(pubkey_hex: &str) -> Result<String> {
    let pubkey_bytes = hex::decode(pubkey_hex.trim_start_matches("0x"))?;
    if pubkey_bytes.len() != 32 {
        anyhow::bail!("Public key must be 32 bytes");
    }

    let mut pubkey_array = [0u8; 32];
    pubkey_array.copy_from_slice(&pubkey_bytes);

    let address = Address::from_public_key(&pubkey_array);
    Ok(format!("0x{}", hex::encode(address.as_bytes())))
}

/// Parse a hex string to a 32-byte array
pub fn parse_hex32(hex: &str) -> Result<[u8; 32]> {
    let bytes = hex::decode(hex.trim_start_matches("0x"))?;
    if bytes.len() != 32 {
        anyhow::bail!("Input must be exactly 32 bytes");
    }
    let mut array = [0u8; 32];
    array.copy_from_slice(&bytes);
    Ok(array)
}

/// Format vc to readable token amount
#[allow(dead_code)]
pub fn format_balance(wei: u128) -> String {
    format!("{:.6} tokens", wei as f64 / 1e18)
}

/// Load devnet configuration
pub fn load_devnet_config() -> Result<Vec<(String, String, String)>> {
    // Hardcoded devnet accounts
    Ok(vec![
        (
            "0x0000000000000000000000000000000000000000000000000000000000000001".to_string(),
            "0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".to_string(),
            "1000000000000000000000000000".to_string(), // balance
        ),
        (
            "0x0000000000000000000000000000000000000000000000000000000000000002".to_string(),
            "0xfedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210".to_string(),
            "1000000000000000000000000000".to_string(),
        ),
        (
            "0x0000000000000000000000000000000000000000000000000000000000000003".to_string(),
            "0x3333333333333333333333333333333333333333333333333333333333333333".to_string(),
            "1000000000000000000000000000".to_string(),
        ),
        (
            "0x0000000000000000000000000000000000000000000000000000000000000004".to_string(),
            "0x4444444444444444444444444444444444444444444444444444444444444444".to_string(),
            "1000000000000000000000000000".to_string(),
        ),
    ])
}
