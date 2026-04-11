use crate::{TransactionCommands, utils};
use anyhow::Result;
use serde_json::json;
use std::time::Duration;
use tokio::time::sleep;
use ed25519_dalek::{SigningKey, Signer};

pub async fn handle_transaction_command(rpc_url: &str, action: TransactionCommands) -> Result<()> {
    let client = reqwest::Client::new();

    match action {
        TransactionCommands::Send {
            from,
            to,
            value,
            private_key,
            nonce,
            gas,
        } => {
            send_transaction(&client, rpc_url, &from, &to, &value, &private_key, nonce, gas).await?;
        }
        TransactionCommands::Status {
            hash,
            poll_interval,
            poll_max,
        } => {
            check_transaction_status(&client, rpc_url, &hash, poll_interval, poll_max).await?;
        }
        TransactionCommands::Pending { limit } => {
            get_pending_transactions(&client, rpc_url, limit).await?;
        }
    }

    Ok(())
}

async fn send_transaction(
    client: &reqwest::Client,
    rpc_url: &str,
    from: &str,
    to: &str,
    value: &str,
    private_key: &str,
    nonce: u64,
    gas: u64,
) -> Result<()> {
    println!("📤 Creating and Signing Transaction");
    println!("═══════════════════════════════════════════════════════════");

    // Parse addresses
    let from_bytes = hex::decode(from.trim_start_matches("0x"))?;
    let to_bytes = hex::decode(to.trim_start_matches("0x"))?;

    if from_bytes.len() != 32 || to_bytes.len() != 32 {
        anyhow::bail!("Addresses must be 32 bytes (64 hex chars)");
    }

    let value_u128: u128 = value.parse()?;
    let tokens = value_u128 as f64 / 1e18;

    // Create transaction
    let mut tx = json!({
        "from": from_bytes,
        "to": to_bytes,
        "value": format!("0x{:x}", value_u128),
        "nonce": nonce,
        "gas_limit": gas,
        "gas_price": "0x3b9aca00",
        "chain_id": 1,
        "data": [],
        "signature": null,
    });

    println!("  From:  {}", from);
    println!("  To:    {}", to);
    println!("  Value: {} vc ({:.6} tokens)", value, tokens);
    println!("  Gas:   {} ({} vc)", gas, gas * 1_000_000_000);
    println!("  Nonce: {}", nonce);
    println!();

    // Sign transaction
    println!("🔐 Signing transaction...");
    let seed = utils::parse_hex32(private_key)?;
    let signing_key = SigningKey::from_bytes(&seed);

    // Serialize tx for signing
    let tx_str = serde_json::to_string(&tx)?;
    let sig = signing_key.sign(tx_str.as_bytes());
    let sig_bytes: Vec<u8> = sig.to_bytes().to_vec();

    tx["signature"] = json!(sig_bytes);

    println!("✅ Signature: 0x{}", hex::encode(&sig_bytes));
    println!();

    // Submit transaction
    println!("📡 Submitting to RPC endpoint: {}", rpc_url);
    let response = utils::call_rpc(client, rpc_url, "vage_sendTransaction", vec![tx]).await?;

    let tx_hash = if response.is_string() {
        response.as_str().unwrap_or("unknown").to_string()
    } else if response.is_object() {
        response["txHash"]
            .as_str()
            .map(|s| s.to_string())
            .unwrap_or_else(|| response.to_string())
    } else {
        response.to_string()
    };

    println!("✅ Transaction submitted!");
    println!("   Hash: {}", tx_hash);
    println!();
    println!("📋 Check status with:");
    println!("   vagecli transaction status {}", tx_hash);

    Ok(())
}

async fn check_transaction_status(
    client: &reqwest::Client,
    rpc_url: &str,
    hash: &str,
    poll_interval: u64,
    poll_max: u32,
) -> Result<()> {
    println!("🔍 Checking Transaction Status");
    println!("═══════════════════════════════════════════════════════════");

    let mut poll_count = 0u32;

    loop {
        poll_count += 1;

        let response = utils::call_rpc(client, rpc_url, "vage_getTransactionByHash", vec![json!(hash)])
            .await
            .ok();

        if let Some(resp) = response {
            println!("Transaction Hash: {}", hash);
            println!("Status: {}", resp.get("status").unwrap_or(&json!("unknown")));
            println!(
                "Block: {}",
                resp.get("blockHeight")
                    .unwrap_or(&json!("pending"))
            );

            if let Some(status) = resp.get("status").and_then(|s| s.as_str()) {
                if status == "success" || status == "finalized" {
                    println!("\n✅ Transaction finalized!");
                    return Ok(());
                }
            }
        } else {
            println!("⏳ Transaction pending (attempt {}/{})", poll_count, poll_max);
        }

        if poll_interval > 0 && poll_count < poll_max {
            println!("⏳ Polling again in {}s...", poll_interval);
            sleep(Duration::from_secs(poll_interval)).await;
        } else {
            break;
        }
    }

    println!("\n❓ Transaction status unknown or still pending");
    Ok(())
}

async fn get_pending_transactions(
    client: &reqwest::Client,
    rpc_url: &str,
    limit: usize,
) -> Result<()> {
    println!("📋 Pending Transactions");
    println!("═══════════════════════════════════════════════════════════");

    let response = utils::call_rpc(client, rpc_url, "vage_getPendingTransactions", vec![json!(limit)]).await?;

    if response.is_array() {
        let txs = response.as_array().unwrap();
        println!("Found {} pending transaction(s):\n", txs.len());

        for (idx, tx) in txs.iter().enumerate() {
            println!("  #{}. {}", idx + 1, tx);
        }
    } else {
        println!("No pending transactions");
    }

    Ok(())
}
