use crate::{utils, AccountCommands};
use anyhow::Result;
use std::fs;
use std::path::PathBuf;

pub async fn handle_account_command(action: AccountCommands) -> Result<()> {
    match action {
        AccountCommands::Generate { output, count } => {
            generate_keypairs(output, count).await?;
        }
        AccountCommands::Derive { private_key } => {
            derive_address_from_key(&private_key).await?;
        }
        AccountCommands::ListDevnet => {
            list_devnet_accounts().await?;
        }
        AccountCommands::Import {
            private_key,
            output,
        } => {
            import_account(&private_key, output).await?;
        }
        AccountCommands::Show { address } => {
            show_account(&address).await?;
        }
    }
    Ok(())
}

async fn generate_keypairs(output: Option<PathBuf>, count: usize) -> Result<()> {
    println!("🔐 Generating {} keypair(s)...\n", count);

    let mut accounts = Vec::new();

    for i in 1..=count {
        let (privkey, pubkey) = utils::generate_keypair();
        let address = utils::derive_address(&pubkey)?;

        println!("═══════════════════════════════════════════════════════════");
        println!("Account #{}", i);
        println!("═══════════════════════════════════════════════════════════");
        println!("Address:     {}", address);
        println!("Public Key:  {}", pubkey);
        println!("Private Key: {} ⚠️  KEEP SECRET!", privkey);
        println!();

        accounts.push(serde_json::json!({
            "address": address,
            "pubkey": pubkey,
            "privkey": privkey,
        }));
    }

    if let Some(path) = output {
        let json = serde_json::to_string_pretty(&accounts)?;
        fs::write(&path, json)?;
        println!("✅ Accounts saved to: {}", path.display());
    }

    Ok(())
}

async fn derive_address_from_key(private_key: &str) -> Result<()> {
    // For Ed25519, we need to derive the public key first
    // Parse the private key bytes
    let seed = utils::parse_hex32(private_key)?;

    // Use ed25519-dalek to get public key
    let signing_key = ed25519_dalek::SigningKey::from_bytes(&seed);
    let verifying_key = signing_key.verifying_key();
    let pubkey_hex = format!("0x{}", hex::encode(verifying_key.as_bytes()));

    let address = utils::derive_address(&pubkey_hex)?;

    println!("📖 Address Derivation");
    println!("═══════════════════════════════════════════════════════════");
    println!("Private Key: {}", private_key);
    println!("Public Key:  {}", pubkey_hex);
    println!("Address:     {}", address);

    Ok(())
}

async fn list_devnet_accounts() -> Result<()> {
    println!("📋 DEVNET PRE-FUNDED ACCOUNTS");
    println!("═══════════════════════════════════════════════════════════\n");

    let accounts = utils::load_devnet_config()?;

    for (idx, (address, pubkey, balance)) in accounts.iter().enumerate() {
        let balance_wei: u128 = balance.parse()?;
        let balance_tokens = balance_wei as f64 / 1e18;

        println!("Validator #{}", idx + 1);
        println!("───────────────────────────────────────────────────────────");
        println!("Address:     {}", address);
        println!("Public Key:  {}", pubkey);
        println!("Balance:     {} vc ({:.6} tokens)", balance, balance_tokens);
        println!();
    }

    println!("💡 Use these addresses to transfer tokens to new accounts.");
    println!("   Example: vagecli transaction send --from <validator> --to <new> --value <amount> --private-key <key>");

    Ok(())
}

async fn import_account(private_key: &str, output: Option<PathBuf>) -> Result<()> {
    let seed = utils::parse_hex32(private_key)?;

    let signing_key = ed25519_dalek::SigningKey::from_bytes(&seed);
    let verifying_key = signing_key.verifying_key();
    let pubkey_hex = format!("0x{}", hex::encode(verifying_key.as_bytes()));

    let address = utils::derive_address(&pubkey_hex)?;

    println!("📥 Imported Account");
    println!("═══════════════════════════════════════════════════════════");
    println!("Address:     {}", address);
    println!("Public Key:  {}", pubkey_hex);
    println!("Private Key: {} ⚠️  KEEP SECRET!", private_key);

    if let Some(path) = output {
        let data = serde_json::json!({
            "address": address,
            "pubkey": pubkey_hex,
            "privkey": private_key,
        });
        fs::write(&path, serde_json::to_string_pretty(&data)?)?;
        println!("\n✅ Saved to: {}", path.display());
    }

    Ok(())
}

async fn show_account(address: &str) -> Result<()> {
    println!("📊 Account: {}", address);
    println!("═══════════════════════════════════════════════════════════");
    println!("To query balance, use: vagecli query balance {}", address);
    println!("To query nonce, use:   vagecli query nonce {}", address);

    Ok(())
}
