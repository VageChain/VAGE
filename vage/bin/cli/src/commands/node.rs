use crate::NodeCommands;
use anyhow::Result;
use std::path::PathBuf;

pub async fn handle_node_command(action: NodeCommands) -> Result<()> {
    match action {
        NodeCommands::Start { config, log_level } => {
            start_node(config, log_level).await?;
        }
        NodeCommands::Status => {
            show_status().await?;
        }
        NodeCommands::Peers => {
            show_peers().await?;
        }
    }
    Ok(())
}

async fn start_node(config: Option<PathBuf>, log_level: Option<String>) -> Result<()> {
    let config_path = config.unwrap_or_else(|| PathBuf::from("configs/devnet.json"));
    let log_level_str = log_level.unwrap_or_else(|| "info".to_string());

    println!("🖥️  Starting VageChain Node");
    println!("═══════════════════════════════════════════════════════════");
    println!("Config file: {}", config_path.display());
    println!("Log level:   {}", log_level_str);
    println!();
    println!("📡 Launching the node process...");
    println!();

    // Try to run the node binary
    let target_dir = if cfg!(debug_assertions) {
        "target/debug"
    } else {
        "target/release"
    };

    let node_binary = if cfg!(windows) {
        format!("{}\\vagechain.exe", target_dir)
    } else {
        format!("{}/vagechain", target_dir)
    };

    if !std::path::Path::new(&node_binary).exists() {
        println!("⚠️  Node binary not found at: {}", node_binary);
        println!("Build the project first with: cargo build --release");
        return Ok(());
    }

    println!("✅ Node binary found at: {}", node_binary);
    println!("📝 To start manually, run:");
    println!("   {} --config {}", node_binary, config_path.display());
    println!();
    println!("🌐 Once running, the RPC server will be available at:");
    println!("   http://127.0.0.1:8080/rpc");

    Ok(())
}

async fn show_status() -> Result<()> {
    let client = reqwest::Client::new();
    let rpc_url = "http://127.0.0.1:8080/rpc";

    println!("📊 VageChain Node Status");
    println!("═══════════════════════════════════════════════════════════");

    // Try to connect
    let payload = serde_json::json!({
        "jsonrpc": "2.0",
        "method": "vage_getStateRoot",
        "params": [],
        "id": 1
    });

    match client.post(rpc_url).json(&payload).send().await {
        Ok(response) => match response.json::<serde_json::Value>().await {
            Ok(result) => {
                println!("✅ Node is running!");
                println!("RPC URL: {}", rpc_url);
                if let Some(state_root) = result.get("result") {
                    println!("State Root: {}", state_root);
                }
            }
            Err(_) => {
                println!("❌ Node is not responding properly");
            }
        },
        Err(_) => {
            println!("❌ Cannot connect to node");
            println!("📡 RPC URL: {}", rpc_url);
            println!("💡 Make sure the node is running: vagecli node start");
        }
    }

    Ok(())
}

async fn show_peers() -> Result<()> {
    let client = reqwest::Client::new();
    let rpc_url = "http://127.0.0.1:8080/rpc";

    println!("👥 Network Peers");
    println!("═══════════════════════════════════════════════════════════");

    let payload = serde_json::json!({
        "jsonrpc": "2.0",
        "method": "vage_peerCount",
        "params": [],
        "id": 1
    });

    match client.post(rpc_url).json(&payload).send().await {
        Ok(response) => match response.json::<serde_json::Value>().await {
            Ok(result) => {
                if let Some(peers) = result.get("result") {
                    println!("Connected Peers: {}", peers);
                }
            }
            Err(_) => {
                println!("❌ Failed to fetch peer count");
            }
        },
        Err(_) => {
            println!("❌ Cannot connect to RPC endpoint at {}", rpc_url);
        }
    }

    Ok(())
}
