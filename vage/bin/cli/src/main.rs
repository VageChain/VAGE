use anyhow::Result;
use clap::{Parser, Subcommand};
use serde_json::json;
use std::path::PathBuf;

mod commands;
mod utils;

use commands::{account, node, transaction};

#[derive(Parser)]
#[command(name = "vagecli")]
#[command(about = "VageChain L1 Complete CLI - Manage accounts, transactions, and run the node")]
#[command(version = "0.1.0")]
struct Cli {
    /// URL of the VageChain RPC node (default: http://127.0.0.1:8080/rpc)
    #[arg(
        short,
        long,
        global = true,
        default_value = "http://127.0.0.1:8080/rpc"
    )]
    rpc_url: String,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// 📋 Account Management
    Account {
        #[command(subcommand)]
        action: AccountCommands,
    },

    /// 💰 Transaction Management
    Transaction {
        #[command(subcommand)]
        action: TransactionCommands,
    },

    /// 🖥️  Node Management
    Node {
        #[command(subcommand)]
        action: NodeCommands,
    },

    /// 🔍 Query Blockchain State
    Query {
        #[command(subcommand)]
        action: QueryCommands,
    },
}

#[derive(Subcommand)]
enum AccountCommands {
    /// Generate a new random keypair
    Generate {
        /// Save to file (optional)
        #[arg(short, long)]
        output: Option<PathBuf>,

        /// Generate multiple accounts
        #[arg(short, long, default_value = "1")]
        count: usize,
    },

    /// Derive address from private key
    Derive {
        #[arg(help = "Private key (0x-prefixed hex, 32 bytes)")]
        private_key: String,
    },

    /// List all pre-funded devnet accounts
    ListDevnet,

    /// Import account from private key
    Import {
        #[arg(help = "Private key (0x-prefixed hex)")]
        private_key: String,

        #[arg(short, long, help = "Save to file")]
        output: Option<PathBuf>,
    },

    /// Show account details
    Show {
        #[arg(help = "Account address (0x-prefixed hex)")]
        address: String,
    },
}

#[derive(Subcommand)]
enum TransactionCommands {
    /// Create and sign a transfer transaction
    Send {
        #[arg(long, help = "Sender address")]
        from: String,

        #[arg(long, help = "Recipient address")]
        to: String,

        #[arg(long, help = "Amount in vc (1 token = 10^18 vc)")]
        value: String,

        #[arg(long, help = "Sender's private key for signing")]
        private_key: String,

        #[arg(long, default_value = "0", help = "Transaction nonce")]
        nonce: u64,

        #[arg(long, default_value = "210", help = "Gas limit")]
        gas: u64,
    },

    /// Check transaction status
    Status {
        #[arg(help = "Transaction hash")]
        hash: String,

        #[arg(short, long, default_value = "0", help = "Poll interval in seconds")]
        poll_interval: u64,

        #[arg(short, long, default_value = "10", help = "Max polls")]
        poll_max: u32,
    },

    /// Get pending transactions in mempool
    Pending {
        #[arg(short, long, default_value = "100", help = "Limit")]
        limit: usize,
    },
}

#[derive(Subcommand)]
enum NodeCommands {
    /// Start the VageChain node
    Start {
        #[arg(short, long, help = "Configuration file path")]
        config: Option<PathBuf>,

        #[arg(short, long, help = "Log level (trace, debug, info, warn, error)")]
        log_level: Option<String>,
    },

    /// Show node status and metrics
    Status,

    /// Show node network peers
    Peers,
}

#[derive(Subcommand)]
enum QueryCommands {
    /// Get account balance
    Balance {
        #[arg(help = "Account address")]
        address: String,
    },

    /// Get account nonce
    Nonce {
        #[arg(help = "Account address")]
        address: String,
    },

    /// Get block by height
    Block {
        #[arg(help = "Block height")]
        height: u64,
    },

    /// Get current state root
    StateRoot,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Account { action } => account::handle_account_command(action).await?,
        Commands::Transaction { action } => {
            transaction::handle_transaction_command(&cli.rpc_url, action).await?
        }
        Commands::Node { action } => node::handle_node_command(action).await?,
        Commands::Query { action } => {
            let client = reqwest::Client::new();
            match action {
                QueryCommands::Balance { address } => {
                    query_balance(&client, &cli.rpc_url, &address).await?;
                }
                QueryCommands::Nonce { address } => {
                    query_nonce(&client, &cli.rpc_url, &address).await?;
                }
                QueryCommands::Block { height } => {
                    query_block(&client, &cli.rpc_url, height).await?;
                }
                QueryCommands::StateRoot => {
                    query_state_root(&client, &cli.rpc_url).await?;
                }
            }
        }
    }

    Ok(())
}

async fn query_balance(client: &reqwest::Client, url: &str, address: &str) -> Result<()> {
    let response = utils::call_rpc(client, url, "vage_getBalance", vec![json!(address)]).await?;
    let wei = response
        .as_str()
        .map(|s| s.parse::<u128>().unwrap_or(0))
        .unwrap_or(0);
    let tokens = wei as f64 / 1e18;
    println!("📊 Account Balance");
    println!("  Address:  {}", address);
    println!("  Balance:  {} wei ({:.6} tokens)", wei, tokens);
    Ok(())
}

async fn query_nonce(client: &reqwest::Client, url: &str, address: &str) -> Result<()> {
    let response = utils::call_rpc(client, url, "vage_getNonce", vec![json!(address)]).await?;
    println!("📋 Account Nonce");
    println!("  Address: {}", address);
    println!("  Nonce:   {}", response);
    Ok(())
}

async fn query_block(client: &reqwest::Client, url: &str, height: u64) -> Result<()> {
    let response = utils::call_rpc(
        client,
        url,
        "vage_getBlockByNumber",
        vec![json!(format!("0x{:x}", height))],
    )
    .await?;
    println!("🔗 Block #{}", height);
    println!("{}", serde_json::to_string_pretty(&response)?);
    Ok(())
}

async fn query_state_root(client: &reqwest::Client, url: &str) -> Result<()> {
    let response = utils::call_rpc(client, url, "vage_getStateRoot", vec![]).await?;
    println!("🌳 State Root: {}", response);
    Ok(())
}
