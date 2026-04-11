use vage_node::Startup;
use clap::Parser;
use tracing::info;
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Path to the node configuration file (e.g., config.json)
    #[arg(short, long)]
    config: Option<PathBuf>,

    /// Override the log level (default: info)
    #[arg(short, long, default_value = "info")]
    log_level: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    // Initialize tracing/logging with the specified level
    tracing_subscriber::fmt()
        .with_env_filter(format!("vagechain={},vage_node={},vage_consensus={}", args.log_level, args.log_level, args.log_level))
        .init();

    info!("VageChain L1 Node starting up...");
    
    // Convert Option<PathBuf> to Option<&str> for bootstrap_node and execute
    let config_path = args.config.as_ref().and_then(|p| p.to_str());
    let mut node = Startup::bootstrap_node(config_path).await?;
    
    info!("Bootstrap complete. Entering main event loop.");
    Startup::start_node_event_loop(&mut node).await?;
    
    Ok(())
}
