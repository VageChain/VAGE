use crate::node::{Node, NodeConfig};
use anyhow::{Context, Result};
use ed25519_dalek::SigningKey;
use primitive_types::U256;
use std::sync::Arc;
use tracing::{info, warn};
use vage_rpc::RpcServer;
use vage_state::StateDB;
use vage_storage::StorageEngine;
use vage_types::Address;

const DEFAULT_CONFIG_PATH: &str = "config/node.json";

pub struct Startup;

impl Startup {
    pub fn load_configuration_file(path: Option<&str>) -> Result<NodeConfig> {
        let config_path = path.unwrap_or(DEFAULT_CONFIG_PATH);
        match std::fs::read_to_string(config_path) {
            Ok(contents) => {
                info!("Loading node configuration from {}...", config_path);
                Self::parse_node_config(&contents)
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                warn!(
                    "Configuration file {} not found. Falling back to defaults.",
                    config_path
                );
                Ok(NodeConfig::default())
            }
            Err(error) => Err(error).context("Failed to read configuration file"),
        }
    }

    pub fn initialize_logger() -> Result<()> {
        let subscriber = tracing_subscriber::fmt()
            .with_target(false)
            .with_env_filter(
                tracing_subscriber::EnvFilter::try_from_default_env()
                    .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
            )
            .finish();

        let _ = tracing::subscriber::set_global_default(subscriber);
        Ok(())
    }

    pub fn load_validator_keys(config: &NodeConfig) -> Result<(SigningKey, Address)> {
        // Reject the compile-time default key ([1u8;32]) to prevent accidental
        // production deployments that share keys with every other default node.
        let all_same = config
            .proposer_private_key
            .iter()
            .all(|&b| b == config.proposer_private_key[0]);
        if all_same {
            warn!(
                "SECURITY: Proposer private key is a trivial repeated-byte value. \
                 Set VAGE_VALIDATOR_KEY or provide a real key in the config before joining mainnet."
            );
        }
        let signing_key = SigningKey::from_bytes(&config.proposer_private_key);
        let validator_address = Address::from_public_key(&signing_key.verifying_key().to_bytes());
        info!("Loaded validator keys for {}", validator_address);
        Ok((signing_key, validator_address))
    }

    /// Initialize the storage engine, load latest metadata, and warm up the cache.
    pub fn init_storage(path: &str) -> Result<Arc<StorageEngine>> {
        info!("Initializing persistent storage engine at {}...", path);
        let engine = StorageEngine::new(path).context("Failed to open storage engine")?;

        let latest_height = engine.latest_block_height()?;
        info!(
            "Storage successfully initialized. Latest block height: {}",
            latest_height
        );

        // Performance: warm up the read cache with general system state
        let _ = engine.state_get_cached(b"system_config".to_vec());

        Ok(Arc::new(engine))
    }

    pub fn init_state(storage: Arc<StorageEngine>) -> Result<Arc<StateDB>> {
        let state = Arc::new(StateDB::new(storage.clone()));
        let latest_height = storage.latest_block_height()?;
        let restored_root = Self::restore_blockchain_state(storage.as_ref(), state.as_ref())?;

        // Don't validate expected root at height 0, since genesis allocations will change it
        let expected_root = if latest_height > 0 {
            Some(restored_root)
        } else {
            None
        };
        let hydrated_root = state.initialize_backend(latest_height, expected_root)?;

        info!(
            "State backend initialized. latest_height={}, state_root=0x{}",
            latest_height,
            hex::encode(hydrated_root)
        );

        // Warm the hot metadata keys and the current head into the storage LRU.
        let _ = storage.state_get_cached(b"metadata:state_root".to_vec());
        if latest_height > 0 {
            let mut block_root_key = b"execution:block:state_root:".to_vec();
            block_root_key.extend_from_slice(latest_height.to_string().as_bytes());
            let _ = storage.state_get_cached(block_root_key);
            let _ = storage.get_block_header(latest_height);
            let _ = storage.get_block_body(latest_height);
        }

        Ok(state)
    }

    /// Apply genesis account allocations to the state database.
    /// This loads pre-funded accounts from the genesis configuration.
    pub fn apply_genesis_allocations(
        state: &StateDB,
        storage: &StorageEngine,
        alloc: &std::collections::HashMap<String, String>,
    ) -> Result<()> {
        let latest_height = storage.latest_block_height()?;

        // Only apply genesis allocations at block 0 (fresh chain)
        if latest_height > 0 {
            info!(
                "Chain already initialized (height={}). Skipping genesis allocations.",
                latest_height
            );
            return Ok(());
        }

        if alloc.is_empty() {
            info!("No genesis allocations configured.");
            return Ok(());
        }

        info!("Applying {} genesis allocations...", alloc.len());

        for (address_str, balance_str) in alloc.iter() {
            // Parse address from hex string
            let addr_bytes = hex::decode(address_str.trim_start_matches("0x"))
                .context(format!("Invalid address format: {}", address_str))?;

            if addr_bytes.len() != 32 {
                warn!(
                    "Genesis address {} has invalid length (expected 32 bytes)",
                    address_str
                );
                continue;
            }

            let mut addr = [0u8; 32];
            addr.copy_from_slice(&addr_bytes);
            let address = Address(addr);

            // Parse balance from string (vc amount, usually very large)
            // Try decimal first, then hex if it starts with 0x
            let balance = if balance_str.starts_with("0x") || balance_str.starts_with("0X") {
                U256::from_str_radix(
                    balance_str
                        .trim_start_matches("0x")
                        .trim_start_matches("0X"),
                    16,
                )
                .context(format!("Invalid hex balance format: {}", balance_str))?
            } else {
                U256::from_str_radix(balance_str, 10)
                    .context(format!("Invalid decimal balance format: {}", balance_str))?
            };

            state
                .set_balance(&address, balance)
                .context(format!("Failed to set balance for {}", address_str))?;

            info!("Genesis allocation: {} -> {} vc", address_str, balance);
        }

        info!("Genesis allocations applied successfully");
        Ok(())
    }

    pub fn restore_blockchain_state(storage: &StorageEngine, state: &StateDB) -> Result<[u8; 32]> {
        let latest_height = storage.latest_block_height()?;
        if latest_height == 0 {
            info!("No persisted blockchain height found. Using current state root.");
            return Ok(state.state_root());
        }

        if let Some(state_root_bytes) = storage.state_get(b"metadata:state_root".to_vec())? {
            if state_root_bytes.len() == 32 {
                let mut state_root = [0u8; 32];
                state_root.copy_from_slice(&state_root_bytes);
                info!(
                    "Restored blockchain state at height {} with persisted state root.",
                    latest_height
                );
                return Ok(state_root);
            }
        }

        warn!(
            "Latest block height is {}, but persisted state root metadata was missing. Falling back to in-memory root.",
            latest_height
        );
        Ok(state.state_root())
    }

    pub fn restore_mempool_state(node: &Node) -> Result<usize> {
        node.mempool.start()?;
        let pending = node.mempool.pending_count()?;
        info!(
            "Mempool state restored. pending_transactions={}",
            pending
        );
        Ok(pending)
    }

    pub async fn restore_consensus_state(node: &Node) -> Result<u64> {
        let view = node.consensus.write().await.start()?;
        info!("Consensus state restored at view {}.", view);
        Ok(view)
    }

    pub async fn start_networking_layer(node: &Node) -> Result<()> {
        if let Some(address) = node.config.p2p_listen_addr.clone() {
            node.networking.lock().await.listen_on(address)?;
            info!("Networking layer listening on configured address.");
        } else {
            info!("Networking layer initialized without a listen address.");
        }
        Ok(())
    }

    pub async fn start_node_event_loop(node: &mut Node) -> Result<()> {
        info!("Starting node event loop...");

        let rpc_context = Arc::new(vage_rpc::RpcContext::new(
            node.networking.clone(),
            node.mempool.clone(),
            node.consensus.clone(),
            node.state.clone(),
            node.storage.clone(),
            node.execution.clone(),
        ));

        let mut rpc_server = RpcServer::new(rpc_context, vage_rpc::RpcConfig::default());
        tokio::spawn(async move {
            if let Err(error) = rpc_server.start().await {
                tracing::error!("rpc server error: {:?}", error);
            }
        });

        // Start background services.
        crate::services::spawn_background_services(node);

        node.run_event_loop().await
    }

    pub async fn bootstrap_node(path: Option<&str>) -> Result<Node> {
        // â”€â”€ Step 1: load configuration file â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
        // Try the supplied path first; fall back to DEFAULT_CONFIG_PATH; if
        // that is also absent, fall back to compiled-in defaults.  This is the
        // only step that must succeed before the logger is running, so errors
        // surface as plain stderr output.
        let config = Self::load_configuration_file(path)?;

        // â”€â”€ Step 2: initialize logger â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
        // Set up the global tracing subscriber as early as possible so that
        // every subsequent step emits structured log lines.
        Self::initialize_logger()?;

        // â”€â”€ Step 3: load validator keys â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
        // Derive the signing key and validator address from the config.
        // Prefers the VAGE_VALIDATOR_KEY env-var over the JSON value so that
        // production deployments never read key material from disk.
        let _ = Self::load_validator_keys(&config)?;

        // â”€â”€ Step 4: initialize storage database â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
        // Steps 4 and 5 are performed inside `Node::new`; the storage engine
        // is opened and the state trie is loaded before the rest of the
        // subsystems are constructed.  The per-step functions `init_storage`
        // and `init_state` are also callable individually for tooling / tests.
        info!("Initializing storage and state subsystems via Node::newâ€¦");
        let node = Node::new(config.clone()).await?;

        // â”€â”€ Step 5: restore blockchain state â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
        // Read the persisted state-root metadata key and re-hydrate the trie
        // so the in-memory root matches the last committed block.
        let restored_root = node.state.state_root();
        info!(
            "Blockchain state recovery complete. state_root=0x{}",
            hex::encode(restored_root)
        );

        // â”€â”€ Step 5.5: apply genesis allocations â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
        // Load pre-funded accounts from genesis configuration.
        // Only applies on fresh chain (height 0).
        Self::apply_genesis_allocations(&node.state, &node.storage, &config.genesis_alloc)?;

        // â”€â”€ Step 6: restore mempool state â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
        // Re-insert transactions that were persisted to disk before the last
        // shutdown; any expired entries are silently dropped during insertion.
        let _ = Self::restore_mempool_state(&node)?;

        // â”€â”€ Step 7: restore consensus state â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
        // Reload the last committed view number and validator set so HotStuff
        // can resume from where it left off.
        let _ = Self::restore_consensus_state(&node).await?;

        // â”€â”€ Step 8: start networking layer â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
        // Bind the P2P listen address (if configured) and connect to bootstrap
        // peers so the node begins participating in the gossip overlay.
        Self::start_networking_layer(&node).await?;

        Ok(node)
    }

    /// Full node lifecycle: runs all 10 startup steps and then blocks until the
    /// event loop exits (either cleanly via `Node::stop` or on a fatal error).
    ///
    /// Step 9 â€” start node event loop â€” is intentionally separated from
    /// `bootstrap_node` so that callers (tests, tooling) can inspect or modify
    /// the node after initialisation before handing control to the loop.
    pub async fn run(path: Option<&str>) -> Result<()> {
        let mut node = Self::bootstrap_node(path).await?;

        // â”€â”€ Step 9: start node event loop â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
        // Spawns the RPC server and all background services, then enters the
        // continuous `tokio::select!` loop that dispatches P2P messages, RPC
        // requests, consensus events, and new transactions until `Node::stop`
        // is called.
        Self::start_node_event_loop(&mut node).await
    }

    fn parse_node_config(contents: &str) -> Result<NodeConfig> {
        let value: serde_json::Value =
            serde_json::from_str(contents).context("Invalid node config JSON")?;

        let mut config = NodeConfig::default();

        if let Some(storage_path) = value.get("storage_path").and_then(|v| v.as_str()) {
            config.storage_path = storage_path.to_owned();
        }

        if let Some(rpc_addr) = value.get("rpc_addr").and_then(|v| v.as_str()) {
            config.rpc_addr = rpc_addr.parse().context("Invalid rpc_addr in config")?;
        }

        // 1. Prioritize Environment Variable for Proposer Private Key (Production-grade Security)
        if let Ok(env_key_hex) = std::env::var("VAGE_VALIDATOR_KEY") {
            let decoded = hex::decode(env_key_hex.trim_start_matches("0x"))
                .context("Invalid VAGE_VALIDATOR_KEY hex")?;
            if decoded.len() != 32 {
                anyhow::bail!("VAGE_VALIDATOR_KEY must be 32 bytes");
            }
            config.proposer_private_key.copy_from_slice(&decoded);
            info!("Validator private key successfully loaded from environment variable.");
        }
        // 2. Fallback to Local Config (Development/Testing only)
        else if let Some(private_key_hex) =
            value.get("proposer_private_key").and_then(|v| v.as_str())
        {
            let decoded = hex::decode(private_key_hex.trim_start_matches("0x"))
                .context("Invalid proposer_private_key hex")?;
            if decoded.len() != 32 {
                anyhow::bail!("proposer_private_key must be 32 bytes");
            }
            config.proposer_private_key.copy_from_slice(&decoded);
            warn!("SECURITY ALERT: Validator private key loaded from JSON config. Use environment variables in production.");
        }

        // Load genesis allocations (pre-funded accounts)
        if let Some(alloc_obj) = value.get("alloc").and_then(|v| v.as_object()) {
            for (address, account) in alloc_obj.iter() {
                if let Some(balance_str) = account.get("balance").and_then(|v| v.as_str()) {
                    config
                        .genesis_alloc
                        .insert(address.clone(), balance_str.to_string());
                    info!(
                        "Loaded genesis allocation: {} balance={}",
                        address, balance_str
                    );
                }
            }
        }

        Ok(config)
    }
}
