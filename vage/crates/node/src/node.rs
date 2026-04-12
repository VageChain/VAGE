use anyhow::Result;
use ed25519_dalek::SigningKey;
use libp2p::PeerId;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{mpsc, Mutex, RwLock};
use tokio::time::{interval, MissedTickBehavior};
use tracing::info;
use vage_block::{Block, BlockBuilder};
use vage_consensus::hotstuff::proposer::Proposer;
use vage_consensus::hotstuff::vote::{QuorumCertificate, Vote};
use vage_consensus::Consensus;
use vage_execution::Executor;
use vage_mempool::{Mempool, MempoolConfig};
use vage_networking::{
    ChainSyncState, GossipMessage, L1Request, L1Response, P2PConfig, P2PNetwork, RpcRequestHandler,
    RpcStateProofQuery, RpcStateProofRequest, RpcStateProofResponse, RpcStateProofValue,
    RpcSyncClient, RpcVerifiedHeaderEnvelope,
};
use vage_state::StateDB;
use vage_storage::StorageEngine;
use vage_types::{Address, Transaction, Validator};
use vage_zk::ZkEngine;

#[derive(Clone, Debug)]
pub enum RpcRequestEvent {
    SubmitTransaction(Transaction),
    GetBlock(u64),
    GetStateRoot,
    GetNetworkStatus,
}

#[derive(Clone, Debug)]
pub enum ConsensusEvent {
    BlockProposal(vage_block::Block),
    Vote(Vote),
    QuorumCertificate(QuorumCertificate),
    NewTransaction(Transaction),
    Tick,
}

#[derive(Clone, Debug)]
pub enum NodeEvent {
    P2PMessage(GossipMessage),
    RpcRequest(RpcRequestEvent),
    Consensus(ConsensusEvent),
    NewTransaction(Transaction),
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub enum NodeMode {
    /// Full consensus participant: proposes blocks, votes, runs the EVM.
    Validator,
    /// Follows the chain, executes blocks, serves RPC Ã¢â‚¬â€ no proposing or voting.
    #[default]
    FullNode,
    /// Syncs only block headers via aggregated signatures; minimal resource use.
    LightClient,
}

#[derive(Clone, Debug)]
pub struct NodeConfig {
    pub storage_path: String,
    pub rpc_addr: SocketAddr,
    pub proposer_private_key: [u8; 32],
    pub p2p_listen_addr: Option<libp2p::Multiaddr>,
    pub bootstrap_peers: Vec<(libp2p::PeerId, libp2p::Multiaddr)>,
    pub discovery_interval: Duration,
    pub discovery_backoff: Duration,
    pub max_peers: usize,
    pub mempool: MempoolConfig,
    /// Operating mode Ã¢â‚¬â€ governs which subsystems are started.
    pub mode: NodeMode,
    /// Genesis account allocations (address -> balance in vc)
    pub genesis_alloc: std::collections::HashMap<String, String>,
}

impl Default for NodeConfig {
    fn default() -> Self {
        Self {
            storage_path: "data/blockchain.redb".to_string(),
            rpc_addr: "127.0.0.1:8080"
                .parse()
                .expect("default rpc address should parse"),
            proposer_private_key: [1u8; 32],
            p2p_listen_addr: None,
            bootstrap_peers: Vec::new(),
            discovery_interval: Duration::from_secs(30),
            discovery_backoff: Duration::from_secs(5),
            max_peers: 64,
            mempool: MempoolConfig::default(),
            mode: NodeMode::default(),
            genesis_alloc: std::collections::HashMap::new(),
        }
    }
}

/// The core node struct. Shared mutable subsystems use async locks so the
/// live state can be accessed from both the event loop and the RPC layer.
/// so that the live state can be accessed from both the event loop and the
/// RPC layer simultaneously without cloning divergent snapshots.
pub struct Node {
    pub config: NodeConfig,
    /// Shared P2P networking layer. Mutex avoids requiring `P2PNetwork` to be
    /// `Sync`, which libp2p's Windows-backed internals do not satisfy.
    pub networking: Arc<Mutex<P2PNetwork>>,
    pub mempool: Arc<Mempool>,
    /// Shared consensus engine Ã¢â‚¬â€ Arc<RwLock<>> means the RPC validator-set
    /// queries see the same state that the event loop mutates.
    pub consensus: Arc<RwLock<Consensus>>,
    pub execution: Arc<Executor>,
    pub state: Arc<StateDB>,
    pub storage: Arc<StorageEngine>,
    validator_address: Address,
    proposer_signing_key: SigningKey,
    chain_head: Option<[u8; 32]>,
    running: AtomicBool,
    event_tx: mpsc::UnboundedSender<NodeEvent>,
    event_rx: mpsc::UnboundedReceiver<NodeEvent>,
}

const CONSENSUS_QC_PREFIX: &[u8] = b"consensus:qc:";
const CONSENSUS_VALIDATOR_SET_KEY: &[u8] = b"consensus:validator_set";
const BLOCK_STATE_ROOT_PREFIX: &[u8] = b"execution:block:state_root:";

struct StorageBackedRpcRequestHandler {
    storage: Arc<StorageEngine>,
}

impl StorageBackedRpcRequestHandler {
    fn new(storage: Arc<StorageEngine>) -> Self {
        Self { storage }
    }

    fn load_validators(&self) -> Result<Vec<Validator>> {
        let Some(bytes) = self
            .storage
            .state_get(CONSENSUS_VALIDATOR_SET_KEY.to_vec())?
        else {
            return Ok(Vec::new());
        };

        Ok(bincode::deserialize(&bytes)?)
    }

    fn load_quorum_certificate(&self, block_hash: [u8; 32]) -> Result<Option<QuorumCertificate>> {
        let mut key = Vec::with_capacity(CONSENSUS_QC_PREFIX.len() + block_hash.len());
        key.extend_from_slice(CONSENSUS_QC_PREFIX);
        key.extend_from_slice(&block_hash);

        self.storage
            .state_get(key)?
            .map(|bytes| QuorumCertificate::decode(&bytes))
            .transpose()
    }

    fn build_verified_header_envelopes(
        &self,
        start: u64,
        end: u64,
    ) -> Result<Vec<RpcVerifiedHeaderEnvelope>> {
        let validators = self.load_validators()?;
        let quorum_threshold = if validators.is_empty() {
            0
        } else {
            ((validators.len() * 2) / 3) + 1
        };
        let required_voting_power = if validators.is_empty() {
            0
        } else {
            ((validators
                .iter()
                .filter(|validator| validator.is_active())
                .map(|validator| validator.voting_power)
                .sum::<u64>()
                * 2)
                / 3)
                + 1
        };

        let mut envelopes = Vec::new();
        for height in start..=end {
            let Some(header) = self.storage.get_block_header(height)? else {
                break;
            };

            let consensus_signatures = if height == 0 {
                Vec::new()
            } else {
                let qc = self
                    .load_quorum_certificate(header.hash())?
                    .ok_or_else(|| {
                        anyhow::anyhow!("missing quorum certificate for header {}", height)
                    })?;

                if !qc.verify_with_voting_power(
                    &validators,
                    quorum_threshold,
                    required_voting_power,
                )? {
                    anyhow::bail!(
                        "stored quorum certificate failed validation for header {}",
                        height
                    );
                }

                qc.validators
                    .iter()
                    .copied()
                    .zip(qc.signatures.iter().cloned())
                    .collect()
            };

            envelopes.push(RpcVerifiedHeaderEnvelope {
                header,
                consensus_signatures,
            });
        }

        Ok(envelopes)
    }

    fn block_state_root_key(height: u64) -> Vec<u8> {
        let mut key = Vec::with_capacity(BLOCK_STATE_ROOT_PREFIX.len() + 20);
        key.extend_from_slice(BLOCK_STATE_ROOT_PREFIX);
        key.extend_from_slice(height.to_string().as_bytes());
        key
    }

    fn build_state_proof_response(
        &self,
        request: RpcStateProofRequest,
    ) -> Result<RpcStateProofResponse> {
        let persisted_root = self
            .storage
            .state_get(Self::block_state_root_key(request.height))?
            .ok_or_else(|| {
                anyhow::anyhow!("missing state root for block height {}", request.height)
            })?;
        if persisted_root.len() != 32 {
            anyhow::bail!(
                "invalid persisted state root for block height {}",
                request.height
            );
        }

        let (value, proof) = match request.query {
            RpcStateProofQuery::Account { address } => {
                let (account, proof) = self
                    .storage_backed_state()
                    .export_account_proof_for_height(request.height, &address, request.max_depth)?;
                (RpcStateProofValue::Account(account), proof)
            }
            RpcStateProofQuery::Storage { address, key } => {
                let (value, proof) = self
                    .storage_backed_state()
                    .export_storage_proof_for_height(
                        request.height,
                        &address,
                        key,
                        request.max_depth,
                    )?;
                (RpcStateProofValue::Storage(value), proof)
            }
            RpcStateProofQuery::Minimal { key } => {
                let (value, proof) = self
                    .storage_backed_state()
                    .export_minimal_proof_for_height(request.height, key, request.max_depth)?;
                (RpcStateProofValue::Minimal(value), proof)
            }
        };

        Ok(RpcStateProofResponse {
            height: request.height,
            proof,
            value,
        })
    }

    fn storage_backed_state(&self) -> StateDB {
        StateDB::new(self.storage.clone())
    }
}

impl RpcRequestHandler for StorageBackedRpcRequestHandler {
    fn handle_request(&self, _peer_id: PeerId, request: L1Request) -> Result<L1Response> {
        match request {
            L1Request::GetLatestBlockHeight => Ok(L1Response::respond_latest_block_height(Some(
                self.storage.latest_block_height()?,
            ))),
            L1Request::GetBlock(height) => {
                let block = match (
                    self.storage.get_block_header(height)?,
                    self.storage.get_block_body(height)?,
                ) {
                    (Some(header), Some(body)) => {
                        Some(bincode::serialize(&Block::new(header, body))?)
                    }
                    _ => None,
                };
                Ok(L1Response::respond_block(block))
            }
            L1Request::GetHeaders { start, end } => {
                let headers = self.build_verified_header_envelopes(start, end)?;
                Ok(L1Response::respond_headers(Some(headers)))
            }
            L1Request::GetBlockProof(_) => Ok(L1Response::respond_block_proof(None)),
            L1Request::GetTransaction(_) => Ok(L1Response::respond_transaction(None)),
            L1Request::GetStateProof(request) => Ok(L1Response::respond_state_proof(Some(
                self.build_state_proof_response(request)?,
            ))),
        }
    }
}

impl Node {
    pub async fn new(config: NodeConfig) -> Result<Self> {
        info!("Initializing node...");
        let (event_tx, event_rx) = mpsc::unbounded_channel();

        let storage = crate::startup::Startup::init_storage(&config.storage_path)?;
        let state = crate::startup::Startup::init_state(storage.clone())?;
        let execution = Arc::new(Executor::new(state.clone()));
        let proposer_signing_key = SigningKey::from_bytes(&config.proposer_private_key);
        let validator_address =
            Address::from_public_key(&proposer_signing_key.verifying_key().to_bytes());
        let mempool = Arc::new(Mempool::with_storage(
            config.mempool.clone(),
            state.clone(),
            storage.clone(),
        ));

        let networking = Arc::new(Mutex::new(
            P2PNetwork::new(P2PConfig {
                local_key: libp2p::identity::Keypair::generate_ed25519(),
                bootstrap_peers: config.bootstrap_peers.clone(),
                discovery_interval: config.discovery_interval,
                discovery_backoff: config.discovery_backoff,
                max_peers: config.max_peers,
            })
            .await?,
        ));
        networking
            .lock()
            .await
            .set_rpc_handler(Arc::new(StorageBackedRpcRequestHandler::new(
                storage.clone(),
            )));

        // Pass the shared storage engine into Consensus so both use the same DB.
        let mut consensus = Consensus::with_storage(storage.clone());
        consensus.proposer = Proposer::new(validator_address, mempool.clone(), execution.clone());
        let consensus = Arc::new(RwLock::new(consensus));

        Ok(Self {
            config,
            networking,
            mempool,
            consensus,
            execution,
            state,
            storage,
            validator_address,
            proposer_signing_key,
            chain_head: None,
            running: AtomicBool::new(false),
            event_tx,
            event_rx,
        })
    }

    pub async fn start(&mut self) -> Result<()> {
        if self.running.swap(true, Ordering::SeqCst) {
            return Ok(());
        }

        info!("Starting node services in {:?} mode...", self.config.mode);
        self.mempool.start()?;

        // Consensus is only started for full participants.  Light-client nodes
        // neither propose blocks nor cast votes.
        if self.config.mode != NodeMode::LightClient {
            let _ = self.consensus.write().await.start()?;
        }

        if let Some(address) = self.config.p2p_listen_addr.clone() {
            self.networking.lock().await.listen_on(address)?;
        }

        let rpc_context = Arc::new(vage_rpc::RpcContext::new(
            self.networking.clone(),
            self.mempool.clone(),
            self.consensus.clone(),
            self.state.clone(),
            self.storage.clone(),
            self.execution.clone(),
        ));
        let mut rpc_server = vage_rpc::RpcServer::new(
            rpc_context,
            vage_rpc::RpcConfig {
                addr: self.config.rpc_addr,
                ..Default::default()
            },
        );
        tokio::spawn(async move {
            if let Err(error) = rpc_server.start().await {
                tracing::error!("rpc server error: {:?}", error);
            }
        });

        // Spawn a dedicated P2P listener that continuously polls the networking
        // layer for incoming gossip and forwards every message into the shared
        // event channel.  Running as an independent task means P2P traffic is
        // never starved behind the consensus tick or RPC queue.
        {
            let networking = self.networking.clone();
            let event_tx = self.event_tx.clone();
            tokio::spawn(async move {
                loop {
                    let message = networking.lock().await.receive_message();
                    match message {
                        Some(msg) => {
                            // If the receiver has been dropped the node is
                            // shutting down Ã¢â‚¬â€ exit the loop cleanly.
                            if event_tx.send(NodeEvent::P2PMessage(msg)).is_err() {
                                break;
                            }
                        }
                        None => tokio::time::sleep(Duration::from_millis(10)).await,
                    }
                }
            });
        }

        self.run_event_loop().await
    }

    pub async fn stop(&mut self) -> Result<()> {
        if !self.running.swap(false, Ordering::SeqCst) {
            return Ok(());
        }

        info!("Stopping node services...");

        // Ã¢â€â‚¬Ã¢â€â‚¬ Step 1: stop networking service Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬
        //    Closes all open libp2p connections and shuts down the swarm event
        //    loop so no further inbound messages are accepted.
        self.networking.lock().await.shutdown()?;

        // Ã¢â€â‚¬Ã¢â€â‚¬ Step 2: stop consensus engine Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬
        //    Saves the current view number and validator-set snapshot so the
        //    engine can resume from the same point on restart.
        self.consensus.write().await.stop()?;

        // Ã¢â€â‚¬Ã¢â€â‚¬ Step 3: flush mempool to disk Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬
        //    Serialises every pending transaction into the redb mempool table.
        //    On restart, `restore_mempool_state` will re-insert them.
        let persisted_mempool = self.mempool.persist_mempool_transactions_to_disk()?;
        info!("flushed {} pending transactions to disk", persisted_mempool);

        // Ã¢â€â‚¬Ã¢â€â‚¬ Step 4: persist state root Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬
        //    Commit the in-memory state trie and store the resulting Merkle
        //    root under the well-known metadata key so node restarts can
        //    verify the on-disk trie is consistent with the last committed block.
        let persisted_state_root = self.state.commit()?;
        self.storage.state_put(
            b"metadata:state_root".to_vec(),
            persisted_state_root.to_vec(),
        )?;
        info!(
            "persisted state root: 0x{}",
            hex::encode(persisted_state_root)
        );

        // Ã¢â€â‚¬Ã¢â€â‚¬ Step 5: close storage database Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬
        //    `flush_to_disk` forces an fsync so all redb pages are durable,
        //    then `shutdown` releases the file lock cleanly.
        self.storage.flush_to_disk()?;
        self.storage.shutdown()?;
        info!("Storage database closed. Node shutdown complete.");

        Ok(())
    }

    pub async fn restart(&mut self) -> Result<()> {
        info!("Restarting node...");
        self.stop().await?;

        let replacement = Self::new(self.config.clone()).await?;
        *self = replacement;
        self.start().await
    }

    pub async fn run_event_loop(&mut self) -> Result<()> {
        if !self.running.load(Ordering::SeqCst) {
            self.running.store(true, Ordering::SeqCst);
        }

        info!("Entering node event loop...");
        let mut consensus_tick = interval(Duration::from_millis(250));
        consensus_tick.set_missed_tick_behavior(MissedTickBehavior::Skip);

        while self.running.load(Ordering::SeqCst) {
            // Periodic metrics update
            crate::metrics::MetricsService::record_block_height(
                self.storage.latest_block_height().unwrap_or(0),
            );
            crate::metrics::MetricsService::record_peer_count(
                self.networking.lock().await.peer_count(),
            );
            crate::metrics::MetricsService::record_mempool_size(
                self.mempool.pending_count().unwrap_or(0),
            );

            tokio::select! {
                // Ã¢â€â‚¬Ã¢â€â‚¬ 1. Incoming P2P messages (forwarded by the listener task)
                // Ã¢â€â‚¬Ã¢â€â‚¬ 2. Incoming RPC requests (forwarded by the RPC server)
                // Ã¢â€â‚¬Ã¢â€â‚¬ 3. Consensus events submitted by subsystems
                // Ã¢â€â‚¬Ã¢â€â‚¬ 4. New transactions submitted directly to the node
                // All four sources share the same unbounded channel so they
                // are all first-class citizens in the select and none can
                // starve the others.
                maybe_event = self.event_rx.recv() => {
                    if let Some(event) = maybe_event {
                        // Ã¢â€â‚¬Ã¢â€â‚¬ 5. Dispatch to the appropriate module.
                        self.dispatch_event(event).await?;
                    }
                }
                // Ã¢â€â‚¬Ã¢â€â‚¬ 6. Periodic consensus tick Ã¢â‚¬â€ drives view timeouts and
                //       block proposal attempts even when the event queue is
                //       empty.  Processed asynchronously, same as every other
                //       event.
                _ = consensus_tick.tick() => {
                    self.dispatch_event(NodeEvent::Consensus(ConsensusEvent::Tick)).await?;
                }
            }
        }

        Ok(())
    }

    pub fn event_sender(&self) -> mpsc::UnboundedSender<NodeEvent> {
        self.event_tx.clone()
    }

    pub fn submit_rpc_request(&self, request: RpcRequestEvent) -> Result<()> {
        self.event_tx
            .send(NodeEvent::RpcRequest(request))
            .map_err(|error| anyhow::anyhow!("failed to enqueue rpc request event: {}", error))
    }

    pub fn submit_consensus_event(&self, event: ConsensusEvent) -> Result<()> {
        self.event_tx
            .send(NodeEvent::Consensus(event))
            .map_err(|error| anyhow::anyhow!("failed to enqueue consensus event: {}", error))
    }

    pub fn submit_new_transaction(&self, transaction: Transaction) -> Result<()> {
        self.event_tx
            .send(NodeEvent::NewTransaction(transaction))
            .map_err(|error| anyhow::anyhow!("failed to enqueue transaction event: {}", error))
    }

    async fn dispatch_event(&mut self, event: NodeEvent) -> Result<()> {
        match event {
            NodeEvent::P2PMessage(message) => self.handle_p2p_message(message).await,
            NodeEvent::RpcRequest(request) => self.handle_rpc_request(request).await,
            NodeEvent::Consensus(event) => self.handle_consensus_event(event).await,
            NodeEvent::NewTransaction(transaction) => {
                self.handle_new_transaction(transaction).await
            }
        }
    }

    async fn handle_p2p_message(&mut self, message: GossipMessage) -> Result<()> {
        match message {
            GossipMessage::Transaction(payload) => {
                let transaction: Transaction = bincode::deserialize(&payload)?;
                self.handle_new_transaction(transaction).await?;
            }
            GossipMessage::Block(payload) => {
                let block: vage_block::Block = bincode::deserialize(&payload)?;
                self.handle_network_block_proposal(block).await?;
            }
            GossipMessage::Vote(payload) => {
                let vote = Vote::decode(&payload)?;
                let _ = self.consensus.write().await.process_vote(vote)?;
            }
            GossipMessage::QuorumCertificate(payload) => {
                let qc = QuorumCertificate::decode(&payload)?;
                self.handle_consensus_event(ConsensusEvent::QuorumCertificate(qc))
                    .await?;
            }
            GossipMessage::StateSync(_) => {
                info!("received state sync gossip message");
            }
        }

        Ok(())
    }

    async fn handle_rpc_request(&mut self, request: RpcRequestEvent) -> Result<()> {
        match request {
            RpcRequestEvent::SubmitTransaction(transaction) => {
                self.handle_rpc_transaction_submission(transaction).await?;
            }
            RpcRequestEvent::GetBlock(height) => {
                let _ = self.storage.get_block_header(height)?;
            }
            RpcRequestEvent::GetStateRoot => {
                let _ = self.state.state_root();
            }
            RpcRequestEvent::GetNetworkStatus => {
                let _ = self.networking.lock().await.peer_count();
            }
        }

        Ok(())
    }

    async fn handle_consensus_event(&mut self, event: ConsensusEvent) -> Result<()> {
        match event {
            ConsensusEvent::BlockProposal(block) => {
                let _ = self.consensus.write().await.process_block_proposal(block)?;
            }
            ConsensusEvent::Vote(vote) => {
                // Start the consensus-latency clock when a vote arrives.
                let vote_received_at = std::time::Instant::now();
                let mut consensus = self.consensus.write().await;
                let previous_finalized_height = consensus.finalized_block_height;
                let _ = consensus.process_vote(vote)?;
                if consensus.finalized_block_height > previous_finalized_height {
                    if let Some(block) = consensus.latest_finalized_block() {
                        drop(consensus); // release lock before await
                                         // Track 5: record the time from vote receipt to finalization.
                        crate::metrics::MetricsService::record_consensus_latency(
                            vote_received_at.elapsed(),
                        );
                        self.handle_finalized_block(block).await?;
                    }
                }
            }
            ConsensusEvent::QuorumCertificate(qc) => {
                let _ = qc;
            }
            ConsensusEvent::NewTransaction(_transaction) => {
                if self.config.mode == NodeMode::Validator {
                    let _ = self.produce_and_broadcast_block_proposal(256).await?;
                }
            }
            ConsensusEvent::Tick => {
                self.synchronize_if_behind().await?;
                if self.config.mode == NodeMode::Validator {
                    let _ = self.produce_and_broadcast_block_proposal(256).await?;
                }
            }
        }

        Ok(())
    }

    async fn handle_new_transaction(&mut self, transaction: Transaction) -> Result<()> {
        let tx_hash = self.mempool.add_transaction(transaction)?;
        if let Some(message) = self.mempool.broadcast_new_transaction_to_peers(tx_hash)? {
            if let Err(error) = self.networking.lock().await.broadcast_message(message) {
                tracing::warn!("transaction gossip broadcast skipped: {}", error);
            }
        }
        Ok(())
    }

    async fn handle_rpc_transaction_submission(&mut self, transaction: Transaction) -> Result<()> {
        // Ã¢â€â‚¬Ã¢â€â‚¬ Step 1: receive transaction from RPC.
        //    Basic structural checks (size, signature format, nonce bounds)
        //    before touching any shared state.  Cheap and allocation-free.
        transaction.validate_basic()?;

        // Ã¢â€â‚¬Ã¢â€â‚¬ Step 2 + 3: full validation + insert into mempool.
        //    `add_transaction` runs the complete TxValidator pipeline
        //    (signature, balance, nonce, gas, duplicate detection) and, on
        //    success, atomically inserts the transaction into the pool and
        //    persists it to disk.
        let tx_hash = self.mempool.add_transaction(transaction.clone())?;
        info!("rpc transaction accepted: hash=0x{}", hex::encode(tx_hash));

        // Ã¢â€â‚¬Ã¢â€â‚¬ Step 4: broadcast transaction to P2P peers.
        //    `broadcast_new_transaction_to_peers` checks the gossip tracker so
        //    we never re-broadcast a transaction that arrived via gossip.
        if let Some(message) = self.mempool.broadcast_new_transaction_to_peers(tx_hash)? {
            if let Err(error) = self.networking.lock().await.broadcast_message(message) {
                tracing::warn!("rpc transaction p2p broadcast skipped: {}", error);
            }
        }

        // Ã¢â€â‚¬Ã¢â€â‚¬ Step 5: notify consensus proposer so it can trigger a new block
        //    proposal when the node is the current leader.
        self.handle_consensus_event(ConsensusEvent::NewTransaction(transaction))
            .await
    }

    async fn handle_network_block_proposal(&mut self, block: vage_block::Block) -> Result<()> {
        // Ã¢â€â‚¬Ã¢â€â‚¬ Step 1: received block proposal from the P2P network.
        //    Already deserialized by handle_p2p_message; `block` is the
        //    canonical in-memory representation.
        info!(
            "received block proposal: height={}, txs={}, proposer=0x{}",
            block.height(),
            block.transaction_count(),
            hex::encode(block.header.proposer)
        );

        // Ã¢â€â‚¬Ã¢â€â‚¬ Step 2: validate block header.
        //    Checks: parent hash not zero, timestamp monotonicity, valid
        //    proposer address, and correct block height.
        block.header.validate_basic()?;

        // Ã¢â€â‚¬Ã¢â€â‚¬ Step 3: validate transactions.
        //    Structural + signature checks on every transaction in the
        //    block body, independent of the current chain state.
        self.execution.validate_block_transactions(&block)?;

        // Ã¢â€â‚¬Ã¢â€â‚¬ Step 4 + 5: execute transactions and compute new state root.
        //    Applies every transaction against the current state, advances
        //    account nonces and balances, and returns the resulting root hash.
        let computed_state_root = self.execution.execute_block(block.clone())?;

        // Ã¢â€â‚¬Ã¢â€â‚¬ Step 6: verify the computed state root matches the block header.
        //    A mismatch means the proposer is either faulty or malicious;
        //    we reject the proposal without penalising our local state.
        if computed_state_root != block.header.state_root {
            anyhow::bail!(
                "state root mismatch on block proposal at height={}: computed=0x{}, header=0x{}",
                block.height(),
                hex::encode(computed_state_root),
                hex::encode(block.header.state_root)
            );
        }

        // Ã¢â€â‚¬Ã¢â€â‚¬ Step 7: pass the validated block to the consensus engine.
        //    HotStuff will cast a vote if the block is safe to extend and we
        //    are the correct voter for this view.
        let _ = self.consensus.write().await.process_block_proposal(block)?;
        Ok(())
    }

    async fn handle_finalized_block(&mut self, block: vage_block::Block) -> Result<()> {
        info!(
            "finalizing block: height={}, txs={}",
            block.height(),
            block.transaction_count()
        );

        // Ã¢â€â‚¬Ã¢â€â‚¬ Step 2: apply state changes.
        //    `state.commit()` flushes the in-memory state trie to the
        //    storage backend and returns the persisted Merkle root hash.
        let persisted_state_root = self.state.commit()?;
        if persisted_state_root != block.header.state_root {
            anyhow::bail!(
                "state root mismatch after commit at height={}: persisted=0x{}, block=0x{}",
                block.height(),
                hex::encode(persisted_state_root),
                hex::encode(block.header.state_root)
            );
        }

        // Ã¢â€â‚¬Ã¢â€â‚¬ Step 3: persist block header and body to storage.
        //    `atomic_block_commit` writes both in a single redb transaction
        //    so a crash between the two writes cannot leave a partial record.
        let header_bytes = bincode::serialize(&block.header)?;
        let body_bytes = bincode::serialize(&block.body)?;
        self.storage
            .atomic_block_commit(block.height(), header_bytes, body_bytes)?;

        // Ã¢â€â‚¬Ã¢â€â‚¬ Step 4: persist the canonical state root for this height.
        //    Stored under a well-known key so node restarts can verify that
        //    the on-disk state trie matches the last committed block.
        self.storage.state_put(
            b"metadata:state_root".to_vec(),
            block.header.state_root.to_vec(),
        )?;
        self.storage.state_put(
            StorageBackedRpcRequestHandler::block_state_root_key(block.height()),
            block.header.state_root.to_vec(),
        )?;
        self.state.snapshot_state(block.height())?;

        // Generate and persist a ZK block validity proof so light clients can
        // verify the block's execution integrity without a full state transition.
        if !block.body.transactions.is_empty() {
            let zk_engine = ZkEngine::new();
            let block_proof = zk_engine.generate_block_validity_proof(&block, &[])?;
            if let Err(zk_err) =
                zk_engine.store_block_proof(&self.storage, block.height(), &block_proof)
            {
                tracing::warn!(
                    "ZK proof storage failed for block {}: {}  (non-fatal, continuing)",
                    block.height(),
                    zk_err
                );
            } else {
                info!(
                    "ZK block validity proof stored for height={}",
                    block.height()
                );
            }
        } else {
            info!(
                "Skipping ZK proof generation for empty block at height={}",
                block.height()
            );
        }

        // Ã¢â€â‚¬Ã¢â€â‚¬ Step 5: remove included transactions from the mempool.
        //    Prevents already-executed transactions from being re-selected
        //    in future block proposals and frees the per-account nonce slots.
        self.mempool
            .remove_transactions_after_block_commit(&block)?;
        info!(
            "removed {} finalized transactions from mempool",
            block.transaction_count()
        );

        // Ã¢â€â‚¬Ã¢â€â‚¬ Step 5b: advance the MEV commit-reveal pool's block clock.
        //    Evicts expired unrevealed commits and enables the pool to serve
        //    the next block's randomized, sandwich-protected transaction list.
        if let Err(mev_err) = self.mempool.on_block_height(block.height()) {
            tracing::warn!(
                "MEV pool clock advance failed at height={}: {} (non-fatal)",
                block.height(),
                mev_err
            );
        }

        // Ã¢â€â‚¬Ã¢â€â‚¬ Step 6: update the local chain head pointer.
        self.chain_head = Some(block.hash());
        info!(
            "chain head advanced: height={}, hash=0x{}",
            block.height(),
            hex::encode(block.hash())
        );

        // Ã¢â€â‚¬Ã¢â€â‚¬ Step 7: broadcast the finalized block to all peers.
        //    Allows other nodes that may have missed the proposal to apply
        //    the block and advance their own chain head without re-syncing.
        if let Err(error) = self
            .networking
            .lock()
            .await
            .broadcast_message(GossipMessage::Block(bincode::serialize(&block)?))
        {
            tracing::warn!("finalized block broadcast skipped: {}", error);
        }

        Ok(())
    }

    async fn is_local_leader(&self) -> bool {
        let consensus = self.consensus.read().await;
        if let Some(leader) = consensus.current_leader() {
            leader == self.validator_address
        } else {
            self.local_proposer().is_leader(consensus.current_view())
        }
    }

    fn local_proposer(&self) -> Proposer {
        Proposer::new(
            self.validator_address,
            self.mempool.clone(),
            self.execution.clone(),
        )
    }

    fn next_block_template(&self) -> Result<Block> {
        let latest_height = self.storage.latest_block_height()?;
        let state_root = self.state.state_root();

        let Some(parent_header) = self.storage.get_block_header(latest_height)? else {
            return Ok(Block::genesis(state_root));
        };

        let mut builder = BlockBuilder::new(&parent_header);
        builder.set_state_root(state_root);
        builder.set_proposer(self.validator_address);
        Ok(builder.build())
    }

    async fn produce_and_broadcast_block_proposal(
        &mut self,
        limit: usize,
    ) -> Result<Option<Block>> {
        // Ã¢â€â‚¬Ã¢â€â‚¬ Step 1: detect if this node is the current leader.
        //    HotStuff assigns the proposer role round-robin over the validator
        //    set.  If we are not the leader for this view we return immediately
        //    without touching the mempool or execution engine.
        if !self.is_local_leader().await {
            return Ok(None);
        }

        let start_time = std::time::Instant::now();

        // Ã¢â€â‚¬Ã¢â€â‚¬ Step 2: fetch transactions from the mempool.
        //    Returns up to `limit` transactions in priority order (highest
        //    gas price first) with gap-free nonce sequences per sender.
        //    Returns early if the pool is empty so we don't build empty blocks.
        let transactions = self.mempool.provide_transactions_to_block_proposer(limit)?;
        if transactions.is_empty() {
            return Ok(None);
        }

        info!(
            "building block proposal with {} transactions",
            transactions.len()
        );

        // Ã¢â€â‚¬Ã¢â€â‚¬ Step 3: build the new block template.
        //    `next_block_template` derives the parent hash, height, and
        //    current state root from storage and sets the local validator
        //    as the proposer.
        let proposer = self.local_proposer();
        let template = self.next_block_template()?;

        // Ã¢â€â‚¬Ã¢â€â‚¬ Step 4: execute transactions.
        //    `produce_block_from_transactions` applies every transaction
        //    against the current state, advancing nonces and balances, and
        //    returns the block with filled-in receipts.
        let mut block = self
            .execution
            .produce_block_from_transactions(template, transactions)?;

        // Ã¢â€â‚¬Ã¢â€â‚¬ Step 5: compute the new state root.
        //    After execution the state trie is dirty; `compute_block_state_root`
        //    hashes it and returns the Merkle root without committing to disk.
        let computed_state_root = self.execution.compute_block_state_root();
        block.header.state_root = computed_state_root;
        block.header.proposer = self.validator_address;
        block.compute_roots();

        // Ã¢â€â‚¬Ã¢â€â‚¬ Step 6: sign the block.
        //    The proposer attaches an Ed25519 signature over the block hash so
        //    that validators can verify the proposal came from the elected leader.
        proposer.sign_block(&mut block, &self.proposer_signing_key)?;

        // Ã¢â€â‚¬Ã¢â€â‚¬ Step 7: broadcast the block proposal.
        //    First via the proposer's internal channel (so the local consensus
        //    engine processes it atomically with the QC attachment), then over
        //    P2P gossip so every other validator receives it.
        let quorum_certificate =
            QuorumCertificate::new(block.parent_hash(), 0, Vec::new(), Vec::new());
        let proposal = proposer.attach_quorum_certificate(block.clone(), quorum_certificate);
        let _ = proposer.broadcast_proposal(&proposal)?;
        if let Err(error) = self
            .networking
            .lock()
            .await
            .broadcast_message(GossipMessage::Block(bincode::serialize(&proposal.block)?))
        {
            tracing::warn!("block proposal broadcast skipped: {}", error);
        }

        let duration = start_time.elapsed();
        crate::metrics::MetricsService::record_block_production_time(duration);

        info!(
            "broadcast block proposal: height={}, txs={}, state_root=0x{}, time={:?}",
            proposal.block.height(),
            proposal.block.transaction_count(),
            hex::encode(proposal.block.header.state_root),
            duration
        );

        Ok(Some(proposal.block))
    }

    async fn synchronize_if_behind(&mut self) -> Result<()> {
        // Ã¢â€â‚¬Ã¢â€â‚¬ Step 1: detect whether this node is behind the network.
        //    Pick any connected peer; if the node has no peers yet, skip
        //    silently Ã¢â‚¬â€ we will retry on the next consensus tick.
        let peer_id = {
            let net = self.networking.lock().await;
            net.peer_store.connected_peers().first().map(|p| p.peer_id)
        };

        let Some(peer_id) = peer_id else {
            tracing::debug!("sync skipped: no connected peers");
            return Ok(());
        };

        let mut net = self.networking.lock().await;

        let local_height = self.storage.latest_block_height()?;
        let remote_height = net.request_latest_block_height(peer_id).await?;
        if remote_height <= local_height {
            return Ok(());
        }

        info!(
            "node is behind peer {:?} at local_height={} Ã¢â‚¬â€ starting sync",
            peer_id, local_height
        );

        // Ã¢â€â‚¬Ã¢â€â‚¬ Steps 3Ã¢â‚¬â€œ6: download, verify, apply, and update state.
        //    `synchronize_chain_from_peer` iterates every missing height in
        //    order and for each block calls:
        //      Ã¢â‚¬â€ Step 3: `rpc_client.request_block(peer_id, height)`
        //      Ã¢â‚¬â€ Step 4: `self.validate_downloaded_block(bytes)` (header +
        //                  signature + transaction structural checks)
        //      Ã¢â‚¬â€ Step 5: `self.apply_downloaded_block(block)` (execute txs,
        //                  verify state-root match)
        //      Ã¢â‚¬â€ Step 6: `self.update_local_chain_head(block)` (atomic
        //                  storage commit, advances local height)
        let mut applied_blocks = 0u64;
        let mut new_local_head = local_height;
        for height in (local_height + 1)..=remote_height {
            let block_bytes = net
                .request_block(peer_id, height)
                .await?
                .ok_or_else(|| anyhow::anyhow!("missing block at height {}", height))?;

            let block = self.validate_downloaded_block(&block_bytes)?;
            self.apply_downloaded_block(&block)?;
            self.update_local_chain_head(&block)?;
            applied_blocks = applied_blocks.saturating_add(1);
            new_local_head = block.height();
        }
        drop(net);

        let outcome = vage_networking::ChainSyncOutcome {
            was_out_of_sync: true,
            remote_height,
            applied_blocks,
            new_local_head,
        };

        // Advance the in-memory chain-head pointer to match the last block
        // written to storage by update_local_chain_head.
        if let Some(header) = self.storage.get_block_header(outcome.new_local_head)? {
            self.chain_head = Some(header.hash());
        }

        info!(
            "sync complete from peer {:?}: applied={}, remote_height={}, new_head={}",
            peer_id, outcome.applied_blocks, outcome.remote_height, outcome.new_local_head
        );

        Ok(())
    }
}

impl ChainSyncState for Node {
    /// Step 1 / Step 2 support: returns the height of the last block this
    /// node has committed to storage.  Used by both `detect_node_out_of_sync_state`
    /// (to compare against the peer height) and `synchronize_chain_from_peer`
    /// (to determine the first missing height to download).
    fn local_block_height(&self) -> Result<u64> {
        self.storage.latest_block_height()
    }

    /// Step 4: validate a raw block received from a peer.
    ///
    /// Performs: deserialisation, header structural check, and transaction
    /// signature + size checks.  Does NOT touch the state trie so it is
    /// safe to call on a block that has not yet been applied.
    fn validate_downloaded_block(&self, block_bytes: &[u8]) -> Result<vage_block::Block> {
        let block: vage_block::Block = bincode::deserialize(block_bytes)?;
        block.validate_basic()?;
        self.execution.validate_block_transactions(&block)?;
        Ok(block)
    }

    /// Step 5: execute all transactions in the block and verify the resulting
    /// state root matches the one recorded in the block header.
    ///
    /// On mismatch the block is rejected and sync aborts for this peer; the
    /// caller can retry with a different peer.
    fn apply_downloaded_block(&self, block: &vage_block::Block) -> Result<()> {
        let computed_state_root = self.execution.execute_block(block.clone())?;
        if computed_state_root != block.header.state_root {
            anyhow::bail!(
                "state root mismatch for downloaded block at height={}: computed=0x{}, header=0x{}",
                block.height(),
                hex::encode(computed_state_root),
                hex::encode(block.header.state_root)
            );
        }
        Ok(())
    }

    /// Step 6: atomically write the block header and body to persistent storage,
    /// advancing the node's canonical chain head for this height.
    fn update_local_chain_head(&self, block: &vage_block::Block) -> Result<()> {
        let header_bytes = bincode::serialize(&block.header)?;
        let body_bytes = bincode::serialize(&block.body)?;
        self.storage
            .atomic_block_commit(block.height(), header_bytes, body_bytes)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::{ConsensusEvent, Node, NodeConfig};
    use ed25519_dalek::SigningKey;
    use primitive_types::U256;
    use std::fs;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};
    use vage_block::{Block, BlockBody, BlockHeader};
    use vage_consensus::hotstuff::vote::Vote;
    use vage_types::validator::ValidatorStatus;
    use vage_types::{Address, Validator};

    fn unique_storage_path(name: &str) -> PathBuf {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock should be valid")
            .as_nanos();
        std::env::temp_dir().join(format!("vage-{name}-{unique}.redb"))
    }

    fn test_config(name: &str, proposer_private_key: [u8; 32]) -> (NodeConfig, PathBuf) {
        let path = unique_storage_path(name);
        let mut config = NodeConfig::default();
        config.storage_path = path.to_string_lossy().into_owned();
        config.rpc_addr = "127.0.0.1:0"
            .parse()
            .expect("ephemeral rpc address should parse");
        config.proposer_private_key = proposer_private_key;
        (config, path)
    }

    fn active_validator_from_key(signing_key: &SigningKey) -> Validator {
        let pubkey = signing_key.verifying_key().to_bytes();
        let address = Address::from_public_key(&pubkey);
        let mut validator = Validator::new(address, pubkey, U256::from(10u64.pow(18)));
        validator.status = ValidatorStatus::Active;
        validator
    }

    fn block_for(
        parent_hash: [u8; 32],
        height: u64,
        proposer: Address,
        state_root: [u8; 32],
    ) -> Block {
        let mut header = BlockHeader::new(parent_hash, height);
        header.proposer = proposer;
        header.state_root = state_root;
        let mut block = Block::new(header, BlockBody::empty());
        block.compute_roots();
        block
    }

    #[tokio::test]
    async fn node_finalizes_consensus_block_and_persists_it() {
        let proposer_private_key = [11u8; 32];
        let signing_key = SigningKey::from_bytes(&proposer_private_key);
        let validator = active_validator_from_key(&signing_key);
        let (config, path) = test_config("node-consensus-finalize", proposer_private_key);

        let mut node = Node::new(config).await.expect("node should initialize");
        {
            let mut consensus = node.consensus.write().await;
            consensus.update_validator_set(vec![validator.clone()]);
            consensus.start().expect("consensus should start");
        }

        let block = block_for([0u8; 32], 1, validator.address, node.state.state_root());
        let block_hash = block.hash();

        node.handle_consensus_event(ConsensusEvent::BlockProposal(block.clone()))
            .await
            .expect("block proposal should be accepted");

        let mut vote = Vote::new(validator.address, block_hash, 0);
        vote.sign(&signing_key).expect("vote should sign");

        for _ in 0..3 {
            node.handle_consensus_event(ConsensusEvent::Vote(vote.clone()))
                .await
                .expect("vote should advance consensus");
        }

        let consensus = node.consensus.read().await;
        assert_eq!(consensus.finalized_block_height, 1);
        assert_eq!(
            consensus.latest_finalized_block().map(|block| block.hash()),
            Some(block_hash)
        );
        drop(consensus);

        assert_eq!(
            node.storage
                .latest_block_height()
                .expect("height should load"),
            1
        );
        assert_eq!(node.chain_head, Some(block_hash));
        assert_eq!(
            node.storage
                .state_get(b"metadata:state_root".to_vec())
                .expect("state root metadata should load")
                .map(|bytes| {
                    let mut root = [0u8; 32];
                    root.copy_from_slice(&bytes);
                    root
                }),
            Some(block.header.state_root)
        );

        drop(node);
        let _ = fs::remove_file(path);
    }
}
