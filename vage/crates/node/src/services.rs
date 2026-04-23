use crate::node::{ConsensusEvent, NodeEvent};
use anyhow::Result;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{mpsc, Mutex};
use tokio::task::JoinHandle;
use tokio::time::interval;
use tracing::info;
use vage_block::BlockHeader;
use vage_execution::Executor;
use vage_light_client::LightClient;
use vage_mempool::Mempool;
use vage_networking::P2PNetwork;
use vage_state::StateDB;
use vage_storage::StorageEngine;

#[derive(Clone, Debug)]
pub struct ServiceConfig {
    pub consensus_interval: Duration,
    pub block_production_interval: Duration,
    pub state_pruning_interval: Duration,
    pub peer_discovery_interval: Duration,
    pub metrics_interval: Duration,
}

impl Default for ServiceConfig {
    fn default() -> Self {
        Self {
            consensus_interval: Duration::from_millis(250),
            block_production_interval: Duration::from_secs(1),
            state_pruning_interval: Duration::from_secs(300),
            peer_discovery_interval: Duration::from_secs(30),
            metrics_interval: Duration::from_secs(10),
        }
    }
}

pub struct ServiceManager {
    handles: Vec<JoinHandle<Result<()>>>,
}

impl Default for ServiceManager {
    fn default() -> Self {
        Self::new()
    }
}

impl ServiceManager {
    pub fn new() -> Self {
        Self {
            handles: Vec::new(),
        }
    }

    pub fn spawn<F>(&mut self, f: F)
    where
        F: std::future::Future<Output = Result<()>> + Send + 'static,
    {
        let handle = tokio::spawn(f);
        self.handles.push(handle);
    }

    pub fn start_networking_service(&mut self, networking: Arc<Mutex<P2PNetwork>>) {
        self.spawn(async move {
            info!("starting networking service");
            loop {
                networking
                    .lock()
                    .await
                    .poll_once(Duration::from_millis(50))
                    .await?;
            }
        });
    }

    pub fn start_mempool_service(&mut self, mempool: Arc<Mempool>) {
        self.spawn(async move {
            info!("starting mempool service");
            mempool.start()?;
            loop {
                let _ = mempool.remove_expired_transactions_periodically()?;
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
        });
    }

    pub fn start_consensus_service(
        &mut self,
        event_tx: mpsc::UnboundedSender<NodeEvent>,
        config: ServiceConfig,
    ) {
        self.spawn(async move {
            info!("starting consensus tick service");
            let mut ticker = interval(config.consensus_interval);
            loop {
                ticker.tick().await;
                event_tx
                    .send(NodeEvent::Consensus(ConsensusEvent::Tick))
                    .map_err(|error| {
                        anyhow::anyhow!("failed to dispatch consensus tick: {}", error)
                    })?;
            }
        });
    }

    pub fn start_block_production_service(
        &mut self,
        mempool: Arc<Mempool>,
        event_tx: mpsc::UnboundedSender<NodeEvent>,
        config: ServiceConfig,
    ) {
        self.spawn(async move {
            info!("starting block production service");
            let mut ticker = interval(config.block_production_interval);
            loop {
                ticker.tick().await;
                let Some(transaction) = mempool
                    .provide_transactions_to_block_proposer(1)?
                    .into_iter()
                    .next()
                else {
                    continue;
                };
                event_tx
                    .send(NodeEvent::Consensus(ConsensusEvent::NewTransaction(
                        transaction,
                    )))
                    .map_err(|error| {
                        anyhow::anyhow!("failed to dispatch block production event: {}", error)
                    })?;
            }
        });
    }

    pub fn start_state_pruning_service(&mut self, state: Arc<StateDB>, config: ServiceConfig) {
        self.spawn(async move {
            info!("starting state pruning service");
            let mut ticker = interval(config.state_pruning_interval);
            loop {
                ticker.tick().await;
                let pruned = state.prune_old_state()?;
                if pruned > 0 {
                    info!("pruned {} old state snapshot entries", pruned);
                }
            }
        });
    }

    pub fn start_peer_discovery_service(
        &mut self,
        networking: Arc<Mutex<P2PNetwork>>,
        config: ServiceConfig,
    ) {
        self.spawn(async move {
            info!("starting peer discovery service");
            let mut ticker = interval(config.peer_discovery_interval);
            loop {
                ticker.tick().await;
                networking.lock().await.trigger_peer_discovery()?;
            }
        });
    }

    pub fn start_metrics_service(
        &mut self,
        networking: Arc<Mutex<P2PNetwork>>,
        mempool: Arc<Mempool>,
        execution: Arc<Executor>,
        storage: Arc<StorageEngine>,
        config: ServiceConfig,
    ) {
        self.spawn(async move {
            info!("starting metrics service");
            let mut ticker = interval(config.metrics_interval);
            loop {
                ticker.tick().await;

                let peer_count = networking.lock().await.peer_count();
                let mempool_metrics = mempool.metrics_snapshot();
                let execution_metrics = execution.execution_metrics();
                let storage_metrics = storage.get_metrics()?;
                let tps = execution_metrics.executed_transactions as f64
                    / config.metrics_interval.as_secs_f64().max(1.0);

                crate::metrics::MetricsService::record_peer_count(peer_count);
                crate::metrics::MetricsService::record_mempool_size(mempool_metrics.mempool_size);
                crate::metrics::MetricsService::record_tps(tps);

                info!(
                    "metrics: peers={}, mempool_size={}, tx_rate={}, tps={}, rejected_txs={}, executed_txs={}, executed_blocks={}, gas_used={}, storage={}",
                    peer_count,
                    mempool_metrics.mempool_size,
                    mempool_metrics.transaction_arrival_rate,
                    tps,
                    mempool_metrics.rejected_transactions,
                    execution_metrics.executed_transactions,
                    execution_metrics.executed_blocks,
                    execution_metrics.gas_used,
                    storage_metrics
                );
            }
        });
    }

    /// Periodically syncs block headers using the light-client engine.
    /// On each tick, it looks for a connected peer and runs the header sync
    /// loop â€” verifying parent-child linkage, BFT quorum signatures, and
    /// ZK validity proofs before accepting each header.
    pub fn start_light_client_sync_service(
        &mut self,
        networking: Arc<Mutex<P2PNetwork>>,
        config: ServiceConfig,
    ) {
        self.spawn(async move {
            info!("starting light-client sync service");
            let mut ticker = interval(config.peer_discovery_interval);
            let mut light_client: Option<LightClient> = None;
            loop {
                ticker.tick().await;

                // Pick the first connected peer as the sync anchor.
                let peer_id = {
                    let net = networking.lock().await;
                    net.peer_store.connected_peers().first().map(|p| p.peer_id)
                };

                let Some(peer_id) = peer_id else {
                    // No peers yet â€” wait for the next tick.
                    continue;
                };

                let client = match &light_client {
                    Some(client) => {
                        if client.tracking_peer().await != peer_id {
                            client.update_tracking_peer(peer_id).await;
                        }
                        client
                    }
                    None => {
                        light_client = Some(LightClient::new(
                            networking.clone(),
                            peer_id,
                            BlockHeader::genesis(),
                        ));
                        light_client
                            .as_ref()
                            .expect("light client should initialize")
                    }
                };
                if let Err(error) = client.run_sync_loop().await {
                    tracing::warn!("light-client sync error: {}", error);
                }
            }
        });
    }

    pub async fn wait_all(self) {
        for handle in self.handles {
            let _ = handle.await;
        }
    }
}

/// Spawns all background service tasks from the node's shared components.
/// Called once from `startup.rs` before entering the main event loop.
///
/// Services spawned here run as independent Tokio tasks and are automatically
/// terminated when the process exits or the runtime shuts down.
pub fn spawn_background_services(node: &crate::node::Node) {
    let config = ServiceConfig::default();
    let mut manager = ServiceManager::new();

    // 1. Networking service â€” drives the libp2p swarm event loop so that
    //    connection upgrades, DHT queries, and gossip propagation are
    //    continuously processed in the background.
    manager.start_networking_service(node.networking.clone());

    // 2. Mempool service â€” starts the pool and runs the periodic TTL expiry
    //    sweep so stale transactions are evicted without blocking the event loop.
    manager.start_mempool_service(node.mempool.clone());

    // 3. Consensus tick service â€” sends a ConsensusEvent::Tick into the node
    //    event channel at the configured interval, driving view timeouts and
    //    HotStuff round advancement independent of transaction activity.
    manager.start_consensus_service(node.event_sender(), config.clone());

    // 4. Block production service â€” polls the mempool and fires a
    //    ConsensusEvent::NewTransaction when there is work available, prompting
    //    the node to attempt a block proposal if it is the current leader.
    manager.start_block_production_service(
        node.mempool.clone(),
        node.event_sender(),
        config.clone(),
    );

    // 5. State pruning service â€” periodically trims old state-trie snapshots
    //    to keep on-disk storage bounded as the chain grows.
    manager.start_state_pruning_service(node.state.clone(), config.clone());

    // 6. Peer discovery service â€” triggers Kademlia lookups on a timer so
    //    the node continuously expands its peer table without manual bootstrapping.
    manager.start_peer_discovery_service(node.networking.clone(), config.clone());

    // 7. Metrics service â€” collects and logs peer count, mempool stats,
    //    execution counters, and storage statistics on every metrics interval.
    manager.start_metrics_service(
        node.networking.clone(),
        node.mempool.clone(),
        node.execution.clone(),
        node.storage.clone(),
        config.clone(),
    );

    // Light-client header sync loop â€” runs against the first connected peer.
    // If no peer is available yet the loop just idles and retries.
    manager.start_light_client_sync_service(node.networking.clone(), config);

    // Background tasks are running independently. The node's main event loop
    // (run_event_loop) is the primary blocking point â€” we do not await here.
}
