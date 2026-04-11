use std::sync::Arc;
use tokio::sync::{Mutex, RwLock};
use vage_networking::P2PNetwork;
use vage_mempool::Mempool;
use vage_consensus::Consensus;
use vage_execution::Executor;
use vage_state::StateDB;
use vage_storage::StorageEngine;

/// Global context shared across all JSON-RPC handlers, providing thread-safe
/// access to the core node components.
pub struct RpcContext {
    /// Thread-safe reference to the P2P Networking layer.
    pub networking: Arc<Mutex<P2PNetwork>>,
    /// Thread-safe reference to the Mempool.
    pub mempool: Arc<Mempool>,
    /// Thread-safe, mutable access to Consensus state.
    pub consensus: Arc<RwLock<Consensus>>,
    /// Thread-safe reference to the State Database (Verkle Tree).
    pub state: Arc<StateDB>,
    /// Thread-safe reference to the permanent storage backend.
    pub storage: Arc<StorageEngine>,
    /// Execution engine â€” used for gas estimation and dry-runs.
    pub executor: Arc<Executor>,
}

impl RpcContext {
    pub fn new(
        networking: Arc<Mutex<P2PNetwork>>,
        mempool: Arc<Mempool>,
        consensus: Arc<RwLock<Consensus>>,
        state: Arc<StateDB>,
        storage: Arc<StorageEngine>,
        executor: Arc<Executor>,
    ) -> Self {
        Self {
            networking,
            mempool,
            consensus,
            state,
            storage,
            executor,
        }
    }

    /// Access the Mempool.
    pub fn mempool(&self) -> Arc<Mempool> {
        Arc::clone(&self.mempool)
    }

    /// Access the Consensus engine read-lock.
    pub fn consensus(&self) -> Arc<RwLock<Consensus>> {
        Arc::clone(&self.consensus)
    }

    /// Access the State Database.
    pub fn state(&self) -> Arc<StateDB> {
        Arc::clone(&self.state)
    }

    /// Access the Storage backend.
    pub fn storage(&self) -> Arc<StorageEngine> {
        Arc::clone(&self.storage)
    }

    /// Access the networking layer read-lock.
    pub fn networking(&self) -> Arc<Mutex<P2PNetwork>> {
        Arc::clone(&self.networking)
    }
}

