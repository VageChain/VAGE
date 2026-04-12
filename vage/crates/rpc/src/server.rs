use axum::{
    extract::{Path, State},
    middleware,
    routing::{get, post},
    Json, Router,
};
use axum_server::tls_rustls::RustlsConfig;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::oneshot;
use tower_http::trace::TraceLayer;
use tracing::info;

use crate::context::RpcContext;
use crate::error::JsonRpcError;
use crate::metrics;
use crate::middleware::{
    auth_middleware, cors_middleware, ddos_protection_middleware, logging_middleware,
    size_limit_layer, timeout_middleware,
};
use crate::protocol::{JsonRpcRequest, JsonRpcResponse};
use crate::routes::{blocks, health, network, state, tx};

/// TLS configuration for secure RPC communication.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TlsConfig {
    pub cert_path: PathBuf,
    pub key_path: PathBuf,
}

/// Configuration options for the VageChain RPC server.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RpcConfig {
    pub addr: SocketAddr,
    pub max_request_body_size: usize,
    pub tls: Option<TlsConfig>,
}

impl Default for RpcConfig {
    fn default() -> Self {
        Self {
            addr: "127.0.0.1:8080"
                .parse()
                .expect("hardcoded default RPC address is valid"),
            max_request_body_size: 1024 * 1024 * 10, // 10MB
            tls: None,
        }
    }
}

/// The VageChain RPC Server, supporting JSON-RPC, REST, and secure communication.
pub struct RpcServer {
    context: Arc<RpcContext>,
    config: RpcConfig,
    shutdown_tx: Option<oneshot::Sender<()>>,
}

impl RpcServer {
    /// Creates a new RPC server instance with the specified context and configuration.
    pub fn new(context: Arc<RpcContext>, config: RpcConfig) -> Self {
        Self {
            context,
            config,
            shutdown_tx: None,
        }
    }

    /// Starts the asynchronous HTTP/HTTPS server with support for graceful shutdown.
    pub async fn start(&mut self) -> anyhow::Result<()> {
        let (shutdown_tx, shutdown_rx) = oneshot::channel();
        self.shutdown_tx = Some(shutdown_tx);

        let app = self.build_router();
        let addr = self.config.addr;

        // Graceful handle for axum-server
        let handle = axum_server::Handle::new();
        let shutdown_handle = handle.clone();
        tokio::spawn(async move {
            shutdown_rx.await.ok();
            info!("Graceful shutdown signal received. Stopping RPC server...");
            shutdown_handle.graceful_shutdown(Some(std::time::Duration::from_secs(5)));
        });

        if let Some(tls) = &self.config.tls {
            info!(
                "Starting VageChain SECURE (HTTPS) RPC server on {}...",
                addr
            );
            let rustls_config = RustlsConfig::from_pem_file(&tls.cert_path, &tls.key_path).await?;
            axum_server::bind_rustls(addr, rustls_config)
                .handle(handle)
                .serve(app.into_make_service_with_connect_info::<SocketAddr>())
                .await?;
        } else {
            info!("Starting VageChain (HTTP) RPC server on {}...", addr);
            axum_server::bind(addr)
                .handle(handle)
                .serve(app.into_make_service_with_connect_info::<SocketAddr>())
                .await?;
        }

        Ok(())
    }

    /// Initializes the Axum router with JSON-RPC handlers, REST routes, and middleware.
    fn build_router(&self) -> Router {
        Router::new()
            // -----------------------------------------------------------------
            // JSON-RPC Endpoints
            // -----------------------------------------------------------------
            .route("/rpc", post(Self::handle_json_rpc))
            // -----------------------------------------------------------------
            // REST Endpoints
            // -----------------------------------------------------------------
            .route("/health", get(health::health_check))
            .route("/metrics", get(|| async { metrics::render_metrics() }))
            .route("/status", get(Self::handle_status_rest))
            .route("/blocks/:height", get(Self::handle_block_rest))
            // -----------------------------------------------------------------
            // Shared Middleware Stack
            // -----------------------------------------------------------------
            .layer(cors_middleware())
            .layer(size_limit_layer(self.config.max_request_body_size))
            .layer(middleware::from_fn(logging_middleware))
            .layer(middleware::from_fn(auth_middleware))
            .layer(middleware::from_fn(ddos_protection_middleware))
            .layer(middleware::from_fn(timeout_middleware))
            .layer(TraceLayer::new_for_http())
            .with_state(self.context.clone())
    }

    /// High-level handler for all incoming JSON-RPC 2.0 requests.
    async fn handle_json_rpc(
        State(context): State<Arc<RpcContext>>,
        Json(raw_request): Json<Value>,
    ) -> Json<Value> {
        let start_time = std::time::Instant::now();

        // Standard JSON-RPC Parsing
        let request: JsonRpcRequest = match serde_json::from_value(raw_request) {
            Ok(req) => req,
            Err(_) => {
                return Json(
                    serde_json::to_value(JsonRpcResponse::error(
                        Value::Null,
                        JsonRpcError::parse_error(),
                    ))
                    .expect("JsonRpcResponse error is always serializable"),
                );
            }
        };

        if let Err(e) = request.validate() {
            return Json(
                serde_json::to_value(JsonRpcResponse::error(request.id, e))
                    .expect("JsonRpcResponse error is always serializable"),
            );
        }

        let method_name = request.method.clone();
        metrics::record_request(&method_name);

        // Core Method Dispatcher
        let result = Self::dispatch_rpc_method(&context, request.method, request.params).await;

        let response = match result {
            Ok(val) => {
                metrics::record_latency(&method_name, start_time);
                JsonRpcResponse::success(request.id, val)
            }
            Err(e) => {
                let rpc_error = e.to_json_rpc_error();
                metrics::record_error(&method_name, rpc_error.code);
                JsonRpcResponse::error(request.id, rpc_error)
            }
        };

        Json(
            serde_json::to_value(response)
                .expect("JsonRpcResponse with standard types should always serialize successfully"),
        )
    }

    /// Dispatches JSON-RPC calls to specialized module-level handlers.
    async fn dispatch_rpc_method(
        context: &Arc<RpcContext>,
        method: String,
        params: Option<Value>,
    ) -> Result<Value, crate::error::RpcError> {
        // Ethereum compatibility layer - map eth_ methods to vage_ internally
        let method_name = if method.starts_with("eth_") {
            match method.as_str() {
                "eth_chainId" => return Ok(json!("0x78637a7d")), // Chain ID: 2018131581
                "eth_networkId" => return Ok(json!("2018131581")),
                "eth_gasPrice" => return Ok(json!("0x1")), // 1 wei minimum
                "eth_blockNumber" => {
                    let height = context.storage.latest_block_height().map_err(|e| {
                        crate::error::RpcError::InternalError(format!(
                            "failed to fetch block height: {}",
                            e
                        ))
                    })?;
                    return Ok(json!(format!("0x{:x}", height)));
                }
                "eth_getBalance" => "vage_getBalance".to_string(),
                "eth_getCode" => "vage_getCode".to_string(),
                "eth_getStorageAt" => "vage_getStorageAt".to_string(),
                "eth_getTransactionCount" => "vage_getNonce".to_string(),
                "eth_sendTransaction" => "vage_sendTransaction".to_string(),
                "eth_sendRawTransaction" => "vage_sendRawTransaction".to_string(),
                "eth_call" => "vage_call".to_string(),
                "eth_getTransactionReceipt" => "vage_getTransactionReceipt".to_string(),
                "eth_accounts" => return Ok(json!([])), // No accounts in RPC-only mode
                "eth_coinbase" => return Ok(json!("0x0000000000000000000000000000000000000000")),
                "eth_mining" => return Ok(json!(false)),
                "eth_hashrate" => return Ok(json!("0x0")),
                "web3_clientVersion" => return Ok(json!("VageChain/0.1.0")),
                _ => method.clone(), // Pass through unknown eth_ methods
            }
        } else {
            method.clone()
        };

        // Namespace-based dispatch
        if method_name.starts_with("vage_getBlock") || method_name == "vage_latestBlock" {
            blocks::handle_block_method(&method_name, params, context).await
        } else if method_name.starts_with("vage_send") || method_name.contains("Transaction") {
            tx::handle_tx_method(&method_name, params, context).await
        } else if method_name == "vage_getBalance"
            || method_name.contains("Storage")
            || method_name.contains("Proof")
        {
            state::handle_state_method(&method_name, params, context).await
        } else {
            network::handle_network_method(&method_name, params, context).await
        }
    }

    // --- REST Handlers ---

    async fn handle_status_rest(State(_context): State<Arc<RpcContext>>) -> Json<Value> {
        Json(json!({
            "version": "0.1.0",
            "chain_id": "vage-mainnet-1",
            "status": "online"
        }))
    }

    async fn handle_block_rest(
        Path(height): Path<u64>,
        State(context): State<Arc<RpcContext>>,
    ) -> Json<Value> {
        // Directly resolve using the RPC handler logic
        match blocks::handle_block_method("vage_getBlockByNumber", Some(json!([height])), &context)
            .await
        {
            Ok(val) => Json(val),
            Err(_) => Json(json!({"error": "block not found"})),
        }
    }

    /// Stops the server gracefully by signaling the shutdown channel.
    pub fn stop(&mut self) {
        if let Some(tx) = self.shutdown_tx.take() {
            info!("Stop signal received. Initiating shutdown...");
            let _ = tx.send(());
        }
    }
}
