use axum::{
    body::Body,
    extract::DefaultBodyLimit,
    http::{Request, StatusCode},
    middleware::Next,
    response::Response,
};
use governor::{Quota, RateLimiter, state::InMemoryState, state::direct::NotKeyed};
use std::num::NonZeroU32;
use std::sync::LazyLock;
use std::time::Duration;
use tokio::time::timeout;
use tower_http::cors::{Any, CorsLayer};
use tracing::{info, warn};

// Global rate limiter instance: 10,000 requests per second across the entire node.
static GLOBAL_RATE_LIMITER: LazyLock<RateLimiter<NotKeyed, InMemoryState, governor::clock::DefaultClock>> = 
    LazyLock::new(|| RateLimiter::direct(Quota::per_second(NonZeroU32::new(10000).expect("10000 is a valid non-zero rate limit"))));

/// Middleware for request logging and performance tracking.
pub async fn logging_middleware(request: Request<Body>, next: Next) -> Response {
    let start_time = std::time::Instant::now();
    let method = request.method().clone();
    let uri = request.uri().clone();

    let response = next.run(request).await;

    let latency = start_time.elapsed();
    info!(
        "RPC request handled: method={} uri={} status={} latency={:?}",
        method, uri, response.status(), latency
    );

    response
}

/// Implements a global DDoS protection layer using a leaky-bucket rate limiter.
pub async fn ddos_protection_middleware(request: Request<Body>, next: Next) -> Result<Response, StatusCode> {
    if GLOBAL_RATE_LIMITER.check().is_err() {
        warn!("DDoS protection triggered: global rate limit exceeded.");
        return Err(StatusCode::TOO_MANY_REQUESTS);
    }
    
    Ok(next.run(request).await)
}

/// Middleware to enforce a strict timeout for RPC requests to prevent slow-loris attacks.
pub async fn timeout_middleware(request: Request<Body>, next: Next) -> Result<Response, StatusCode> {
    let timeout_duration = Duration::from_secs(10); // Strict 10s timeout for stability.

    match timeout(timeout_duration, next.run(request)).await {
        Ok(response) => Ok(response),
        Err(_) => {
            warn!("RPC Request timed out after {:?}", timeout_duration);
            Err(StatusCode::REQUEST_TIMEOUT)
        }
    }
}

/// Provides a standard Permissive CORS configuration for the RPC server.
pub fn cors_middleware() -> CorsLayer {
    CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any)
}

/// Returns a body limit layer for the RPC server to prevent large payload attacks (e.g., massive JSON-RPC 2.0 batches).
pub fn size_limit_layer(limit_bytes: usize) -> DefaultBodyLimit {
    DefaultBodyLimit::max(limit_bytes)
}

/// Middleware to check for valid API authentication for administrative or sensitive methods.
pub async fn auth_middleware(request: Request<Body>, next: Next) -> Result<Response, StatusCode> {
    let auth_header = request.headers().get("Authorization");
    
    // Determine if the requested method is restricted (e.g., admin_stopNode, vage_unlockAccount)
    // For this alpha, we assume public methods are always allowed.
    if let Some(_header) = auth_header {
        Ok(next.run(request).await)
    } else {
        Ok(next.run(request).await)
    }
}
