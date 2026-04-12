use metrics::{counter, histogram};
use metrics_exporter_prometheus::{PrometheusBuilder, PrometheusHandle};
use std::sync::OnceLock;
use std::time::Instant;

/// Global handle to the Prometheus recorder, set once during initialization.
static PROMETHEUS_HANDLE: OnceLock<PrometheusHandle> = OnceLock::new();

/// Initialize the global Prometheus recorder and exporter.
///
/// Must be called once at startup before any metrics are recorded.
/// Subsequent calls are no-ops.
pub fn init_metrics_recorder() {
    if PROMETHEUS_HANDLE.get().is_some() {
        return;
    }
    let handle = PrometheusBuilder::new().build_recorder().handle();
    // Install the recorder globally; PROMETHEUS_HANDLE gives us access for rendering.
    PrometheusBuilder::new()
        .install()
        .expect("failed to install Prometheus recorder");
    // Store the handle for later rendering via /metrics.
    // If another thread races and wins, that is fine — the global recorder is already
    // installed and we just discard the duplicate handle.
    let _ = PROMETHEUS_HANDLE.set(handle);
}

/// Track a new incoming RPC request by method name.
pub fn record_request(method: &str) {
    counter!("rpc_requests_total", "method" => method.to_string()).increment(1);
}

/// Track a failed RPC request with specific method and error code labels.
pub fn record_error(method: &str, code: i32) {
    counter!(
        "rpc_requests_failed_total",
        "method" => method.to_string(),
        "code" => code.to_string()
    )
    .increment(1);
}

/// Record the latency of a successful RPC response into a histogram.
pub fn record_latency(method: &str, start_time: Instant) {
    let duration = start_time.elapsed();
    histogram!(
        "rpc_request_duration_seconds",
        "method" => method.to_string()
    )
    .record(duration.as_secs_f64());
}

/// Export current metrics as a Prometheus-formatted string for the `/metrics` endpoint.
pub fn render_metrics() -> String {
    PROMETHEUS_HANDLE
        .get()
        .map(|h| h.render())
        .unwrap_or_else(|| "# metrics recorder not initialized\n".to_string())
}
