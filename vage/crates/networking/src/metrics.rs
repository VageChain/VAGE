use metrics::{counter, gauge, histogram};
use std::time::Duration;

/// Metrics for tracking P2P connectivity and peer health.
pub struct NetworkingMetrics;

impl NetworkingMetrics {
    /// Update the current number of active P2P peers.
    pub fn update_peer_count(count: usize) {
        gauge!("vage_p2p_peers_connected").set(count as f64);
    }

    /// Record a successfully established inbound/outbound P2P connection.
    pub fn record_connection(direction: &str) {
        counter!("vage_p2p_connections_total", "direction" => direction.to_string()).increment(1);
    }

    /// Record a disconnected peer with a failure reason.
    pub fn record_disconnection(reason: &str) {
        counter!("vage_p2p_disconnections_total", "reason" => reason.to_string()).increment(1);
    }

    /// Record the number of messages handled for a topic and direction.
    pub fn record_messages(direction: &str, topic: &str, count: u64) {
        counter!(
            "vage_p2p_messages_total",
            "direction" => direction.to_string(),
            "topic" => topic.to_string()
        ).increment(count);
    }

    /// Record the current observed messages-per-second rate for a topic and direction.
    pub fn record_messages_per_second(direction: &str, topic: &str, messages_per_second: f64) {
        gauge!(
            "vage_p2p_messages_per_second",
            "direction" => direction.to_string(),
            "topic" => topic.to_string()
        ).set(messages_per_second);
    }

    /// Record total bandwidth usage in bytes.
    pub fn record_bandwidth(direction: &str, bytes: u64) {
        counter!(
            "vage_p2p_bandwidth_bytes_total", 
            "direction" => direction.to_string()
        ).increment(bytes);
    }

    /// Record end-to-end gossip propagation latency.
    pub fn record_gossip_propagation_latency(topic: &str, latency: Duration) {
        histogram!(
            "vage_p2p_gossip_propagation_latency_seconds",
            "topic" => topic.to_string()
        ).record(latency.as_secs_f64());
    }
}
