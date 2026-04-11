use metrics::{counter, gauge, histogram};
use std::time::Instant;

/// Metrics for tracking block production and consensus performance.
pub struct ConsensusMetrics;

impl ConsensusMetrics {
    /// Track a successfully produced block.
    pub fn record_block_mined(height: u64, proposer: &str) {
        counter!("vage_blocks_produced_total", 1, "proposer" => proposer.to_string());
        gauge!("vage_chain_head_height", height as f64);
    }

    /// Record the latency between view starts and block finalization.
    pub fn record_consensus_latency(view: u64, start_time: Instant) {
        let duration = start_time.elapsed();
        histogram!(
            "vage_consensus_latency_seconds",
            duration.as_secs_f64(),
            "view" => view.to_string()
        );
    }

    /// Record a timeout event in the HotStuff view.
    pub fn record_view_timeout(view: u64) {
        counter!("vage_consensus_timeouts_total", 1, "view" => view.to_string());
    }

    /// Track the current number of active validators.
    pub fn record_validator_count(count: usize) {
        gauge!("vage_validators_active_count", count as f64);
    }

    /// Track a validator's consecutive missed blocks.
    pub fn record_validator_missed_block(validator: &str, missed_count: u64) {
        gauge!(
            "vage_validator_missed_blocks_consecutive",
            missed_count as f64,
            "validator" => validator.to_string()
        );
    }
}
