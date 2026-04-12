use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use vage_types::Address;

/// Tracks the block production performance of validators to enforce uptime rules.
#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct UptimeMonitor {
    /// Maps validator addresses to the number of consecutive missed slots.
    pub missed_slots: HashMap<Address, u64>,
    /// Maps validator addresses to their total lifetime missed slots.
    pub total_missed: HashMap<Address, u64>,
    /// Threshold for consecutive missed slots before a validator is jailed/slashed.
    pub slashing_threshold: u64,
}

impl UptimeMonitor {
    pub fn new(threshold: u64) -> Self {
        Self {
            missed_slots: HashMap::new(),
            total_missed: HashMap::new(),
            slashing_threshold: threshold,
        }
    }

    /// Record a successfully produced block by a validator.
    pub fn record_success(&mut self, validator: &Address) {
        // Reset consecutive misses upon a successful production.
        self.missed_slots.insert(*validator, 0);
    }

    /// Record a missed slot for a validator.
    /// Returns true if the validator has crossed the slashing threshold.
    pub fn record_miss(&mut self, validator: &Address) -> bool {
        let consecutive = self.missed_slots.entry(*validator).or_insert(0);
        *consecutive += 1;

        let total = self.total_missed.entry(*validator).or_insert(0);
        *total += 1;

        *consecutive >= self.slashing_threshold
    }

    /// Check if a validator should be penalized based on current uptime metrics.
    pub fn should_slash(&self, validator: &Address) -> bool {
        self.missed_slots.get(validator).copied().unwrap_or(0) >= self.slashing_threshold
    }

    /// Reset metrics for a validator (e.g., after they have served a jail sentence).
    pub fn reset_validator(&mut self, validator: &Address) {
        self.missed_slots.remove(validator);
    }
}
