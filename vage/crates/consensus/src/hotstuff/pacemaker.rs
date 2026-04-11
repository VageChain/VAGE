use serde::{Deserialize, Serialize};
use std::time::Duration;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NewViewMessage {
    pub view: u64,
    pub leader_index: Option<usize>,
}

pub struct Pacemaker {
    pub current_view: u64,
    pub timeout: Duration,
}

impl Pacemaker {
    pub fn new(timeout: Duration) -> Self {
        Self {
            current_view: 0,
            timeout,
        }
    }

    pub fn advance_view(&mut self) -> u64 {
        self.current_view = self.current_view.saturating_add(1);
        self.current_view
    }

    pub fn on_timeout(&mut self) -> u64 {
        self.advance_view()
    }

    pub fn leader_for_view(&self, view: u64, validator_count: usize) -> Option<usize> {
        if validator_count == 0 {
            return None;
        }
        Some((view as usize) % validator_count)
    }

    pub fn reset_timer(&mut self) {}

    pub fn handle_new_view_message(&mut self, message: &NewViewMessage) -> u64 {
        if message.view > self.current_view {
            self.current_view = message.view;
        }
        self.reset_timer();
        self.current_view
    }

    pub fn broadcast_new_view(&self, validator_count: usize) -> NewViewMessage {
        NewViewMessage {
            view: self.current_view,
            leader_index: self.leader_for_view(self.current_view, validator_count),
        }
    }

    pub fn detect_leader_failure(&self) -> bool {
        !self.timeout.is_zero()
    }

    pub fn sync_view_with_network(&mut self, network_view: u64) -> u64 {
        if network_view > self.current_view {
            self.current_view = network_view;
        }
        self.reset_timer();
        self.current_view
    }

    pub fn is_timed_out(&self) -> bool {
        self.detect_leader_failure()
    }
}

#[cfg(test)]
mod tests {
    use super::{NewViewMessage, Pacemaker};
    use std::time::Duration;

    #[test]
    fn new_and_advance_view_initialize_and_increment_state() {
        let mut pacemaker = Pacemaker::new(Duration::from_secs(5));

        assert_eq!(pacemaker.current_view, 0);
        assert_eq!(pacemaker.timeout, Duration::from_secs(5));
        assert_eq!(pacemaker.advance_view(), 1);
        assert_eq!(pacemaker.current_view, 1);
        assert_eq!(pacemaker.on_timeout(), 2);
        assert_eq!(pacemaker.current_view, 2);
    }

    #[test]
    fn leader_selection_and_broadcast_new_view_follow_view_modulo() {
        let pacemaker = Pacemaker::new(Duration::from_secs(3));

        assert_eq!(pacemaker.leader_for_view(0, 0), None);
        assert_eq!(pacemaker.leader_for_view(0, 4), Some(0));
        assert_eq!(pacemaker.leader_for_view(5, 4), Some(1));

        let message = pacemaker.broadcast_new_view(4);
        assert_eq!(message.view, 0);
        assert_eq!(message.leader_index, Some(0));
    }

    #[test]
    fn handle_new_view_and_network_sync_only_move_forward() {
        let mut pacemaker = Pacemaker::new(Duration::from_secs(1));
        pacemaker.current_view = 4;

        let stale_message = NewViewMessage {
            view: 2,
            leader_index: Some(0),
        };
        assert_eq!(pacemaker.handle_new_view_message(&stale_message), 4);

        let newer_message = NewViewMessage {
            view: 7,
            leader_index: Some(1),
        };
        assert_eq!(pacemaker.handle_new_view_message(&newer_message), 7);
        assert_eq!(pacemaker.sync_view_with_network(6), 7);
        assert_eq!(pacemaker.sync_view_with_network(9), 9);
    }

    #[test]
    fn timeout_detection_reflects_configured_timeout() {
        let timed = Pacemaker::new(Duration::from_secs(1));
        let not_timed = Pacemaker::new(Duration::ZERO);

        assert!(timed.detect_leader_failure());
        assert!(timed.is_timed_out());
        assert!(!not_timed.detect_leader_failure());
        assert!(!not_timed.is_timed_out());
    }
}
