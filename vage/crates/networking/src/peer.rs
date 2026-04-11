use libp2p::{Multiaddr, PeerId};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

const BANNED_REPUTATION_THRESHOLD: i32 = -100;
const INVALID_MESSAGE_PENALTY: i32 = 25;
const DUPLICATE_MESSAGE_PENALTY: i32 = 5;
const RATE_LIMIT_PENALTY: i32 = 10;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Peer {
    pub peer_id: PeerId,
    pub address: String,
    pub last_seen: u64,
    pub reputation: i32,
}

impl Peer {
    pub fn new(peer_id: PeerId, address: Multiaddr) -> Self {
        Self {
            peer_id,
            address: address.to_string(),
            last_seen: Self::unix_timestamp(),
            reputation: 0,
        }
    }

    pub fn update_last_seen(&mut self) {
        self.last_seen = Self::unix_timestamp();
    }

    pub fn increase_reputation(&mut self, amount: i32) {
        self.reputation = self.reputation.saturating_add(amount.max(0));
    }

    pub fn decrease_reputation(&mut self, amount: i32) {
        self.reputation = self.reputation.saturating_sub(amount.max(0));
    }

    pub fn is_banned(&self) -> bool {
        self.reputation <= BANNED_REPUTATION_THRESHOLD
    }

    fn unix_timestamp() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct PeerStore {
    pub peers: HashMap<PeerId, Peer>,
}

impl PeerStore {
    pub fn add_peer(&mut self, peer: Peer) {
        self.peers.insert(peer.peer_id, peer);
    }

    pub fn remove_peer(&mut self, peer_id: &PeerId) -> Option<Peer> {
        self.peers.remove(peer_id)
    }

    pub fn get_peer(&self, peer_id: &PeerId) -> Option<&Peer> {
        self.peers.get(peer_id)
    }

    pub fn get_peer_mut(&mut self, peer_id: &PeerId) -> Option<&mut Peer> {
        self.peers.get_mut(peer_id)
    }

    pub fn connected_peers(&self) -> Vec<&Peer> {
        self.peers
            .values()
            .filter(|peer| !peer.is_banned())
            .collect()
    }

    pub fn ban_peer(&mut self, peer_id: &PeerId) -> bool {
        if let Some(peer) = self.peers.get_mut(peer_id) {
            peer.reputation = BANNED_REPUTATION_THRESHOLD;
            return true;
        }
        false
    }

    pub fn unban_peer(&mut self, peer_id: &PeerId) -> bool {
        if let Some(peer) = self.peers.get_mut(peer_id) {
            if peer.is_banned() {
                peer.reputation = 0;
            }
            return true;
        }
        false
    }

    pub fn penalize_invalid_message(&mut self, peer_id: &PeerId) -> bool {
        self.apply_penalty(peer_id, INVALID_MESSAGE_PENALTY)
    }

    pub fn penalize_duplicate_message(&mut self, peer_id: &PeerId) -> bool {
        self.apply_penalty(peer_id, DUPLICATE_MESSAGE_PENALTY)
    }

    pub fn penalize_rate_limit_violation(&mut self, peer_id: &PeerId) -> bool {
        self.apply_penalty(peer_id, RATE_LIMIT_PENALTY)
    }

    fn apply_penalty(&mut self, peer_id: &PeerId, amount: i32) -> bool {
        if let Some(peer) = self.peers.get_mut(peer_id) {
            peer.decrease_reputation(amount);
            if peer.is_banned() {
                peer.reputation = BANNED_REPUTATION_THRESHOLD;
            }
            return true;
        }
        false
    }
}

#[cfg(test)]
mod tests {
    use super::{Peer, PeerStore};
    use libp2p::{identity::Keypair, Multiaddr, PeerId};

    fn peer_id(seed: u8) -> PeerId {
        let mut bytes = [seed; 32];
        bytes[0] = bytes[0].max(1);
        PeerId::from(Keypair::ed25519_from_bytes(bytes).expect("keypair should build").public())
    }

    fn address(port: u16) -> Multiaddr {
        format!("/ip4/127.0.0.1/tcp/{port}")
            .parse()
            .expect("multiaddr should parse")
    }

    #[test]
    fn peer_new_update_last_seen_and_reputation_methods_work() {
        let peer_id = peer_id(1);
        let mut peer = Peer::new(peer_id, address(9001));

        assert_eq!(peer.peer_id, peer_id);
        assert_eq!(peer.address, "/ip4/127.0.0.1/tcp/9001");
        assert_eq!(peer.reputation, 0);
        assert!(!peer.is_banned());
        assert!(peer.last_seen > 0);

        let initial_last_seen = peer.last_seen;
        peer.update_last_seen();
        assert!(peer.last_seen >= initial_last_seen);

        peer.increase_reputation(15);
        assert_eq!(peer.reputation, 15);
        peer.increase_reputation(-10);
        assert_eq!(peer.reputation, 15);

        peer.decrease_reputation(20);
        assert_eq!(peer.reputation, -5);
        peer.decrease_reputation(-20);
        assert_eq!(peer.reputation, -5);

        peer.decrease_reputation(200);
        assert!(peer.is_banned());
    }

    #[test]
    fn peer_store_add_remove_get_connected_ban_and_unban_work() {
        let first_id = peer_id(2);
        let second_id = peer_id(3);
        let first_peer = Peer::new(first_id, address(9002));
        let second_peer = Peer::new(second_id, address(9003));
        let mut store = PeerStore::default();

        store.add_peer(first_peer.clone());
        store.add_peer(second_peer.clone());

        assert_eq!(store.get_peer(&first_id).map(|peer| peer.address.as_str()), Some("/ip4/127.0.0.1/tcp/9002"));
        assert_eq!(store.connected_peers().len(), 2);

        assert!(store.ban_peer(&first_id));
        assert!(store.get_peer(&first_id).expect("peer should exist").is_banned());
        assert_eq!(store.connected_peers().len(), 1);
        assert_eq!(store.connected_peers()[0].peer_id, second_id);

        assert!(store.unban_peer(&first_id));
        assert!(!store.get_peer(&first_id).expect("peer should exist").is_banned());
        assert_eq!(store.connected_peers().len(), 2);

        let removed = store.remove_peer(&second_id).expect("peer should be removed");
        assert_eq!(removed.peer_id, second_id);
        assert!(store.get_peer(&second_id).is_none());
        assert_eq!(store.connected_peers().len(), 1);
    }
}
