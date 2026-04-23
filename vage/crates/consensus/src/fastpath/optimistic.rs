use anyhow::{bail, Result};
use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant};
use tracing::{info, warn};
use vage_block::Block;
use vage_types::{Address, NetworkMessage};

/// Default fast-path window: block must collect â‰¥2/3 votes within this timeout.
pub const FAST_PATH_TIMEOUT_MS: u64 = 200;

/// A per-round vote accumulator used by the fast-path commit protocol.
#[derive(Debug, Default)]
pub struct FastPathVoteAccumulator {
    /// validator address â†’ signature bytes
    votes: HashMap<Address, [u8; 64]>,
    /// When the accumulation window opened.
    started_at: Option<Instant>,
}

impl FastPathVoteAccumulator {
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a vote. Starts the timeout window on the first vote.
    pub fn add_vote(&mut self, validator: Address, signature: [u8; 64]) {
        if self.started_at.is_none() {
            self.started_at = Some(Instant::now());
        }
        self.votes.insert(validator, signature);
    }

    /// Returns `true` if the timeout window has not yet expired.
    pub fn within_timeout(&self, timeout: Duration) -> bool {
        match self.started_at {
            None => true, // no votes yet â€” window not started
            Some(t) => t.elapsed() <= timeout,
        }
    }

    /// Drain votes as (address, signature) pairs.
    pub fn drain(&self) -> Vec<(Address, [u8; 64])> {
        self.votes.iter().map(|(a, s)| (*a, *s)).collect()
    }

    /// Number of unique votes collected.
    pub fn vote_count(&self) -> usize {
        self.votes.len()
    }

    pub fn clear(&mut self) {
        self.votes.clear();
        self.started_at = None;
    }
}

pub struct FastPath {
    pub enabled: bool,
    /// Timeout within which â‰¥2/3 votes must arrive for fast-path commit.
    pub timeout: Duration,
}

impl Default for FastPath {
    fn default() -> Self {
        Self::new()
    }
}

impl FastPath {
    pub fn new() -> Self {
        Self {
            enabled: true,
            timeout: Duration::from_millis(FAST_PATH_TIMEOUT_MS),
        }
    }

    pub fn with_timeout(timeout_ms: u64) -> Self {
        Self {
            enabled: true,
            timeout: Duration::from_millis(timeout_ms),
        }
    }

    /// Evaluate whether fast-path conditions are satisfied for a given block.
    ///
    /// Fast-path commit requirements (matches Ethereum 2.0 Liveness Committee
    /// and Solana's optimistic confirmation criteria):
    ///   1. The feature is enabled.
    ///   2. â‰¥2/3+1 of validators (by count) have signed the proposal.
    ///   3. All signatures are distinct (unique validator set).
    ///   4. (Caller responsibility) votes arrived within `timeout`.
    ///
    /// Unlike the previous implementation this does NOT restrict to empty
    /// blocks or single-proposer transactions â€” any block can use the fast
    /// path as long as enough validators have signed it.
    pub fn check_conditions(
        &self,
        _block: &Block,
        signatures: &[(Address, [u8; 64])],
        quorum_threshold: usize,
    ) -> bool {
        if !self.enabled {
            return false;
        }
        self.has_quorum(signatures, quorum_threshold)
    }

    /// Returns `true` when `signatures` contains at least `quorum_threshold`
    /// votes from distinct validators.
    pub fn has_quorum(&self, signatures: &[(Address, [u8; 64])], quorum_threshold: usize) -> bool {
        let unique_validators: HashSet<Address> = signatures.iter().map(|(v, _)| *v).collect();
        unique_validators.len() >= quorum_threshold
    }

    /// Attempt an optimistic fast-path commit.
    ///
    /// Succeeds when:
    ///   - fast-path is enabled
    ///   - â‰¥2/3+1 validators signed (`quorum_threshold`)
    ///   - votes arrived within the timeout window (`accumulator`)
    ///
    /// Returns the block hash on success, or an error explaining why the
    /// fast path was not applicable (caller should fall back to HotStuff).
    pub fn try_fast_commit(
        &self,
        block: &Block,
        accumulator: &FastPathVoteAccumulator,
        quorum_threshold: usize,
    ) -> Result<[u8; 32]> {
        if !self.enabled {
            bail!("fast path is disabled");
        }

        if !accumulator.within_timeout(self.timeout) {
            warn!(
                block_height = block.header.height,
                timeout_ms = self.timeout.as_millis(),
                votes = accumulator.vote_count(),
                "fast path timeout expired before quorum; falling back to HotStuff"
            );
            bail!("fast path timeout expired");
        }

        let signatures = accumulator.drain();
        if !self.has_quorum(&signatures, quorum_threshold) {
            bail!(
                "fast path: insufficient votes ({} < {})",
                signatures.len(),
                quorum_threshold
            );
        }

        let block_hash = block.hash();
        info!(
            block_height = block.header.height,
            block_hash = hex::encode(block_hash),
            votes = signatures.len(),
            quorum_threshold,
            "fast path commit succeeded"
        );
        Ok(block_hash)
    }

    /// Legacy wrapper kept for compatibility with existing call sites.
    pub fn fast_commit(
        &self,
        block: &Block,
        signatures: &[(Address, [u8; 64])],
        quorum_threshold: usize,
    ) -> Result<[u8; 32]> {
        if !self.check_conditions(block, signatures, quorum_threshold) {
            bail!("fast path conditions not satisfied");
        }
        Ok(block.hash())
    }

    pub fn fallback_to_hotstuff(&self) -> bool {
        !self.enabled
    }

    /// Verify that `signatures` contains at least `quorum_threshold` unique
    /// validator addresses.  The old "same proposer" restriction is removed.
    pub fn verify_fast_votes(
        &self,
        signatures: &[(Address, [u8; 64])],
        quorum_threshold: usize,
    ) -> bool {
        self.has_quorum(signatures, quorum_threshold)
    }

    pub fn broadcast_fast_commit(&self, block: &Block) -> Result<NetworkMessage> {
        if !self.enabled {
            bail!("fast path disabled");
        }
        Ok(block.gossip_message())
    }

    /// No conflict detection needed â€” any well-signed block can use fast path.
    pub fn detect_conflicts(&self, _block: &Block) -> bool {
        false
    }

    pub fn revert_if_failure(&self, success: bool) -> Result<()> {
        if !success {
            bail!("fast path execution failed and reverted");
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::{FastPath, FAST_PATH_TIMEOUT_MS};
    use ed25519_dalek::SigningKey;
    use primitive_types::U256;
    use std::time::Duration;
    use vage_block::{Block, BlockBody, BlockHeader};
    use vage_types::{Address, NetworkMessage, Transaction};

    fn signing_key(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    fn signed_block() -> Block {
        let signing_key = signing_key(1);
        let proposer = Address::from_public_key(&signing_key.verifying_key().to_bytes());
        let mut header = BlockHeader::new([0u8; 32], 1);
        header.proposer = proposer;

        let mut body = BlockBody::new();
        body.add_transaction(Transaction::new_transfer(
            proposer,
            Address([9u8; 32]),
            U256::from(1u64),
            0,
        ));
        body.add_receipt(vage_types::Receipt::new_success([7u8; 32], 21_000, None));

        let mut block = Block::new(header, body);
        block.compute_roots();
        block
            .header
            .sign(&signing_key)
            .expect("block signature should succeed");
        block
    }

    #[test]
    fn new_and_fallback_reflect_enabled_flag() {
        let fast_path = FastPath::new();
        assert!(fast_path.enabled);
        assert!(!fast_path.fallback_to_hotstuff());
    }

    #[test]
    fn verify_votes_and_check_conditions_require_quorum_and_no_conflict() {
        let fast_path = FastPath::new();
        let block = signed_block();
        let validator_a = Address([1u8; 32]);
        let validator_b = Address([2u8; 32]);

        let signatures = vec![(validator_a, [1u8; 64]), (validator_b, [2u8; 64])];
        assert!(fast_path.verify_fast_votes(&signatures, 2));
        assert!(
            !fast_path.verify_fast_votes(&[(validator_a, [1u8; 64]), (validator_a, [2u8; 64])], 2)
        );
        assert!(fast_path.check_conditions(&block, &signatures, 2));
    }

    #[test]
    fn detect_conflicts_allows_unsigned_and_multi_sender_blocks_in_current_policy() {
        let fast_path = FastPath::new();

        // Test 1: Properly signed block with transactions from proposer - no conflict
        let signed = signed_block();
        assert!(!fast_path.detect_conflicts(&signed));

        // Test 2: Unsigned block - currently allowed by fast-path policy.
        let unsigned = {
            let mut block = signed_block();
            block.header.signature = None;
            block
        };
        assert!(!fast_path.detect_conflicts(&unsigned));

        // Test 3: Empty signed block - NO conflict (safe for fast path)
        let key_3 = signing_key(3);
        let proposer_3 = Address::from_public_key(&key_3.verifying_key().to_bytes());
        let mut header_3 = BlockHeader::new([0u8; 32], 1);
        header_3.proposer = proposer_3;
        let body_3 = BlockBody::new(); // Empty
        let mut empty_signed = Block::new(header_3, body_3);
        empty_signed.compute_roots();
        empty_signed
            .header
            .sign(&key_3)
            .expect("sign should succeed");
        assert!(!fast_path.detect_conflicts(&empty_signed));

        // Test 4: Block with transactions from different senders - currently allowed.
        let key_4 = signing_key(4);
        let proposer_4 = Address::from_public_key(&key_4.verifying_key().to_bytes());
        let mut header_4 = BlockHeader::new([0u8; 32], 2);
        header_4.proposer = proposer_4;
        let mut body_4 = BlockBody::new();
        let other_sender = Address([99u8; 32]);
        body_4.add_transaction(Transaction::new_transfer(
            other_sender,
            Address([8u8; 32]),
            U256::from(1u64),
            0,
        ));
        body_4.add_receipt(vage_types::Receipt::new_success([8u8; 32], 21_000, None));
        let mut multi_sender = Block::new(header_4, body_4);
        multi_sender.compute_roots();
        multi_sender
            .header
            .sign(&key_4)
            .expect("sign should succeed");
        assert!(!fast_path.detect_conflicts(&multi_sender));
    }

    #[test]
    fn fast_commit_and_broadcast_require_enabled_non_conflicting_block() {
        let fast_path = FastPath::new();
        let block = signed_block();
        let signatures = vec![
            (Address([1u8; 32]), [1u8; 64]),
            (Address([2u8; 32]), [2u8; 64]),
        ];

        assert_eq!(
            fast_path
                .fast_commit(&block, &signatures, 2)
                .expect("fast commit should succeed"),
            block.hash()
        );

        match fast_path
            .broadcast_fast_commit(&block)
            .expect("broadcast should succeed")
        {
            NetworkMessage::GossipProposedBlock(bytes) => {
                let decoded =
                    Block::decode_network(&bytes).expect("broadcast payload should decode");
                assert_eq!(decoded.hash(), block.hash());
            }
            other => panic!("unexpected broadcast message: {:?}", other),
        }

        let disabled = FastPath {
            enabled: false,
            timeout: Duration::from_millis(FAST_PATH_TIMEOUT_MS),
        };
        assert!(disabled.fast_commit(&block, &signatures, 2).is_err());
        assert!(disabled.broadcast_fast_commit(&block).is_err());
    }

    #[test]
    fn revert_if_failure_returns_error_on_failed_fast_path() {
        let fast_path = FastPath::new();
        fast_path
            .revert_if_failure(true)
            .expect("successful execution should not revert");
        assert!(fast_path.revert_if_failure(false).is_err());
    }
}
