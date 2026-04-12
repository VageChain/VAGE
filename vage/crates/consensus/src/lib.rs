pub mod consensus_state;
pub mod fastpath;
pub mod governance;
pub mod hotstuff;
pub mod pos;
pub mod slashing;
pub mod upgrades;

use crate::governance::GovernanceManager;
use crate::hotstuff::pacemaker::Pacemaker;
use crate::hotstuff::proposer::{ProposalExecution, Proposer};
use crate::hotstuff::vote::{QuorumCertificate, Vote, VoteCollector};
use crate::hotstuff::HotStuffPhase;
use crate::pos::uptime::UptimeMonitor;
use crate::pos::validator_set::ValidatorSet;
use crate::upgrades::{ProtocolVersion, UpgradeManager};
use anyhow::{bail, Result};
use primitive_types::U256;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use vage_block::Block;
use vage_block::BlockBody;
use vage_execution::TransactionSource;
use vage_storage::StorageEngine;
use vage_types::{Address, Transaction, Validator};

pub use crate::consensus_state::{
    audit_consensus_state_integrity, checkpoint_finalized_block, detect_inconsistent_state,
    enter_safe_recovery_mode, has_proposed_in_view, latest_checkpoint, load_checkpoint,
    load_consensus_state, persist_consensus_state, record_proposal_in_view,
    reject_proposal_below_locked_block, restore_full_consensus, restore_highest_qc,
    restore_locked_block, restore_pacemaker_view, synchronize_view_with_peers, Checkpoint,
    ConsensusState, ConsensusStateManager, ConsistencyCheck, RestoredConsensus,
};
pub use crate::fastpath::FastPath;
pub use crate::hotstuff::proposer::ProposalMessage;
pub use crate::hotstuff::HotStuff;
pub use crate::pos::staking::StakingManager;
pub use crate::slashing::{
    apply_block_slashing, Evidence, Misbehavior, SlashingConfig, SlashingEvent, SlashingEventRpc,
    SlashingManager,
};

const CONSENSUS_VOTE_PREFIX: &[u8] = b"consensus:vote:";
const CONSENSUS_QC_PREFIX: &[u8] = b"consensus:qc:";
const CONSENSUS_VALIDATOR_SET_KEY: &[u8] = b"consensus:validator_set";
const CONSENSUS_CURRENT_VIEW_KEY: &[u8] = b"consensus:current_view";
const DEFAULT_EPOCH_LENGTH: u64 = 32;

/// Placeholder `TransactionSource` used until the real mempool is wired in via `Proposer`.
struct NoopTransactionSource;

impl TransactionSource for NoopTransactionSource {
    fn pull_transactions(&self, _limit: usize) -> Result<Vec<Transaction>> {
        Ok(Vec::new())
    }

    fn acknowledge_transactions(&self, _hashes: &[[u8; 32]]) -> Result<()> {
        Ok(())
    }
}

/// Placeholder `ProposalExecution` used until the real executor is wired in via `Proposer`.
struct NoopExecution;

impl ProposalExecution for NoopExecution {
    fn produce_block(&self, template: Block, transactions: Vec<Transaction>) -> Result<Block> {
        let mut block = template;
        block.body.transactions = transactions;
        block.compute_roots();
        Ok(block)
    }
}

pub trait ConsensusNetwork {
    fn broadcast_block_proposal(&self, payload: Vec<u8>) -> Result<()>;
    fn broadcast_vote(&self, payload: Vec<u8>) -> Result<()>;
    fn broadcast_quorum_certificate(&self, payload: Vec<u8>) -> Result<()>;
    fn broadcast_new_view(&self, payload: Vec<u8>) -> Result<()>;
    fn request_missing_blocks(&self, start_height: u64, limit: u64) -> Result<Vec<Vec<u8>>>;
    fn synchronize_validator_state(&self, payload: Vec<u8>) -> Result<()>;
}

pub struct Consensus {
    pub validator_set: ValidatorSet,
    pub pacemaker: Pacemaker,
    pub vote_collector: VoteCollector,
    pub proposer: Proposer,
    pub hotstuff: HotStuff,
    pub finalized_block_height: u64,
    pub staking_manager: StakingManager,
    pub uptime_monitor: UptimeMonitor,
    pub upgrades: UpgradeManager,
    pub governance: GovernanceManager,
    highest_qc_block: Option<[u8; 32]>,
    storage: Arc<StorageEngine>,
    pending_blocks: HashMap<[u8; 32], Block>,
    committed_blocks: HashMap<[u8; 32], Block>,
    finalized_blocks: HashMap<[u8; 32], Block>,
    epoch_length: u64,
}

impl Consensus {
    /// Primary constructor: shares the node's existing `StorageEngine` so that
    /// consensus state (votes, QCs, validator set) is persisted in the same
    /// database file as block headers and world state. The internal proposer is
    /// initialised with no-op stubs; callers should replace `self.proposer` with
    /// a real `Proposer` before starting the node.
    pub fn with_storage(storage: Arc<StorageEngine>) -> Self {
        let validator_set = ValidatorSet::new();
        let pacemaker = Pacemaker::new(Duration::from_secs(5));
        let proposer = Proposer::new(
            Address::zero(),
            Arc::new(NoopTransactionSource),
            Arc::new(NoopExecution),
        );

        Self {
            validator_set,
            pacemaker,
            vote_collector: VoteCollector::new(),
            proposer,
            hotstuff: HotStuff::new(),
            finalized_block_height: 0,
            staking_manager: StakingManager::new(),
            uptime_monitor: UptimeMonitor::new(10),
            upgrades: UpgradeManager::new(ProtocolVersion::new(1, 0, 0)),
            governance: GovernanceManager::new(),
            highest_qc_block: None,
            storage,
            pending_blocks: HashMap::new(),
            committed_blocks: HashMap::new(),
            finalized_blocks: HashMap::new(),
            epoch_length: DEFAULT_EPOCH_LENGTH,
        }
    }

    pub fn start(&mut self) -> Result<u64> {
        self.restore_consensus_state_on_restart()?;

        if let Some(leader) = self.current_leader() {
            self.proposer = Proposer::new(
                leader,
                self.proposer.mempool.clone(),
                self.proposer.execution.clone(),
            );
        }

        Ok(self.current_view())
    }

    pub fn stop(&mut self) -> Result<()> {
        self.persist_validator_set()?;
        self.persist_current_consensus_view()?;
        Ok(())
    }

    pub fn process_block_proposal(&mut self, block: Block) -> Result<bool> {
        block.validate_basic()?;

        let expected_leader = self
            .current_leader()
            .ok_or_else(|| anyhow::anyhow!("no active leader for current view"))?;
        if block.header.proposer != expected_leader {
            bail!(
                "invalid proposer for view {}: expected {}, got {}",
                self.current_view(),
                expected_leader,
                block.header.proposer
            );
        }

        if self.is_conflicting_branch(&block) {
            self.reject_conflicting_branch(&block)?;
        }

        if self.detect_fork(&block) {
            self.resolve_fork(&block)?;
        }

        self.detect_conflicting_proposal(&block)?;

        self.pending_blocks.insert(block.hash(), block);
        Ok(true)
    }

    pub fn process_vote(&mut self, vote: Vote) -> Result<Option<QuorumCertificate>> {
        if vote.view != self.current_view() {
            bail!(
                "vote view mismatch: expected {}, got {}",
                self.current_view(),
                vote.view
            );
        }

        if !self.pending_blocks.contains_key(&vote.block_hash) {
            bail!("vote references unknown block");
        }

        self.verify_validator_vote(&vote)?;
        self.vote_collector.add_vote(vote.clone())?;
        self.persist_vote_in_storage(&vote)?;
        let quorum_threshold = self.quorum_threshold();
        let qc = self.vote_collector.build_quorum_certificate(
            vote.view,
            vote.block_hash,
            quorum_threshold,
        );

        if let Some(ref qc) = qc {
            self.reject_invalid_quorum_certificate(qc)?;
            self.persist_quorum_certificate(qc)?;
            self.persist_current_consensus_view()?;
            self.apply_highest_qc_rule(qc);
            let block = self
                .pending_blocks
                .get(&vote.block_hash)
                .ok_or_else(|| anyhow::anyhow!("pending block not found for quorum phase"))?
                .clone();

            let phase = self.apply_three_phase_commit_rule(&block, qc.clone())?;
            match phase {
                HotStuffPhase::Prepare => {
                    if !self.verify_prepare_phase(&block, qc)? {
                        bail!("prepare phase verification failed");
                    }
                }
                HotStuffPhase::PreCommit => {
                    if !self.verify_pre_commit_phase(block.hash(), qc)? {
                        bail!("pre-commit phase verification failed");
                    }
                }
                HotStuffPhase::Finalize => {
                    if !self.verify_commit_phase(block.hash(), qc)? {
                        bail!("commit phase verification failed");
                    }
                    self.finalize_block_once_quorum_reached(block.hash())?;
                }
                HotStuffPhase::Commit => {}
            }
        }

        Ok(qc)
    }

    pub fn commit_block(&mut self, block_hash: [u8; 32]) -> Result<()> {
        let block = self
            .pending_blocks
            .remove(&block_hash)
            .ok_or_else(|| anyhow::anyhow!("block not found for commit"))?;
        self.committed_blocks.insert(block_hash, block);
        Ok(())
    }

    pub fn finalize_block(&mut self, block_hash: [u8; 32]) -> Result<()> {
        self.ensure_committed_block_qc_is_valid(block_hash)?;

        let block = self
            .committed_blocks
            .remove(&block_hash)
            .ok_or_else(|| anyhow::anyhow!("block not found for finalization"))?;
        self.finalized_block_height = block.height();
        self.persist_finalized_block_to_storage(&block)?;
        self.finalized_blocks.insert(block_hash, block.clone());
        // Record uptime for the proposer of the finalized block
        self.uptime_monitor.record_success(&block.header.proposer);
        let _ = self
            .staking_manager
            .reward_validator(&block.header.proposer, U256::from(1000));
        self.maybe_rotate_validator_set_for_new_epoch()?;

        // Check for missed blocks by other expected validators in this view
        // In a production HotStuff, we would know who was supposed to vote.

        self.pacemaker.advance_view();

        if let Some(leader) = self.current_leader() {
            self.proposer = Proposer::new(
                leader,
                self.proposer.mempool.clone(),
                self.proposer.execution.clone(),
            );
        }

        Ok(())
    }

    pub fn update_validator_set(&mut self, validators: Vec<Validator>) {
        self.validator_set
            .replace_validators(validators)
            .expect("validator set replacement should validate input");
        self.persist_validator_set()
            .expect("validator set persistence should succeed");
        if let Some(leader) = self.current_leader() {
            self.proposer = Proposer::new(
                leader,
                self.proposer.mempool.clone(),
                self.proposer.execution.clone(),
            );
        }
    }

    pub fn current_validator_root(&self) -> [u8; 32] {
        BlockBody::compute_validator_root(&self.validator_set.active_validators())
    }

    pub fn current_view(&self) -> u64 {
        self.pacemaker.current_view
    }

    pub fn current_leader(&self) -> Option<Address> {
        self.validator_set.get_proposer(self.current_view())
    }

    pub fn latest_finalized_block(&self) -> Option<Block> {
        self.finalized_blocks
            .values()
            .max_by_key(|block| block.height())
            .cloned()
    }

    pub fn load_persisted_quorum_certificate(
        &self,
        block_hash: [u8; 32],
    ) -> Result<Option<QuorumCertificate>> {
        let key = Self::qc_storage_key_for_block_hash(block_hash);
        self.storage
            .state_get(key)?
            .map(|bytes| QuorumCertificate::decode(&bytes))
            .transpose()
    }

    fn quorum_threshold(&self) -> usize {
        let count = self.validator_set.active_validator_count();
        if count == 0 {
            return 0;
        }
        ((count * 2) / 3) + 1
    }

    fn apply_longest_chain_rule(&self, candidate: &Block) -> bool {
        let best_known_height = self
            .pending_blocks
            .values()
            .chain(self.committed_blocks.values())
            .chain(self.finalized_blocks.values())
            .map(Block::height)
            .max()
            .unwrap_or(0);

        candidate.height() >= best_known_height
    }

    fn apply_highest_qc_rule(&mut self, qc: &QuorumCertificate) {
        if self.highest_qc_block.is_none() {
            self.highest_qc_block = Some(qc.block_hash);
            return;
        }

        let current_height = self
            .highest_qc_block
            .and_then(|hash| self.find_block(&hash))
            .map(Block::height)
            .unwrap_or(0);
        let candidate_height = self
            .find_block(&qc.block_hash)
            .map(Block::height)
            .unwrap_or(0);

        if candidate_height >= current_height {
            self.highest_qc_block = Some(qc.block_hash);
        }
    }

    fn detect_fork(&self, candidate: &Block) -> bool {
        self.pending_blocks.values().any(|existing| {
            existing.parent_hash() == candidate.parent_hash() && existing.hash() != candidate.hash()
        })
    }

    fn resolve_fork(&mut self, candidate: &Block) -> Result<()> {
        if !self.apply_longest_chain_rule(candidate) {
            bail!("fork resolution rejected shorter competing branch");
        }

        let conflicting_hashes: Vec<[u8; 32]> = self
            .pending_blocks
            .values()
            .filter(|existing| {
                existing.parent_hash() == candidate.parent_hash()
                    && existing.hash() != candidate.hash()
            })
            .map(Block::hash)
            .collect();

        for hash in conflicting_hashes {
            if let Some(conflicting_block) = self.pending_blocks.get(&hash) {
                if !self.prefer_candidate_branch(candidate, conflicting_block) {
                    bail!("fork resolution kept existing higher-priority branch");
                }
            }
            self.pending_blocks.remove(&hash);
        }

        Ok(())
    }

    fn reject_conflicting_branch(&self, block: &Block) -> Result<()> {
        bail!(
            "rejected block {} from conflicting branch at parent {:?}",
            block.height(),
            block.parent_hash()
        )
    }

    fn apply_three_phase_commit_rule(
        &mut self,
        block: &Block,
        qc: QuorumCertificate,
    ) -> Result<HotStuffPhase> {
        self.hotstuff.apply_three_phase_commit_rule(block, qc)
    }

    fn verify_prepare_phase(&self, block: &Block, qc: &QuorumCertificate) -> Result<bool> {
        self.hotstuff.verify_prepare_phase(block, qc)
    }

    fn verify_pre_commit_phase(
        &self,
        block_hash: [u8; 32],
        qc: &QuorumCertificate,
    ) -> Result<bool> {
        self.hotstuff.verify_pre_commit_phase(block_hash, qc)
    }

    fn verify_commit_phase(&self, block_hash: [u8; 32], qc: &QuorumCertificate) -> Result<bool> {
        self.hotstuff.verify_commit_phase(block_hash, qc)
    }

    fn finalize_block_once_quorum_reached(&mut self, block_hash: [u8; 32]) -> Result<()> {
        if !self.committed_blocks.contains_key(&block_hash) {
            self.commit_block(block_hash)?;
        }
        self.finalize_block(block_hash)
    }

    fn persist_finalized_block_to_storage(&self, block: &Block) -> Result<()> {
        let header_bytes = bincode::serialize(&block.header)?;
        let body_bytes = bincode::serialize(&block.body)?;
        self.storage
            .atomic_block_commit(block.height(), header_bytes, body_bytes)
    }

    fn is_conflicting_branch(&self, candidate: &Block) -> bool {
        self.finalized_blocks.values().any(|finalized| {
            finalized.height() == candidate.height()
                && finalized.hash() != candidate.hash()
                && finalized.parent_hash() != candidate.parent_hash()
        })
    }

    fn prefer_candidate_branch(&self, candidate: &Block, incumbent: &Block) -> bool {
        if candidate.height() != incumbent.height() {
            return candidate.height() > incumbent.height();
        }

        let candidate_has_highest_qc = self.highest_qc_block == Some(candidate.hash());
        let incumbent_has_highest_qc = self.highest_qc_block == Some(incumbent.hash());
        candidate_has_highest_qc || !incumbent_has_highest_qc
    }

    fn find_block(&self, hash: &[u8; 32]) -> Option<&Block> {
        self.pending_blocks
            .get(hash)
            .or_else(|| self.committed_blocks.get(hash))
            .or_else(|| self.finalized_blocks.get(hash))
    }

    fn detect_conflicting_proposal(&self, candidate: &Block) -> Result<()> {
        let conflicting = self.pending_blocks.values().any(|existing| {
            existing.height() == candidate.height()
                && existing.header.proposer == candidate.header.proposer
                && existing.hash() != candidate.hash()
        });

        if conflicting {
            bail!(
                "conflicting proposal detected from proposer {} at height {}",
                candidate.header.proposer,
                candidate.height()
            );
        }

        Ok(())
    }

    fn verify_validator_vote(&self, vote: &Vote) -> Result<()> {
        let validator = self
            .validator_set
            .validator(&vote.validator)
            .ok_or_else(|| anyhow::anyhow!("unknown validator {}", vote.validator))?;

        if !vote.verify_signature(validator)? {
            bail!("invalid validator signature for {}", vote.validator);
        }

        if self.validator_set.voting_power(&vote.validator) == 0 {
            bail!("validator {} has no voting power", vote.validator);
        }

        Ok(())
    }

    fn reject_invalid_quorum_certificate(&self, qc: &QuorumCertificate) -> Result<()> {
        let active_validators = self.validator_set.active_validators();
        let required_voting_power = self.required_quorum_voting_power();
        if !qc.verify_with_voting_power(
            &active_validators,
            self.quorum_threshold(),
            required_voting_power,
        )? {
            bail!("invalid quorum certificate");
        }
        Ok(())
    }

    fn required_quorum_voting_power(&self) -> u64 {
        let total = self.validator_set.total_active_voting_power();
        if total == 0 {
            return 0;
        }
        ((total * 2) / 3) + 1
    }

    pub fn broadcast_block_proposal_to_peers<N: ConsensusNetwork>(
        &self,
        network: &N,
        block: &Block,
    ) -> Result<()> {
        network.broadcast_block_proposal(bincode::serialize(block)?)
    }

    pub fn broadcast_vote_to_peers<N: ConsensusNetwork>(
        &self,
        network: &N,
        vote: &Vote,
    ) -> Result<()> {
        network.broadcast_vote(vote.encode())
    }

    pub fn broadcast_quorum_certificate_to_peers<N: ConsensusNetwork>(
        &self,
        network: &N,
        quorum_certificate: &QuorumCertificate,
    ) -> Result<()> {
        network.broadcast_quorum_certificate(quorum_certificate.encode())
    }

    pub fn broadcast_new_view_message<N: ConsensusNetwork>(&self, network: &N) -> Result<()> {
        let message = self
            .pacemaker
            .broadcast_new_view(self.validator_set.active_validator_count());
        network.broadcast_new_view(bincode::serialize(&message)?)
    }

    pub fn request_missing_blocks_from_peers<N: ConsensusNetwork>(
        &self,
        network: &N,
        start_height: u64,
        limit: u64,
    ) -> Result<Vec<Block>> {
        let payloads = network.request_missing_blocks(start_height, limit)?;
        payloads
            .into_iter()
            .map(|payload| Ok(bincode::deserialize(&payload)?))
            .collect()
    }

    pub fn synchronize_validator_state_with_network<N: ConsensusNetwork>(
        &self,
        network: &N,
    ) -> Result<()> {
        let validators = self.validator_set.active_validators();
        network.synchronize_validator_state(bincode::serialize(&validators)?)
    }

    fn persist_vote_in_storage(&self, vote: &Vote) -> Result<()> {
        self.storage
            .state_put(Self::vote_storage_key(vote), bincode::serialize(vote)?)
    }

    fn persist_quorum_certificate(&self, qc: &QuorumCertificate) -> Result<()> {
        self.storage
            .state_put(Self::qc_storage_key(qc), qc.encode())
    }

    fn ensure_committed_block_qc_is_valid(&self, block_hash: [u8; 32]) -> Result<()> {
        let qc = self
            .load_persisted_quorum_certificate(block_hash)?
            .ok_or_else(|| {
                anyhow::anyhow!("missing quorum certificate for block {:x?}", block_hash)
            })?;
        self.reject_invalid_quorum_certificate(&qc)
    }

    fn persist_validator_set(&self) -> Result<()> {
        let validators = self.validator_set.active_validators();
        self.storage.state_put(
            CONSENSUS_VALIDATOR_SET_KEY.to_vec(),
            bincode::serialize(&validators)?,
        )
    }

    fn persist_current_consensus_view(&self) -> Result<()> {
        self.storage.state_put(
            CONSENSUS_CURRENT_VIEW_KEY.to_vec(),
            self.current_view().to_le_bytes().to_vec(),
        )
    }

    fn restore_consensus_state_on_restart(&mut self) -> Result<()> {
        if let Some(bytes) = self
            .storage
            .state_get(CONSENSUS_VALIDATOR_SET_KEY.to_vec())?
        {
            let validators: Vec<Validator> = bincode::deserialize(&bytes)?;
            self.validator_set.replace_validators(validators)?;
        }

        if let Some(bytes) = self
            .storage
            .state_get(CONSENSUS_CURRENT_VIEW_KEY.to_vec())?
        {
            if bytes.len() == 8 {
                let mut view_bytes = [0u8; 8];
                view_bytes.copy_from_slice(&bytes);
                self.pacemaker.current_view = u64::from_le_bytes(view_bytes);
            }
        }

        for (_, bytes) in self
            .storage
            .state_prefix_scan(CONSENSUS_VOTE_PREFIX.to_vec())?
        {
            let vote: Vote = bincode::deserialize(&bytes)?;
            let _ = self.vote_collector.add_vote(vote);
        }

        let mut restored_highest_qc: Option<[u8; 32]> = None;
        for (_, bytes) in self
            .storage
            .state_prefix_scan(CONSENSUS_QC_PREFIX.to_vec())?
        {
            let qc = QuorumCertificate::decode(&bytes)?;
            restored_highest_qc = Some(qc.block_hash);
        }
        self.highest_qc_block = restored_highest_qc;

        Ok(())
    }

    fn qc_storage_key_for_block_hash(block_hash: [u8; 32]) -> Vec<u8> {
        let mut key = Vec::with_capacity(CONSENSUS_QC_PREFIX.len() + block_hash.len());
        key.extend_from_slice(CONSENSUS_QC_PREFIX);
        key.extend_from_slice(&block_hash);
        key
    }

    fn maybe_rotate_validator_set_for_new_epoch(&mut self) -> Result<()> {
        if self.finalized_block_height == 0 || self.finalized_block_height % self.epoch_length != 0
        {
            return Ok(());
        }

        self.staking_manager.staking_epoch_update()?;

        let mut next_validators = self.validator_set.all_validators();
        for validator in &mut next_validators {
            validator.stake = self.staking_manager.get_stake(&validator.address);
            validator.update_voting_power();
            if validator.stake.is_zero() {
                validator.status = vage_types::validator::ValidatorStatus::Inactive;
            } else if !validator.is_jailed() {
                validator.status = vage_types::validator::ValidatorStatus::Active;
            }
        }

        next_validators.retain(|validator| !validator.stake.is_zero());
        self.validator_set.replace_validators(next_validators)?;
        self.persist_validator_set()?;
        self.persist_current_consensus_view()?;
        Ok(())
    }

    fn vote_storage_key(vote: &Vote) -> Vec<u8> {
        let mut key = CONSENSUS_VOTE_PREFIX.to_vec();
        key.extend_from_slice(&vote.view.to_le_bytes());
        key.extend_from_slice(vote.validator.as_bytes());
        key.extend_from_slice(&vote.block_hash);
        key
    }

    fn qc_storage_key(qc: &QuorumCertificate) -> Vec<u8> {
        let mut key = CONSENSUS_QC_PREFIX.to_vec();
        key.extend_from_slice(&qc.block_hash);
        key
    }
}

#[cfg(test)]
mod tests {
    use super::{
        Consensus, ConsensusNetwork, CONSENSUS_CURRENT_VIEW_KEY, CONSENSUS_QC_PREFIX,
        CONSENSUS_VALIDATOR_SET_KEY, CONSENSUS_VOTE_PREFIX,
    };
    use crate::hotstuff::vote::{QuorumCertificate, Vote};
    use anyhow::Result;
    use ed25519_dalek::SigningKey;
    use primitive_types::U256;
    use std::cell::RefCell;
    use std::fs;
    use std::path::PathBuf;
    use std::sync::Arc;
    use std::time::{SystemTime, UNIX_EPOCH};
    use vage_block::{Block, BlockBody, BlockHeader};
    use vage_storage::StorageEngine;
    use vage_types::validator::ValidatorStatus;
    use vage_types::{Address, Validator};

    #[derive(Default)]
    struct MockConsensusNetwork {
        block_proposals: RefCell<Vec<Vec<u8>>>,
        votes: RefCell<Vec<Vec<u8>>>,
        quorum_certificates: RefCell<Vec<Vec<u8>>>,
        new_views: RefCell<Vec<Vec<u8>>>,
        validator_syncs: RefCell<Vec<Vec<u8>>>,
        missing_blocks_response: RefCell<Vec<Vec<u8>>>,
        missing_blocks_requests: RefCell<Vec<(u64, u64)>>,
    }

    impl ConsensusNetwork for MockConsensusNetwork {
        fn broadcast_block_proposal(&self, payload: Vec<u8>) -> Result<()> {
            self.block_proposals.borrow_mut().push(payload);
            Ok(())
        }

        fn broadcast_vote(&self, payload: Vec<u8>) -> Result<()> {
            self.votes.borrow_mut().push(payload);
            Ok(())
        }

        fn broadcast_quorum_certificate(&self, payload: Vec<u8>) -> Result<()> {
            self.quorum_certificates.borrow_mut().push(payload);
            Ok(())
        }

        fn broadcast_new_view(&self, payload: Vec<u8>) -> Result<()> {
            self.new_views.borrow_mut().push(payload);
            Ok(())
        }

        fn request_missing_blocks(&self, start_height: u64, limit: u64) -> Result<Vec<Vec<u8>>> {
            self.missing_blocks_requests
                .borrow_mut()
                .push((start_height, limit));
            Ok(self.missing_blocks_response.borrow().clone())
        }

        fn synchronize_validator_state(&self, payload: Vec<u8>) -> Result<()> {
            self.validator_syncs.borrow_mut().push(payload);
            Ok(())
        }
    }

    fn unique_storage_path(name: &str) -> PathBuf {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock should be valid")
            .as_nanos();
        std::env::temp_dir().join(format!("vage-{name}-{unique}.redb"))
    }

    fn test_storage(name: &str) -> (Arc<StorageEngine>, PathBuf) {
        let path = unique_storage_path(name);
        let storage = Arc::new(
            StorageEngine::new(path.to_string_lossy().as_ref())
                .expect("test storage should initialize"),
        );
        (storage, path)
    }

    fn cleanup_storage(path: PathBuf) {
        let _ = fs::remove_file(path);
    }

    fn signing_key(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    fn active_validator(seed: u8) -> (Validator, SigningKey) {
        let signing_key = signing_key(seed);
        let public_key = signing_key.verifying_key().to_bytes();
        let address = Address::from_public_key(&public_key);
        let mut validator = Validator::new(address, public_key, U256::from(10u64.pow(18)));
        validator.status = ValidatorStatus::Active;
        (validator, signing_key)
    }

    fn inactive_validator(seed: u8) -> (Validator, SigningKey) {
        let signing_key = signing_key(seed);
        let public_key = signing_key.verifying_key().to_bytes();
        let address = Address::from_public_key(&public_key);
        let mut validator = Validator::new(address, public_key, U256::from(10u64.pow(18)));
        validator.status = ValidatorStatus::Inactive;
        (validator, signing_key)
    }

    fn zero_power_validator(seed: u8) -> (Validator, SigningKey) {
        let signing_key = signing_key(seed);
        let public_key = signing_key.verifying_key().to_bytes();
        let address = Address::from_public_key(&public_key);
        let mut validator = Validator::new(address, public_key, U256::from(1u64));
        validator.status = ValidatorStatus::Active;
        (validator, signing_key)
    }

    fn block_for(parent_hash: [u8; 32], height: u64, proposer: Address) -> Block {
        let mut header = BlockHeader::new(parent_hash, height);
        header.proposer = proposer;
        let mut block = Block::new(header, BlockBody::empty());
        block.compute_roots();
        block
    }

    fn new_consensus() -> Consensus {
        let storage = Arc::new(
            StorageEngine::new("consensus-temp.redb")
                .expect("consensus temporary storage should initialize"),
        );
        Consensus::with_storage(storage)
    }

    fn with_storage(storage: Arc<StorageEngine>) -> Consensus {
        Consensus::with_storage(storage)
    }

    #[test]
    fn new_initializes_requested_consensus_fields() {
        let path = PathBuf::from("consensus-temp.redb");
        let consensus = new_consensus();

        assert_eq!(consensus.current_view(), 0);
        assert!(consensus.current_leader().is_none());
        assert_eq!(consensus.proposer.validator_id, Address::zero());
        assert_eq!(consensus.vote_collector.vote_count(0, [0u8; 32]), 0);

        drop(consensus);
        let _ = fs::remove_file(path);
    }

    #[test]
    fn start_restores_view_and_updates_proposer_for_current_leader() {
        let (storage, path) = test_storage("consensus-start");
        let (validator, _) = active_validator(1);

        {
            let mut consensus = with_storage(storage.clone());
            consensus.update_validator_set(vec![validator.clone()]);
            consensus.pacemaker.current_view = 7;
            consensus.stop().expect("consensus state should persist");
        }

        let mut restored = with_storage(storage);
        let view = restored.start().expect("consensus should start");

        assert_eq!(view, 7);
        assert_eq!(restored.current_view(), 7);
        assert_eq!(restored.current_leader(), Some(validator.address));
        assert_eq!(restored.proposer.validator_id, validator.address);

        cleanup_storage(path);
    }

    #[test]
    fn process_block_proposal_accepts_leader_block_and_tracks_it() {
        let (storage, path) = test_storage("consensus-proposal");
        let (validator, _) = active_validator(2);
        let mut consensus = with_storage(storage);
        consensus.update_validator_set(vec![validator.clone()]);

        let genesis = Block::genesis([0u8; 32]);
        let block = block_for(genesis.hash(), 1, validator.address);
        let block_hash = block.hash();

        let accepted = consensus
            .process_block_proposal(block)
            .expect("leader proposal should be accepted");

        assert!(accepted);
        assert!(consensus.pending_blocks.contains_key(&block_hash));

        cleanup_storage(path);
    }

    #[test]
    fn process_vote_builds_quorum_certificate_and_persists_vote() {
        let (storage, path) = test_storage("consensus-vote");
        let (validator, signing_key) = active_validator(3);
        let mut consensus = with_storage(storage.clone());
        consensus.update_validator_set(vec![validator.clone()]);

        let genesis = Block::genesis([0u8; 32]);
        let block = block_for(genesis.hash(), 1, validator.address);
        let block_hash = block.hash();
        consensus
            .process_block_proposal(block)
            .expect("proposal should be tracked");

        let mut vote = Vote::new(validator.address, block_hash, consensus.current_view());
        vote.sign(&signing_key).expect("vote should sign");

        let qc = consensus
            .process_vote(vote.clone())
            .expect("vote should be processed")
            .expect("single active validator should reach quorum");

        assert_eq!(qc.block_hash, block_hash);
        assert_eq!(consensus.vote_collector.vote_count(0, block_hash), 1);
        assert!(consensus.hotstuff.has_prepare_quorum(block_hash));

        let persisted_vote = storage
            .state_prefix_scan(CONSENSUS_VOTE_PREFIX.to_vec())
            .expect("vote scan should succeed");
        assert_eq!(persisted_vote.len(), 1);

        cleanup_storage(path);
    }

    #[test]
    fn conflicting_proposals_are_detected_for_same_proposer_and_height() {
        let (storage, path) = test_storage("consensus-conflicting-proposal");
        let (validator, _) = active_validator(19);
        let mut consensus = with_storage(storage);
        consensus.update_validator_set(vec![validator.clone()]);

        let genesis = Block::genesis([0u8; 32]);
        let first = block_for(genesis.hash(), 1, validator.address);
        let second = block_for([7u8; 32], 1, validator.address);
        consensus.pending_blocks.insert(first.hash(), first);

        assert!(consensus.detect_conflicting_proposal(&second).is_err());

        cleanup_storage(path);
    }

    #[test]
    fn validator_vote_verification_rejects_invalid_signature_and_zero_voting_power() {
        let (storage, path) = test_storage("consensus-verify-vote");
        let (active, active_signer) = active_validator(20);
        let (inactive, inactive_signer) = inactive_validator(21);
        let (zero_power, zero_power_signer) = zero_power_validator(26);
        let mut consensus = with_storage(storage);
        consensus.update_validator_set(vec![active.clone(), inactive.clone(), zero_power.clone()]);

        let block_hash = [5u8; 32];
        let mut bad_signature_vote = Vote::new(active.address, block_hash, 0);
        bad_signature_vote
            .sign(&inactive_signer)
            .expect("vote signing should succeed even with wrong signer");
        assert!(consensus
            .verify_validator_vote(&bad_signature_vote)
            .is_err());

        let mut zero_power_vote = Vote::new(zero_power.address, block_hash, 0);
        zero_power_vote
            .sign(&zero_power_signer)
            .expect("zero-power vote should sign");
        assert!(consensus.verify_validator_vote(&zero_power_vote).is_err());

        let mut valid_vote = Vote::new(active.address, block_hash, 0);
        valid_vote.sign(&active_signer).expect("vote should sign");
        consensus
            .verify_validator_vote(&valid_vote)
            .expect("active validator vote should verify");

        cleanup_storage(path);
    }

    #[test]
    fn invalid_quorum_certificates_are_rejected_and_valid_ones_pass() {
        let (storage, path) = test_storage("consensus-invalid-qc");
        let (validator_a, signer_a) = active_validator(22);
        let (validator_b, signer_b) = active_validator(23);
        let mut consensus = with_storage(storage);
        consensus.update_validator_set(vec![validator_a.clone(), validator_b.clone()]);

        let block_hash = [8u8; 32];
        let mut vote_a = Vote::new(validator_a.address, block_hash, 0);
        let mut vote_b = Vote::new(validator_b.address, block_hash, 0);
        vote_a.sign(&signer_a).expect("vote a should sign");
        vote_b.sign(&signer_b).expect("vote b should sign");

        let invalid_qc = QuorumCertificate::new(
            block_hash,
            0,
            vec![vote_a.signature.to_vec()],
            vec![vote_a.validator],
        );
        assert!(consensus
            .reject_invalid_quorum_certificate(&invalid_qc)
            .is_err());

        let valid_qc = QuorumCertificate::new(
            block_hash,
            0,
            vec![vote_a.signature.to_vec(), vote_b.signature.to_vec()],
            vec![vote_a.validator, vote_b.validator],
        );
        consensus
            .reject_invalid_quorum_certificate(&valid_qc)
            .expect("two-validator quorum certificate should be accepted");

        cleanup_storage(path);
    }

    #[test]
    fn commit_and_finalize_block_move_it_through_consensus_lifecycle() {
        let (storage, path) = test_storage("consensus-finalize");
        let (validator_a, signing_key_a) = active_validator(4);
        let (validator_b, signing_key_b) = active_validator(5);
        let mut consensus = with_storage(storage.clone());
        consensus.update_validator_set(vec![validator_a.clone(), validator_b.clone()]);

        let genesis = Block::genesis([0u8; 32]);
        let proposer = consensus.current_leader().expect("leader should exist");
        let block = block_for(genesis.hash(), 1, proposer);
        let block_hash = block.hash();
        consensus
            .process_block_proposal(block)
            .expect("proposal should be accepted");

        let mut vote_a = Vote::new(validator_a.address, block_hash, consensus.current_view());
        vote_a.sign(&signing_key_a).expect("vote should sign");
        let mut vote_b = Vote::new(validator_b.address, block_hash, consensus.current_view());
        vote_b.sign(&signing_key_b).expect("vote should sign");
        let qc = QuorumCertificate::new(
            block_hash,
            consensus.current_view(),
            vec![vote_a.signature.to_vec(), vote_b.signature.to_vec()],
            vec![validator_a.address, validator_b.address],
        );
        consensus
            .reject_invalid_quorum_certificate(&qc)
            .expect("qc should validate before finalization");
        consensus
            .persist_quorum_certificate(&qc)
            .expect("qc should persist before finalization");

        consensus
            .commit_block(block_hash)
            .expect("pending block should commit");
        assert!(consensus.committed_blocks.contains_key(&block_hash));

        let previous_view = consensus.current_view();
        consensus
            .finalize_block(block_hash)
            .expect("committed block should finalize");

        assert_eq!(consensus.finalized_block_height, 1);
        assert_eq!(consensus.current_view(), previous_view + 1);
        assert!(!consensus.committed_blocks.contains_key(&block_hash));
        assert_eq!(
            consensus.latest_finalized_block().map(|block| block.hash()),
            Some(block_hash)
        );
        assert_eq!(
            consensus.proposer.validator_id,
            consensus.current_leader().unwrap()
        );
        assert_eq!(
            storage
                .latest_block_height()
                .expect("latest height should load"),
            1
        );

        cleanup_storage(path);
    }

    #[test]
    fn update_validator_set_persists_validators_and_updates_leader_state() {
        let (storage, path) = test_storage("consensus-validator-set");
        let (validator_a, _) = active_validator(6);
        let (validator_b, _) = active_validator(7);
        let mut consensus = with_storage(storage.clone());

        consensus.update_validator_set(vec![validator_a.clone(), validator_b.clone()]);

        assert_eq!(consensus.current_view(), 0);
        assert_eq!(
            consensus.current_leader(),
            consensus.validator_set.get_proposer(0)
        );
        assert_eq!(
            consensus.proposer.validator_id,
            consensus.current_leader().unwrap()
        );

        let stored_view = storage
            .state_get(CONSENSUS_CURRENT_VIEW_KEY.to_vec())
            .expect("view lookup should succeed");
        assert!(stored_view.is_none());

        let mut restored = with_storage(storage);
        restored.start().expect("restored consensus should start");

        assert_eq!(restored.validator_set.active_validator_count(), 2);
        assert_eq!(
            restored.current_leader(),
            restored.validator_set.get_proposer(0)
        );
        assert_eq!(
            restored.proposer.validator_id,
            restored.current_leader().unwrap()
        );

        cleanup_storage(path);
    }

    #[test]
    fn longest_chain_rule_prefers_candidate_at_or_above_best_known_height() {
        let (storage, path) = test_storage("consensus-longest-chain");
        let (validator, _) = active_validator(8);
        let mut consensus = with_storage(storage);

        let base = Block::genesis([0u8; 32]);
        let higher = block_for(base.hash(), 3, validator.address);
        let shorter = block_for(base.hash(), 2, validator.address);
        let equal = block_for(base.hash(), 3, validator.address);

        consensus.pending_blocks.insert(higher.hash(), higher);

        assert!(!consensus.apply_longest_chain_rule(&shorter));
        assert!(consensus.apply_longest_chain_rule(&equal));

        cleanup_storage(path);
    }

    #[test]
    fn highest_qc_rule_tracks_highest_known_block_height() {
        let (storage, path) = test_storage("consensus-highest-qc");
        let (validator, _) = active_validator(9);
        let mut consensus = with_storage(storage);

        let genesis = Block::genesis([0u8; 32]);
        let lower = block_for(genesis.hash(), 1, validator.address);
        let higher = block_for(lower.hash(), 2, validator.address);
        let lower_hash = lower.hash();
        let higher_hash = higher.hash();
        consensus.pending_blocks.insert(lower_hash, lower);
        consensus.pending_blocks.insert(higher_hash, higher);

        consensus.apply_highest_qc_rule(&QuorumCertificate::new(
            lower_hash,
            1,
            Vec::new(),
            Vec::new(),
        ));
        assert_eq!(consensus.highest_qc_block, Some(lower_hash));

        consensus.apply_highest_qc_rule(&QuorumCertificate::new(
            higher_hash,
            2,
            Vec::new(),
            Vec::new(),
        ));
        assert_eq!(consensus.highest_qc_block, Some(higher_hash));

        cleanup_storage(path);
    }

    #[test]
    fn fork_detection_and_resolution_replace_lower_priority_pending_branch() {
        let (storage, path) = test_storage("consensus-fork-resolution");
        let (validator_a, _) = active_validator(10);
        let (validator_b, _) = active_validator(11);
        let mut consensus = with_storage(storage);

        let genesis = Block::genesis([0u8; 32]);
        let incumbent = block_for(genesis.hash(), 1, validator_a.address);
        let candidate = block_for(genesis.hash(), 1, validator_b.address);
        let incumbent_hash = incumbent.hash();
        let candidate_hash = candidate.hash();

        consensus
            .pending_blocks
            .insert(incumbent_hash, incumbent.clone());

        assert!(consensus.detect_fork(&candidate));

        consensus.highest_qc_block = Some(candidate_hash);
        consensus
            .resolve_fork(&candidate)
            .expect("candidate should replace lower-priority branch");

        assert!(!consensus.pending_blocks.contains_key(&incumbent_hash));
        assert!(!consensus.detect_fork(&candidate));

        cleanup_storage(path);
    }

    #[test]
    fn fork_resolution_rejects_shorter_or_lower_priority_branch() {
        let (storage, path) = test_storage("consensus-fork-reject");
        let (validator_a, _) = active_validator(12);
        let (validator_b, _) = active_validator(13);
        let mut consensus = with_storage(storage);

        let genesis = Block::genesis([0u8; 32]);
        let incumbent = block_for(genesis.hash(), 2, validator_a.address);
        let shorter = block_for(genesis.hash(), 1, validator_b.address);
        let same_height_candidate = block_for(genesis.hash(), 2, validator_b.address);
        let incumbent_hash = incumbent.hash();

        consensus
            .pending_blocks
            .insert(incumbent_hash, incumbent.clone());
        assert!(consensus.resolve_fork(&shorter).is_err());

        consensus.highest_qc_block = Some(incumbent_hash);
        assert!(consensus.resolve_fork(&same_height_candidate).is_err());

        cleanup_storage(path);
    }

    #[test]
    fn conflicting_finalized_branch_is_rejected() {
        let (storage, path) = test_storage("consensus-conflicting-branch");
        let (validator_a, _) = active_validator(14);
        let (validator_b, _) = active_validator(15);
        let mut consensus = with_storage(storage);
        consensus.update_validator_set(vec![validator_a.clone(), validator_b.clone()]);

        let genesis = Block::genesis([0u8; 32]);
        let finalized = block_for(genesis.hash(), 1, validator_a.address);
        let candidate = block_for([9u8; 32], 1, validator_b.address);
        consensus
            .finalized_blocks
            .insert(finalized.hash(), finalized);

        assert!(consensus.is_conflicting_branch(&candidate));
        assert!(consensus.reject_conflicting_branch(&candidate).is_err());
        assert!(consensus.process_block_proposal(candidate).is_err());

        cleanup_storage(path);
    }

    #[test]
    fn consensus_network_methods_broadcast_and_decode_expected_payloads() {
        let (storage, path) = test_storage("consensus-network-broadcasts");
        let (validator_a, signing_key) = active_validator(16);
        let (validator_b, _) = active_validator(17);
        let mut consensus = with_storage(storage);
        consensus.update_validator_set(vec![validator_a.clone(), validator_b.clone()]);
        consensus.pacemaker.current_view = 3;

        let block = block_for([1u8; 32], 2, validator_a.address);
        let mut vote = Vote::new(validator_a.address, block.hash(), 3);
        vote.sign(&signing_key).expect("vote should sign");
        let qc = QuorumCertificate::new(
            block.hash(),
            3,
            vec![vote.signature.to_vec()],
            vec![validator_a.address],
        );
        let network = MockConsensusNetwork::default();

        consensus
            .broadcast_block_proposal_to_peers(&network, &block)
            .expect("block proposal broadcast should succeed");
        let decoded_block: Block = bincode::deserialize(&network.block_proposals.borrow()[0])
            .expect("broadcast block should deserialize");
        assert_eq!(decoded_block.hash(), block.hash());

        consensus
            .broadcast_vote_to_peers(&network, &vote)
            .expect("vote broadcast should succeed");
        let decoded_vote =
            Vote::decode(&network.votes.borrow()[0]).expect("broadcast vote should deserialize");
        assert_eq!(decoded_vote.block_hash, vote.block_hash);

        consensus
            .broadcast_quorum_certificate_to_peers(&network, &qc)
            .expect("qc broadcast should succeed");
        let decoded_qc = QuorumCertificate::decode(&network.quorum_certificates.borrow()[0])
            .expect("broadcast qc should deserialize");
        assert_eq!(decoded_qc.block_hash, qc.block_hash);

        consensus
            .broadcast_new_view_message(&network)
            .expect("new-view broadcast should succeed");
        let new_view: crate::hotstuff::pacemaker::NewViewMessage =
            bincode::deserialize(&network.new_views.borrow()[0])
                .expect("new-view payload should deserialize");
        assert_eq!(new_view.view, 3);
        assert_eq!(new_view.leader_index, Some(1));

        consensus
            .synchronize_validator_state_with_network(&network)
            .expect("validator sync should succeed");
        let synced_validators: Vec<Validator> =
            bincode::deserialize(&network.validator_syncs.borrow()[0])
                .expect("validator sync payload should deserialize");
        assert_eq!(synced_validators.len(), 2);
        assert!(synced_validators
            .iter()
            .any(|validator| validator.address == validator_a.address));
        assert!(synced_validators
            .iter()
            .any(|validator| validator.address == validator_b.address));

        cleanup_storage(path);
    }

    #[test]
    fn consensus_can_request_and_decode_missing_blocks_from_peers() {
        let (storage, path) = test_storage("consensus-request-missing-blocks");
        let (validator, _) = active_validator(18);
        let consensus = with_storage(storage);
        let block_a = block_for([2u8; 32], 4, validator.address);
        let block_b = block_for(block_a.hash(), 5, validator.address);
        let network = MockConsensusNetwork {
            missing_blocks_response: RefCell::new(vec![
                bincode::serialize(&block_a).expect("block a should serialize"),
                bincode::serialize(&block_b).expect("block b should serialize"),
            ]),
            ..Default::default()
        };

        let blocks = consensus
            .request_missing_blocks_from_peers(&network, 4, 2)
            .expect("missing block request should succeed");

        assert_eq!(
            network.missing_blocks_requests.borrow().as_slice(),
            &[(4, 2)]
        );
        assert_eq!(blocks.len(), 2);
        assert_eq!(blocks[0].hash(), block_a.hash());
        assert_eq!(blocks[1].hash(), block_b.hash());

        cleanup_storage(path);
    }

    #[test]
    fn consensus_state_persistence_and_restore_round_trip_votes_qcs_validators_and_view() {
        let (storage, path) = test_storage("consensus-restore-roundtrip");
        let (validator_a, signer_a) = active_validator(24);
        let (validator_b, signer_b) = active_validator(25);

        let block_hash = {
            let genesis = Block::genesis([0u8; 32]);
            let block = block_for(genesis.hash(), 1, validator_a.address);
            block.hash()
        };

        {
            let mut consensus = with_storage(storage.clone());
            consensus.update_validator_set(vec![validator_a.clone(), validator_b.clone()]);
            consensus.pacemaker.current_view = 9;

            let mut vote_a = Vote::new(validator_a.address, block_hash, 9);
            let mut vote_b = Vote::new(validator_b.address, block_hash, 9);
            vote_a.sign(&signer_a).expect("vote a should sign");
            vote_b.sign(&signer_b).expect("vote b should sign");
            consensus
                .persist_vote_in_storage(&vote_a)
                .expect("vote a should persist");
            consensus
                .persist_vote_in_storage(&vote_b)
                .expect("vote b should persist");

            let qc = QuorumCertificate::new(
                block_hash,
                9,
                vec![vote_a.signature.to_vec(), vote_b.signature.to_vec()],
                vec![vote_a.validator, vote_b.validator],
            );
            consensus
                .persist_quorum_certificate(&qc)
                .expect("qc should persist");
            consensus
                .persist_current_consensus_view()
                .expect("view should persist");
            consensus
                .stop()
                .expect("consensus stop should persist validator set");
        }

        let stored_validators: Vec<Validator> = bincode::deserialize(
            &storage
                .state_get(CONSENSUS_VALIDATOR_SET_KEY.to_vec())
                .expect("validator set read should succeed")
                .expect("validator set should persist"),
        )
        .expect("validator set should deserialize");
        assert_eq!(stored_validators.len(), 2);

        let stored_view_bytes = storage
            .state_get(CONSENSUS_CURRENT_VIEW_KEY.to_vec())
            .expect("view read should succeed")
            .expect("view should persist");
        let mut stored_view = [0u8; 8];
        stored_view.copy_from_slice(&stored_view_bytes);
        assert_eq!(u64::from_le_bytes(stored_view), 9);

        let stored_votes = storage
            .state_prefix_scan(CONSENSUS_VOTE_PREFIX.to_vec())
            .expect("vote scan should succeed");
        assert_eq!(stored_votes.len(), 2);

        let stored_qcs = storage
            .state_prefix_scan(CONSENSUS_QC_PREFIX.to_vec())
            .expect("qc scan should succeed");
        assert_eq!(stored_qcs.len(), 1);

        let mut restored = with_storage(storage);
        restored
            .start()
            .expect("consensus should restore from storage");

        assert_eq!(restored.current_view(), 9);
        assert_eq!(restored.validator_set.active_validator_count(), 2);
        assert_eq!(restored.vote_collector.vote_count(9, block_hash), 2);
        assert_eq!(restored.highest_qc_block, Some(block_hash));
        assert_eq!(
            restored.proposer.validator_id,
            restored.current_leader().unwrap()
        );

        cleanup_storage(path);
    }
}
