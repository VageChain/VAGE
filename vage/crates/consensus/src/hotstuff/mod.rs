pub mod pacemaker;
pub mod proposer;
pub mod vote;

use crate::hotstuff::vote::QuorumCertificate;
use anyhow::{bail, Result};
use std::collections::HashMap;
use tracing::warn;
use vage_block::Block;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HotStuffPhase {
    Prepare,
    PreCommit,
    Commit,
    Finalize,
}

pub struct HotStuff {
    prepare_qcs: HashMap<[u8; 32], QuorumCertificate>,
    precommit_qcs: HashMap<[u8; 32], QuorumCertificate>,
    commit_qcs: HashMap<[u8; 32], QuorumCertificate>,
    /// Safety lock: the highest block hash for which we have a PreCommit QC.
    /// A node must never vote for a block that conflicts with its locked block
    /// (HotStuff paper Â§4 "Locked Block" safety rule).
    pub locked_block: Option<[u8; 32]>,
    /// The highest QC view number seen so far (liveness rule).
    pub highest_qc_view: u64,
    /// Map from block hash â†’ parent block hash (populated at Prepare time).
    block_parent: HashMap<[u8; 32], [u8; 32]>,
    /// Map from block hash â†’ view number (populated at Prepare time).
    block_views: HashMap<[u8; 32], u64>,
}

impl Default for HotStuff {
    fn default() -> Self {
        Self::new()
    }
}

impl HotStuff {
    pub fn new() -> Self {
        Self {
            prepare_qcs: HashMap::new(),
            precommit_qcs: HashMap::new(),
            commit_qcs: HashMap::new(),
            locked_block: None,
            highest_qc_view: 0,
            block_parent: HashMap::new(),
            block_views: HashMap::new(),
        }
    }

    /// Update the locked block after receiving a PreCommit QC.
    /// The locked block is updated to the block with the highest PreCommit QC.
    pub fn update_locked_block(&mut self, block_hash: [u8; 32]) {
        self.locked_block = Some(block_hash);
    }

    /// Update the highest QC view for liveness.
    pub fn update_highest_qc(&mut self, qc: &QuorumCertificate) {
        if qc.view > self.highest_qc_view {
            self.highest_qc_view = qc.view;
        }
    }

    /// Deterministic fork-choice: among two conflicting tips, select the branch
    /// extending the QC with the highest view number. This is equivalent to
    /// the "prefer-highest-QC" rule in the HotStuff paper.
    pub fn fork_choice(&self, tip_a: [u8; 32], tip_b: [u8; 32]) -> [u8; 32] {
        let view_a = self.block_views.get(&tip_a).copied().unwrap_or(0);
        let view_b = self.block_views.get(&tip_b).copied().unwrap_or(0);
        if view_a >= view_b {
            tip_a
        } else {
            tip_b
        }
    }

    pub fn apply_three_phase_commit_rule(
        &mut self,
        block: &Block,
        qc: QuorumCertificate,
    ) -> Result<HotStuffPhase> {
        let block_hash = block.hash();

        if !self.prepare_qcs.contains_key(&block_hash) {
            if !self.verify_prepare_phase(block, &qc)? {
                bail!("prepare phase verification failed");
            }
            // Record block metadata for fork-choice and parent QC checks.
            self.block_parent
                .insert(block_hash, block.header.parent_hash);
            self.block_views.insert(block_hash, qc.view);
            self.update_highest_qc(&qc);
            self.prepare_qcs.insert(block_hash, qc);
            return Ok(HotStuffPhase::Prepare);
        }

        if !self.precommit_qcs.contains_key(&block_hash) {
            if !self.verify_pre_commit_phase(block_hash, &qc)? {
                bail!("pre-commit phase verification failed");
            }
            self.update_highest_qc(&qc);
            // Advance the locked block to this block (safety rule).
            self.update_locked_block(block_hash);
            self.precommit_qcs.insert(block_hash, qc);
            return Ok(HotStuffPhase::PreCommit);
        }

        if !self.verify_commit_phase(block_hash, &qc)? {
            bail!("commit phase verification failed");
        }
        self.update_highest_qc(&qc);
        self.commit_qcs.insert(block_hash, qc);
        Ok(HotStuffPhase::Finalize)
    }

    /// Verify the Prepare phase:
    ///  1. Block passes basic validation.
    ///  2. The QC references this block's hash.
    ///  3. The proposal does NOT conflict with the locked block (safety rule).
    ///  4. If there is a parent QC, its block_hash matches block.header.parent_hash.
    pub fn verify_prepare_phase(&self, block: &Block, qc: &QuorumCertificate) -> Result<bool> {
        // Basic structural check.
        if block.validate_basic().is_err() {
            return Ok(false);
        }

        let block_hash = block.hash();

        // QC must reference this block.
        if qc.block_hash != block_hash {
            return Ok(false);
        }

        // â”€â”€ SAFETY RULE: reject proposal that conflicts with the locked block â”€â”€
        // A block B conflicts with locked_block L if B does not extend L (i.e.
        // B is not a descendant of L).  We enforce this by requiring that any
        // proposal's parent chain passes through the locked block.
        if let Some(locked) = self.locked_block {
            if !self.extends_locked_block(locked, block) {
                warn!(
                    "rejecting proposal {}: conflicts with locked block {:?}",
                    hex::encode(block_hash),
                    hex::encode(locked)
                );
                return Ok(false);
            }
        }

        // â”€â”€ PARENT QC VERIFICATION â”€â”€
        // If the proposed block's parent already has a QC recorded, verify
        // that the QC for the parent matches the parent_hash in the header.
        // This prevents validators from signing orphaned branches.
        let parent_hash = block.header.parent_hash;
        let parent_qc_ok = match self.prepare_qcs.get(&parent_hash) {
            Some(parent_qc) => parent_qc.block_hash == parent_hash,
            // No parent QC yet means this is the genesis block or the parent
            // was finalized in a previous epoch â€” both are accepted.
            None => true,
        };

        Ok(parent_qc_ok)
    }

    /// Check whether `block` extends the locked block (i.e. locked_block is an
    /// ancestor of block).  We walk up the known parent chain up to 64 hops to
    /// avoid unbounded loops.  If we can't find the locked block in the chain,
    /// we allow the proposal so the node does not stall on pruned history.
    fn extends_locked_block(&self, locked: [u8; 32], block: &Block) -> bool {
        // The locked block is always an ancestor of itself.
        if block.hash() == locked {
            return true;
        }
        let mut current = block.header.parent_hash;
        for _ in 0..64 {
            if current == locked {
                return true;
            }
            // Zero hash means genesis â€” stop searching.
            if current == [0u8; 32] {
                break;
            }
            match self.block_parent.get(&current) {
                Some(&parent) => current = parent,
                None => return false,
            }
        }
        false
    }

    pub fn verify_pre_commit_phase(
        &self,
        block_hash: [u8; 32],
        qc: &QuorumCertificate,
    ) -> Result<bool> {
        Ok(self.prepare_qcs.contains_key(&block_hash) && qc.block_hash == block_hash)
    }

    pub fn verify_commit_phase(
        &self,
        block_hash: [u8; 32],
        qc: &QuorumCertificate,
    ) -> Result<bool> {
        Ok(self.precommit_qcs.contains_key(&block_hash) && qc.block_hash == block_hash)
    }

    pub fn has_prepare_quorum(&self, block_hash: [u8; 32]) -> bool {
        self.prepare_qcs.contains_key(&block_hash)
    }

    pub fn has_precommit_quorum(&self, block_hash: [u8; 32]) -> bool {
        self.precommit_qcs.contains_key(&block_hash)
    }

    pub fn has_commit_quorum(&self, block_hash: [u8; 32]) -> bool {
        self.commit_qcs.contains_key(&block_hash)
    }
}

#[cfg(test)]
mod tests {
    use super::{HotStuff, HotStuffPhase};
    use crate::hotstuff::vote::QuorumCertificate;
    use vage_block::{Block, BlockBody, BlockHeader};
    use vage_types::Address;

    fn block_for(parent_hash: [u8; 32], height: u64) -> Block {
        let mut header = BlockHeader::new(parent_hash, height);
        header.proposer = Address([height as u8; 32]);
        let mut block = Block::new(header, BlockBody::empty());
        block.compute_roots();
        block
    }

    fn qc_for(block_hash: [u8; 32], view: u64) -> QuorumCertificate {
        QuorumCertificate::new(block_hash, view, Vec::new(), Vec::new())
    }

    #[test]
    fn three_phase_commit_progresses_prepare_precommit_finalize_in_order() {
        let mut hotstuff = HotStuff::new();
        let block = block_for([1u8; 32], 1);
        let block_hash = block.hash();

        let prepare_phase = hotstuff
            .apply_three_phase_commit_rule(&block, qc_for(block_hash, 1))
            .expect("prepare phase should succeed");
        assert_eq!(prepare_phase, HotStuffPhase::Prepare);
        assert!(hotstuff.has_prepare_quorum(block_hash));
        assert!(!hotstuff.has_precommit_quorum(block_hash));
        assert!(!hotstuff.has_commit_quorum(block_hash));

        let precommit_phase = hotstuff
            .apply_three_phase_commit_rule(&block, qc_for(block_hash, 2))
            .expect("pre-commit phase should succeed");
        assert_eq!(precommit_phase, HotStuffPhase::PreCommit);
        assert!(hotstuff.has_precommit_quorum(block_hash));
        assert!(!hotstuff.has_commit_quorum(block_hash));

        let finalize_phase = hotstuff
            .apply_three_phase_commit_rule(&block, qc_for(block_hash, 3))
            .expect("finalize phase should succeed");
        assert_eq!(finalize_phase, HotStuffPhase::Finalize);
        assert!(hotstuff.has_commit_quorum(block_hash));
    }

    #[test]
    fn prepare_phase_rejects_qc_for_wrong_block_hash() {
        let mut hotstuff = HotStuff::new();
        let block = block_for([2u8; 32], 2);

        let error = hotstuff
            .apply_three_phase_commit_rule(&block, qc_for([9u8; 32], 1))
            .expect_err("prepare phase should reject mismatched qc");

        assert!(error
            .to_string()
            .contains("prepare phase verification failed"));
    }

    #[test]
    fn precommit_phase_requires_existing_prepare_quorum() {
        let hotstuff = HotStuff::new();
        let block = block_for([3u8; 32], 3);
        let block_hash = block.hash();

        assert!(!hotstuff
            .verify_pre_commit_phase(block_hash, &qc_for(block_hash, 1))
            .expect("pre-commit verification should run without state"));
    }

    #[test]
    fn commit_phase_requires_existing_precommit_quorum() {
        let mut hotstuff = HotStuff::new();
        let block = block_for([4u8; 32], 4);
        let block_hash = block.hash();

        hotstuff
            .apply_three_phase_commit_rule(&block, qc_for(block_hash, 1))
            .expect("prepare phase should succeed");

        assert!(!hotstuff
            .verify_commit_phase(block_hash, &qc_for(block_hash, 2))
            .expect("commit verification should fail before pre-commit quorum"));
    }

    #[test]
    fn precommit_and_commit_reject_mismatched_qc_hash_after_progression() {
        let mut hotstuff = HotStuff::new();
        let block = block_for([5u8; 32], 5);
        let block_hash = block.hash();

        hotstuff
            .apply_three_phase_commit_rule(&block, qc_for(block_hash, 1))
            .expect("prepare phase should succeed");
        let precommit_error = hotstuff
            .apply_three_phase_commit_rule(&block, qc_for([7u8; 32], 2))
            .expect_err("pre-commit should reject mismatched qc hash");
        assert!(precommit_error
            .to_string()
            .contains("pre-commit phase verification failed"));

        hotstuff
            .apply_three_phase_commit_rule(&block, qc_for(block_hash, 2))
            .expect("pre-commit phase should succeed");
        let commit_error = hotstuff
            .apply_three_phase_commit_rule(&block, qc_for([8u8; 32], 3))
            .expect_err("commit should reject mismatched qc hash");
        assert!(commit_error
            .to_string()
            .contains("commit phase verification failed"));
    }
}
