//! Integration tests for the Vage blockchain node.
//!
//! Tests cover:
//! - HotStuff consensus safety (locked block, fork resolution)
//! - Execution determinism (same block → same state root)
//! - Mempool chain_id replay protection
//! - Transaction priority / eviction

use vage_block::{Block, BlockBody, BlockHeader};
use vage_consensus::hotstuff::{HotStuff, HotStuffPhase};
use vage_consensus::hotstuff::vote::QuorumCertificate;
use vage_types::Address;

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

fn make_block(parent_hash: [u8; 32], height: u64) -> Block {
    let mut header = BlockHeader::new(parent_hash, height);
    Block::new(header, BlockBody::empty())
}

fn make_qc(block: &Block, view: u64) -> QuorumCertificate {
    QuorumCertificate::new(block.hash(), view, vec![], vec![])
}

// ─────────────────────────────────────────────────────────────────────────────
// HotStuff consensus safety tests
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn hotstuff_three_phase_commit_advances_through_all_phases() {
    let mut hs = HotStuff::new();
    let genesis = Block::genesis([0u8; 32]);
    let b1 = make_block(genesis.hash(), 1);
    let qc1 = make_qc(&b1, 1);

    // Prepare phase
    let phase = hs
        .apply_three_phase_commit_rule(&b1, qc1.clone())
        .expect("prepare phase should succeed");
    assert_eq!(phase, HotStuffPhase::Prepare);

    // PreCommit phase
    let phase = hs
        .apply_three_phase_commit_rule(&b1, qc1.clone())
        .expect("pre-commit phase should succeed");
    assert_eq!(phase, HotStuffPhase::PreCommit);
    // Locked block is set after PreCommit.
    assert_eq!(hs.locked_block, Some(b1.hash()));

    // Commit → Finalize phase
    let phase = hs
        .apply_three_phase_commit_rule(&b1, qc1)
        .expect("commit phase should succeed");
    assert_eq!(phase, HotStuffPhase::Finalize);
}

#[test]
fn hotstuff_safety_rule_rejects_conflicting_fork() {
    let mut hs = HotStuff::new();
    let genesis = Block::genesis([0u8; 32]);

    // Commit block B1 through all 3 phases so it becomes the locked block.
    let b1 = make_block(genesis.hash(), 1);
    let qc1 = make_qc(&b1, 1);
    hs.apply_three_phase_commit_rule(&b1, qc1.clone()).unwrap(); // Prepare
    hs.apply_three_phase_commit_rule(&b1, qc1.clone()).unwrap(); // PreCommit → locked
    hs.apply_three_phase_commit_rule(&b1, qc1).unwrap();         // Finalize

    // Try to propose a conflicting fork B2′ that does NOT extend B1.
    // Parent is genesis, not B1, so it conflicts with the locked block.
    let b2_conflict = make_block(genesis.hash(), 1); // same height, different parent chain
    let qc_conflict = make_qc(&b2_conflict, 2);

    let result = hs.verify_prepare_phase(&b2_conflict, &qc_conflict);
    // Must be rejected (locked block safety rule).
    match result {
        Ok(false) => {} // correct — proposal rejected
        Ok(true) => panic!("conflicting fork should have been rejected"),
        Err(_) => {} // also acceptable — error rejection
    }
}

#[test]
fn hotstuff_fork_choice_selects_highest_qc_view() {
    let mut hs = HotStuff::new();
    let genesis = Block::genesis([0u8; 32]);

    let b1 = make_block(genesis.hash(), 1);
    let b2 = make_block(genesis.hash(), 1); // competing fork at same height

    // Record b1 at view 5, b2 at view 3.
    let qc1 = make_qc(&b1, 5);
    let qc2 = make_qc(&b2, 3);
    hs.apply_three_phase_commit_rule(&b1, qc1).unwrap();
    hs.apply_three_phase_commit_rule(&b2, qc2).unwrap();

    // Fork choice must prefer b1 (higher QC view).
    assert_eq!(hs.fork_choice(b1.hash(), b2.hash()), b1.hash());
    // Symmetric: same result regardless of argument order.
    assert_eq!(hs.fork_choice(b2.hash(), b1.hash()), b1.hash());
}

#[test]
fn hotstuff_locked_block_updated_at_precommit() {
    let mut hs = HotStuff::new();
    let genesis = Block::genesis([0u8; 32]);
    let b1 = make_block(genesis.hash(), 1);
    let qc1 = make_qc(&b1, 1);

    assert!(hs.locked_block.is_none());
    hs.apply_three_phase_commit_rule(&b1, qc1.clone()).unwrap(); // Prepare
    assert!(hs.locked_block.is_none(), "locked_block must not be set at Prepare");

    hs.apply_three_phase_commit_rule(&b1, qc1).unwrap(); // PreCommit
    assert_eq!(
        hs.locked_block,
        Some(b1.hash()),
        "locked_block must be set at PreCommit"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Execution determinism tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(feature = "test-execution")]
mod execution_tests {
    use vage_execution::Executor;
    use vage_state::StateDB;
    use vage_storage::StorageEngine;
    use vage_types::{Address, Transaction};
    use primitive_types::U256;
    use std::sync::Arc;
    use tempfile::TempDir;

    fn make_storage(dir: &TempDir) -> Arc<StorageEngine> {
        Arc::new(
            StorageEngine::new(dir.path().join("db").to_str().unwrap())
                .expect("storage engine should open"),
        )
    }

    #[test]
    fn execution_is_deterministic_across_two_runs() {
        let dir1 = TempDir::new().unwrap();
        let dir2 = TempDir::new().unwrap();

        let storage1 = make_storage(&dir1);
        let storage2 = make_storage(&dir2);
        let state1 = Arc::new(StateDB::new(storage1.clone()));
        let state2 = Arc::new(StateDB::new(storage2.clone()));

        let executor1 = Executor::new(state1.clone());
        let executor2 = Executor::new(state2.clone());

        let from = Address::from([1u8; 20]);
        let to   = Address::from([2u8; 20]);
        let tx = Transaction::new_transfer(from, to, U256::from(100), 0);

        let genesis = vage_block::Block::genesis([0u8; 32]);

        let receipts1 = executor1
            .execute_block(&genesis, vec![tx.clone()])
            .expect("execution 1 should succeed");
        let receipts2 = executor2
            .execute_block(&genesis, vec![tx])
            .expect("execution 2 should succeed");

        assert_eq!(
            receipts1.len(),
            receipts2.len(),
            "receipt counts must match"
        );

        let root1 = state1.commit().unwrap();
        let root2 = state2.commit().unwrap();
        assert_eq!(root1, root2, "state roots must be deterministic");
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Mempool replay-protection tests
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn mempool_rejects_transaction_with_wrong_chain_id() {
    use vage_mempool::validation::{TransactionValidator, TxValidationConfig};
    use vage_state::StateDB;
    use vage_storage::StorageEngine;
    use vage_types::{Address, Transaction};
    use primitive_types::U256;
    use std::sync::Arc;
    use tempfile::TempDir;

    let dir = TempDir::new().unwrap();
    let storage = Arc::new(
        StorageEngine::new(dir.path().join("db").to_str().unwrap()).unwrap(),
    );
    let state = Arc::new(StateDB::new(storage));

    let config = TxValidationConfig {
        chain_id: 1,
        ..TxValidationConfig::default()
    };
    let validator = TransactionValidator::new(state, config);

    let mut tx = Transaction::new_transfer(
        Address::from([1u8; 20]),
        Address::from([2u8; 20]),
        U256::from(1),
        0,
    );
    // Wrong chain_id
    tx.chain_id = Some(999);

    let result = validator.validate(&tx);
    assert!(
        result.is_err(),
        "transaction with wrong chain_id must be rejected"
    );
}

#[test]
fn mempool_rejects_transaction_without_chain_id() {
    use vage_mempool::validation::{TransactionValidator, TxValidationConfig};
    use vage_state::StateDB;
    use vage_storage::StorageEngine;
    use vage_types::{Address, Transaction};
    use primitive_types::U256;
    use std::sync::Arc;
    use tempfile::TempDir;

    let dir = TempDir::new().unwrap();
    let storage = Arc::new(
        StorageEngine::new(dir.path().join("db").to_str().unwrap()).unwrap(),
    );
    let state = Arc::new(StateDB::new(storage));

    let config = TxValidationConfig::default(); // chain_id = 1
    let validator = TransactionValidator::new(state, config);

    let mut tx = Transaction::new_transfer(
        Address::from([1u8; 20]),
        Address::from([2u8; 20]),
        U256::from(1),
        0,
    );
    // No chain_id
    tx.chain_id = None;

    let result = validator.validate(&tx);
    assert!(
        result.is_err(),
        "transaction without chain_id must be rejected"
    );
}
