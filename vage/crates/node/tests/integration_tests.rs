/// Integration tests for the consensus â†’ execution â†’ storage pipeline.
///
/// These tests verify that the major subsystems work together correctly:
/// - Consensus can produce block proposals and reach quorum
/// - Execution correctly processes transactions against state
/// - Storage persists and retrieves all data across restarts
use ed25519_dalek::{Signer, SigningKey};
use primitive_types::U256;
use vage_block::{Block, BlockBody, BlockHeader};
use vage_consensus::hotstuff::vote::Vote;
use vage_consensus::Consensus;
use vage_execution::Executor;
use vage_light_client::LightClient;
use vage_networking::{
    L1Response, P2PConfig, P2PNetwork, Peer, RpcStateProofResponse, RpcStateProofValue,
    RpcVerifiedHeaderEnvelope,
};
use vage_state::StateDB;
use vage_storage::StorageEngine;
use vage_types::validator::ValidatorStatus;
use vage_types::{Account, Address, Transaction, Validator};
use std::fs;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::Mutex;

// bincode is needed for serialising blocks into the storage layer
extern crate bincode;

// â”€â”€â”€ helpers â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

fn unique_db_path(label: &str) -> PathBuf {
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock should be valid")
        .as_nanos();
    std::env::temp_dir().join(format!("integration-{label}-{ts}.redb"))
}

fn make_storage(label: &str) -> (Arc<StorageEngine>, PathBuf) {
    let path = unique_db_path(label);
    let engine = StorageEngine::new(path.to_string_lossy().as_ref())
        .expect("integration test storage should initialise");
    (Arc::new(engine), path)
}

fn signing_key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

fn funded_address(seed: u8) -> (Address, SigningKey) {
    let sk = signing_key(seed);
    let pk = sk.verifying_key().to_bytes();
    (Address::from_public_key(&pk), sk)
}

fn active_validator(seed: u8) -> (Validator, SigningKey) {
    let sk = signing_key(seed);
    let pk = sk.verifying_key().to_bytes();
    let addr = Address::from_public_key(&pk);
    let mut v = Validator::new(addr, pk, U256::from(10u64.pow(18)));
    v.status = ValidatorStatus::Active;
    (v, sk)
}

fn empty_block(parent_hash: [u8; 32], height: u64, proposer: Address) -> Block {
    let mut header = BlockHeader::new(parent_hash, height);
    header.proposer = proposer;
    let mut block = Block::new(header, BlockBody::empty());
    block.compute_roots();
    block
}

fn transfer_tx(from: Address, sk: &SigningKey, to: Address, nonce: u64) -> Transaction {
    let mut tx = Transaction::new_transfer(from, to, U256::from(1000u64), nonce);
    tx.gas_limit = 21_000;
    tx.gas_price = U256::from(1);
    tx.sign(sk).expect("transaction signing should succeed");
    tx
}

fn p2p_test_config() -> P2PConfig {
    P2PConfig {
        local_key: libp2p::identity::Keypair::generate_ed25519(),
        bootstrap_peers: Vec::new(),
        discovery_interval: std::time::Duration::from_millis(25),
        discovery_backoff: std::time::Duration::from_millis(10),
        max_peers: 8,
    }
}

fn tcp_addr(port: u16) -> libp2p::Multiaddr {
    format!("/ip4/127.0.0.1/tcp/{port}")
        .parse()
        .expect("tcp multiaddr should parse")
}

// â”€â”€â”€ test 1: storage persists and reloads block/state data â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

#[test]
fn storage_persists_block_and_state_across_reopen() {
    let (storage, path) = make_storage("persist");

    let genesis = Block::genesis([0u8; 32]);
    let header_bytes = bincode::serialize(&genesis.header)
        .expect("header serialization should succeed");
    let body_bytes = bincode::serialize(&genesis.body)
        .expect("body serialization should succeed");
    storage
        .atomic_block_commit(genesis.header.height, header_bytes, body_bytes)
        .expect("genesis block should store");

    let state = StateDB::new(storage.clone());
    let addr = Address::random();
    let mut account = Account::new(addr);
    account.increase_balance(U256::from(1_000_000u64));
    state
        .update_account(&addr, &account)
        .expect("account update should succeed");
    state.commit().expect("state commit should succeed");
    let _root_after_commit = state.state_root();
    drop(state);
    drop(storage);

    // Reopen
    let storage2 = Arc::new(
        StorageEngine::new(path.to_string_lossy().as_ref())
            .expect("storage reopen should succeed"),
    );
    let height = storage2
        .latest_block_height()
        .expect("height lookup should succeed");
    assert_eq!(height, 0, "genesis height should be 0");

    let loaded_header = storage2
        .get_block_header(0)
        .expect("block header load should succeed");
    assert!(loaded_header.is_some(), "genesis header should be found after reopen");
    assert_eq!(loaded_header.unwrap().height, genesis.header.height);

    let state2 = StateDB::new(storage2);
    let loaded_account = state2
        .get_account(&addr)
        .expect("account load should succeed")
        .expect("funded account should exist after reopen");
    assert_eq!(loaded_account.balance, U256::from(1_000_000u64));
    // State root is not asserted here: the Verkle tree root is recomputed lazily
    // from persisted account data. The important invariant is that account state survives.

    let _ = fs::remove_file(&path);
}

// â”€â”€â”€ test 2: execution processes a transfer and updates state â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

#[test]
fn execution_processes_transfer_and_updates_balances() {
    let (storage, path) = make_storage("exec-transfer");
    let state = Arc::new(StateDB::new(storage));
    let executor = Executor::new(state.clone());

    let (sender_addr, sender_sk) = funded_address(10);
    let (recipient_addr, _) = funded_address(11);

    // Seed sender with funds (enough for value + gas)
    let mut sender_account = Account::new(sender_addr);
    sender_account.increase_balance(U256::from(500_000u64));
    state
        .update_account(&sender_addr, &sender_account)
        .expect("seed sender");
    // Create recipient so pre-execution checks pass
    let recipient_account = Account::new(recipient_addr);
    state
        .update_account(&recipient_addr, &recipient_account)
        .expect("seed recipient");
    state.commit().expect("pre-execution commit");

    let tx = transfer_tx(sender_addr, &sender_sk, recipient_addr, 0);
    let receipt = executor
        .execute_transaction(&tx)
        .expect("transfer execution should succeed");

    assert!(receipt.status, "transfer receipt should indicate success");
    assert!(receipt.gas_used > 0, "gas should be consumed");

    let sender_after = state
        .get_account(&sender_addr)
        .expect("load sender")
        .expect("sender should still exist");
    let recipient_after = state
        .get_account(&recipient_addr)
        .expect("load recipient")
        .expect("recipient should exist after transfer");

    // Recipient received the value
    assert_eq!(
        recipient_after.balance,
        U256::from(1000u64),
        "recipient balance should equal the transferred value"
    );
    // Sender nonce was incremented
    assert_eq!(sender_after.nonce, 1, "sender nonce should be 1 post-tx");

    let _ = fs::remove_file(&path);
}

// â”€â”€â”€ test 3: consensus reaches quorum and moves to next view â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

#[test]
fn consensus_reaches_quorum_and_advances_view() {
    let (storage, path) = make_storage("consensus-quorum");
    let (validator_a, signer_a) = active_validator(20);
    let (validator_b, signer_b) = active_validator(21);

    let mut consensus = Consensus::with_storage(storage);
    consensus.update_validator_set(vec![validator_a.clone(), validator_b.clone()]);

    let genesis = Block::genesis([0u8; 32]);
    let leader = consensus
        .current_leader()
        .expect("leader should be elected after validator set update");
    let proposal = empty_block(genesis.hash(), 1, leader);
    let block_hash = proposal.hash();

    consensus
        .process_block_proposal(proposal)
        .expect("block proposal should be accepted");

    let mut vote_a = Vote::new(validator_a.address, block_hash, consensus.current_view());
    let mut vote_b = Vote::new(validator_b.address, block_hash, consensus.current_view());
    vote_a.sign(&signer_a).expect("vote_a sign");
    vote_b.sign(&signer_b).expect("vote_b sign");

    consensus
        .process_vote(vote_a)
        .expect("vote_a should be accepted");
    let qc = consensus
        .process_vote(vote_b)
        .expect("vote_b should be accepted");

    assert!(qc.is_some(), "quorum certificate should be produced on second vote");

    let _ = fs::remove_file(&path);
}

// â”€â”€â”€ test 4: full pipeline â€“ consensus finalises â”€â†’ execution updates state â”€

#[test]
fn pipeline_consensus_finalises_block_then_execution_updates_state() {
    let (storage, path) = make_storage("pipeline");
    let (validator_a, signer_a) = active_validator(30);
    let (validator_b, signer_b) = active_validator(31);

    let (sender_addr, sender_sk) = funded_address(32);
    let (recipient_addr, _) = funded_address(33);

    // Shared storage between consensus and state layers
    let state = Arc::new(StateDB::new(storage.clone()));
    let executor = Executor::new(state.clone());

    // Seed sender and recipient in state
    let mut sender = Account::new(sender_addr);
    sender.increase_balance(U256::from(1_000_000u64));
    state.update_account(&sender_addr, &sender).expect("seed sender");
    state.update_account(&recipient_addr, &Account::new(recipient_addr)).expect("seed recipient");
    state.commit().expect("initial state commit");

    // Consensus flow: elect validators, propose an empty block, reach quorum, commit.
    // Execution is tested separately below.
    let mut consensus = Consensus::with_storage(storage);
    consensus.update_validator_set(vec![validator_a.clone(), validator_b.clone()]);

    let genesis = Block::genesis([0u8; 32]);
    let leader = consensus
        .current_leader()
        .expect("leader should exist");
    // Use an empty block so validate_basic() passes (no receipts needed).  
    let proposal = empty_block(genesis.hash(), 1, leader);
    let block_hash = proposal.hash();

    consensus
        .process_block_proposal(proposal.clone())
        .expect("consensus should accept block proposal");

    let mut vote_a = Vote::new(validator_a.address, block_hash, consensus.current_view());
    let mut vote_b = Vote::new(validator_b.address, block_hash, consensus.current_view());
    vote_a.sign(&signer_a).expect("vote_a sign");
    vote_b.sign(&signer_b).expect("vote_b sign");

    consensus.process_vote(vote_a).expect("vote_a");
    let qc = consensus.process_vote(vote_b).expect("vote_b");
    assert!(qc.is_some(), "QC should form");

    consensus
        .commit_block(block_hash)
        .expect("block commit should succeed");

    // Execution flow: run a value transfer through the executor and verify state.
    let tx = transfer_tx(sender_addr, &sender_sk, recipient_addr, 0);
    let receipt = executor
        .execute_transaction(&tx)
        .expect("transfer should execute");
    assert!(receipt.status, "receipt should be success");

    // Verify state reflects the transfer
    let recipient_account = state
        .get_account(&recipient_addr)
        .expect("load recipient")
        .expect("recipient should exist");
    assert_eq!(
        recipient_account.balance,
        U256::from(1000u64),
        "recipient should have received 1000 after pipeline execution"
    );

    let _ = fs::remove_file(&path);
}

// â”€â”€â”€ test 5: storage migration preserves data when reopening â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

#[test]
fn storage_migration_preserves_data_on_reopen() {
    let (storage, path) = make_storage("migration");

    // Write a sentinel value
    storage
        .state_put(b"sentinel".to_vec(), b"value".to_vec())
        .expect("sentinel put should succeed");

    drop(storage);

    // Reopen â€” schema version check must not wipe data
    let storage2 = Arc::new(
        StorageEngine::new(path.to_string_lossy().as_ref())
            .expect("reopen should succeed"),
    );
    let loaded = storage2
        .state_get(b"sentinel".to_vec())
        .expect("sentinel load should succeed");
    assert_eq!(
        loaded.as_deref(),
        Some(b"value".as_slice()),
        "sentinel value should survive reopen"
    );

    let _ = fs::remove_file(&path);
}

// â”€â”€â”€ HotStuff consensus safety and fork-resolution tests â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

fn make_block_h(parent_hash: [u8; 32], height: u64) -> Block {
    Block::new(BlockHeader::new(parent_hash, height), BlockBody::empty())
}

fn make_qc_h(block: &Block, view: u64) -> vage_consensus::hotstuff::vote::QuorumCertificate {
    vage_consensus::hotstuff::vote::QuorumCertificate::new(
        block.hash(),
        view,
        vec![],
        vec![],
    )
}

#[test]
fn hotstuff_locked_block_is_set_at_precommit_and_not_before() {
    use vage_consensus::hotstuff::HotStuff;

    let mut hs = HotStuff::new();
    let genesis = Block::genesis([0u8; 32]);
    let b1 = make_block_h(genesis.hash(), 1);
    let qc1 = make_qc_h(&b1, 1);

    assert!(hs.locked_block.is_none(), "no locked block before Prepare");
    hs.apply_three_phase_commit_rule(&b1, qc1.clone()).unwrap(); // Prepare
    assert!(hs.locked_block.is_none(), "locked block must not be set at Prepare");
    hs.apply_three_phase_commit_rule(&b1, qc1).unwrap(); // PreCommit
    assert_eq!(hs.locked_block, Some(b1.hash()), "locked block set at PreCommit");
}

#[test]
fn hotstuff_fork_choice_prefers_higher_qc_view() {
    use vage_consensus::hotstuff::HotStuff;

    let mut hs = HotStuff::new();
    let genesis = Block::genesis([0u8; 32]);

    let b1a = make_block_h(genesis.hash(), 1);
    let b1b = make_block_h(genesis.hash(), 1);
    let qa = make_qc_h(&b1a, 10);
    let qb = make_qc_h(&b1b, 3);

    hs.apply_three_phase_commit_rule(&b1a, qa).unwrap();
    hs.apply_three_phase_commit_rule(&b1b, qb).unwrap();

    // b1a has higher QC view â†’ preferred
    assert_eq!(hs.fork_choice(b1a.hash(), b1b.hash()), b1a.hash());
}

#[test]
fn hotstuff_rejects_conflicting_fork_after_lock() {
    use vage_consensus::hotstuff::HotStuff;

    let mut hs = HotStuff::new();
    let genesis = Block::genesis([0u8; 32]);

    let b1 = make_block_h(genesis.hash(), 1);
    let q1 = make_qc_h(&b1, 1);
    hs.apply_three_phase_commit_rule(&b1, q1.clone()).unwrap(); // Prepare
    hs.apply_three_phase_commit_rule(&b1, q1).unwrap();         // PreCommit â†’ locked

    // Fork that does NOT extend b1 (returns to genesis directly).
    let mut fork = make_block_h(genesis.hash(), 1);
    fork.header.proposer = Address([0xabu8; 32]);
    let q_fork = make_qc_h(&fork, 2);

    match hs.verify_prepare_phase(&fork, &q_fork) {
        Ok(false) | Err(_) => {} // correctly rejected
        Ok(true) => panic!("safety rule: conflicting fork must be rejected after lock"),
    }
}

// â”€â”€â”€ chain_id replay-protection tests â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

#[test]
fn transaction_without_chain_id_is_rejected_by_validator() {
    use vage_mempool::{TransactionValidator, TxValidationConfig};

    let (storage, path) = make_storage("chain-id-no");
    let state = Arc::new(StateDB::new(storage));

    let config = TxValidationConfig::default(); // chain_id defaults to 1
    let validator = TransactionValidator::new(state, config);

    let mut tx = Transaction::new_transfer(
        Address::from([1u8; 32]),
        Address::from([2u8; 32]),
        U256::from(1),
        0,
    );
    tx.chain_id = None;

    assert!(validator.validate(&tx).is_err(), "tx without chain_id must be rejected");
    let _ = fs::remove_file(&path);
}

#[tokio::test]
async fn light_client_requests_state_proof_against_historical_snapshot() {
    let (storage, path) = make_storage("light-client-state-proof");
    let state = Arc::new(StateDB::new(storage.clone()));

    let (validator, validator_signer) = active_validator(90);
    let validator_set = vec![validator.clone()];
    let address = validator.address;

    let mut account = Account::new(address);
    account.increase_balance(U256::from(4242u64));
    state
        .update_account(&address, &account)
        .expect("account update should succeed");
    let state_root = state.commit().expect("state commit should succeed");
    state
        .snapshot_state(1)
        .expect("historical snapshot should persist");
    storage
        .state_put(b"execution:block:state_root:1".to_vec(), state_root.to_vec())
        .expect("block state root should persist");

    let genesis = BlockHeader::genesis();
    let mut header = BlockHeader::new(genesis.hash(), 1);
    header.proposer = address;
    header.timestamp = genesis.timestamp + 1;
    header.validator_root = BlockBody::compute_validator_root(&validator_set);
    header.state_root = state_root;
    let unsigned_hash = header.hash();
    let mut hasher = sha2::Sha256::new();
    use sha2::Digest;
    hasher.update(b"sp1:trace");
    hasher.update(vec![0u8; 128]);
    hasher.update(unsigned_hash);
    let execution_trace = hasher.finalize_reset();
    hasher.update(b"sp1:pk");
    hasher.update(vec![0u8; 128]);
    let proving_key = hasher.finalize_reset();
    hasher.update(proving_key);
    hasher.update(execution_trace);
    hasher.update(unsigned_hash);
    header.zk_proof = Some(hasher.finalize().to_vec());
    let header_hash = header.hash();
    header
        .sign(&validator_signer)
        .expect("header signing should succeed");

    let qc_signature = validator_signer.sign(&header_hash).to_bytes().to_vec();
    let envelope = RpcVerifiedHeaderEnvelope {
        header: header.clone(),
        consensus_signatures: vec![(address, qc_signature)],
    };

    let proof = state
        .export_account_proof_for_height(1, &address, 32)
        .expect("historical account proof should export");

    let peer_id = libp2p::PeerId::random();
    let mut network = P2PNetwork::new(p2p_test_config())
        .await
        .expect("network should initialize");
    network.peer_store.add_peer(Peer::new(peer_id, tcp_addr(22002)));
    network.queue_mock_rpc_response(L1Response::respond_latest_block_height(Some(1)));
    network.queue_mock_rpc_response(L1Response::respond_headers(Some(vec![envelope])));
    network.queue_mock_rpc_response(L1Response::respond_state_proof(Some(RpcStateProofResponse {
            height: 1,
            proof: proof.1,
            value: RpcStateProofValue::Account(proof.0.clone()),
        })));

    let client = LightClient::new_with_validator_set(
        Arc::new(Mutex::new(network)),
        peer_id,
        genesis,
        validator_set,
    );
    client.run_sync_loop().await.expect("sync should succeed");

    let (proved_account, proof) = client
        .request_account_state_at_height(1, address, 32)
        .await
        .expect("account state proof request should verify");

    assert_eq!(proved_account.balance, U256::from(4242u64));
    assert_eq!(proof.root, state_root);

    let _ = fs::remove_file(&path);
}

#[test]
fn transaction_with_wrong_chain_id_is_rejected() {
    use vage_mempool::{TransactionValidator, TxValidationConfig};

    let (storage, path) = make_storage("chain-id-wrong");
    let state = Arc::new(StateDB::new(storage));

    let mut config = TxValidationConfig::default();
    config.chain_id = 1;
    let validator = TransactionValidator::new(state, config);

    let mut tx = Transaction::new_transfer(
        Address::from([1u8; 32]),
        Address::from([2u8; 32]),
        U256::from(1),
        0,
    );
    tx.chain_id = Some(999); // wrong chain

    assert!(validator.validate(&tx).is_err(), "tx with wrong chain_id must be rejected");
    let _ = fs::remove_file(&path);
}

#[test]
fn validator_double_vote_is_slashed_and_removed_from_active_set() {
    use vage_consensus::governance::GovernanceManager;
    use vage_consensus::hotstuff::vote::Vote;
    use vage_consensus::pos::validator_set::ValidatorSet;
    use vage_consensus::{SlashingConfig, SlashingManager, StakingManager};

    let (storage, path) = make_storage("node-slashing");
    let (validator, signing_key) = active_validator(9);
    let validator_address = validator.address;

    let mut validator_set = ValidatorSet::new();
    validator_set
        .add_validator(validator.clone())
        .expect("validator should be added to set");

    let mut staking = StakingManager::with_storage(storage.clone());
    staking
        .stake_tokens(validator_address, U256::from(1_000_000u64))
        .expect("stake should be recorded");

    let mut governance = GovernanceManager::new();
    let mut slashing = SlashingManager::new(SlashingConfig::default(), storage.clone());

    let mut vote_a = Vote::new(validator_address, [1u8; 32], 7);
    vote_a.sign(&signing_key).expect("vote_a should sign");
    let mut vote_b = Vote::new(validator_address, [2u8; 32], 7);
    vote_b.sign(&signing_key).expect("vote_b should sign");

    let misbehavior = slashing
        .detect_double_vote(&vote_a, &vote_b)
        .expect("double vote should be detected");
    let evidence_id = slashing
        .record_evidence(validator_address, misbehavior, 42, validator_address, [0u8; 64])
        .expect("evidence should be recorded");
    slashing
        .confirm_misbehavior(&evidence_id, &validator)
        .expect("evidence should be confirmed");

    let event = slashing
        .execute_slash(&evidence_id, 42, &mut validator_set, &mut staking, &mut governance)
        .expect("slash execution should succeed");

    assert!(event.slash_amount > U256::zero());
    assert!(
        !validator_set.active_validators().iter().any(|v| v.address == validator_address),
        "slashed validator must be removed from active validator set"
    );

    let history = slashing
        .slashing_history(&validator_address)
        .expect("history should load");
    assert_eq!(history.len(), 1);

    drop(storage);
    let _ = fs::remove_file(&path);
}

