use crate::node::VerkleNode;
use crate::proof::{storage_proof_key, RpcVerkleProof, VerkleProof};
use crate::verkle_tree::VerkleTree;
use anyhow::{bail, Result};
use parking_lot::Mutex;
use primitive_types::U256;
use vage_block::Block;
use vage_crypto::hash::sha256;
use vage_storage::StorageEngine;
use vage_types::{Account, Address, Transaction};
use std::collections::{BTreeSet, HashMap};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

const ACCOUNT_PREFIX: &[u8] = b"account:";
const STORAGE_PREFIX: &[u8] = b"storage:";
const STATE_ROOT_KEY: &[u8] = b"metadata:state_root";
const SNAPSHOT_META_PREFIX: &[u8] = b"snapshot:meta:";
const SNAPSHOT_FULL_PREFIX: &[u8] = b"snapshot:full:";
const SNAPSHOT_INCREMENTAL_PREFIX: &[u8] = b"snapshot:incremental:";
const SNAPSHOT_ROOT_SUFFIX: &[u8] = b":root";
const SNAPSHOT_TREE_SUFFIX: &[u8] = b":tree";
const SNAPSHOT_BASE_SUFFIX: &[u8] = b":base";
const SNAPSHOT_TYPE_SUFFIX: &[u8] = b":type";
const SNAPSHOT_KEY_PREFIX: &[u8] = b":key:";
const SNAPSHOT_TOMBSTONE: &[u8] = b"__deleted__";
const SNAPSHOT_RETAIN_COUNT: usize = 8;
pub const MAX_VERKLE_PROOF_DEPTH: usize = 32;

#[derive(Clone, Debug)]
pub struct ReadOnlyStateSnapshot {
    pub root: [u8; 32],
    pub revision: u64,
}

#[derive(Clone, Debug)]
pub enum StateBatchOp {
    Put(Vec<u8>, Vec<u8>),
    Delete(Vec<u8>),
}

pub struct StateDb {
    storage: Arc<StorageEngine>,
    tree: Mutex<VerkleTree>,
    committed_tree: Mutex<VerkleTree>,
    committed_state: Mutex<HashMap<Vec<u8>, Vec<u8>>>,
    dirty_keys: Mutex<BTreeSet<Vec<u8>>>,
    key_versions: Mutex<HashMap<Vec<u8>, u64>>,
    node_cache: Mutex<HashMap<[u8; 32], VerkleNode>>,
    revision: AtomicU64,
}

impl StateDb {
    pub fn new(storage: Arc<StorageEngine>) -> Self {
        let tree = VerkleTree::new();
        let committed_state = Self::capture_committed_state(&storage).unwrap_or_default();
        Self {
            storage,
            tree: Mutex::new(tree.clone()),
            committed_tree: Mutex::new(tree),
            committed_state: Mutex::new(committed_state),
            dirty_keys: Mutex::new(BTreeSet::new()),
            key_versions: Mutex::new(HashMap::new()),
            node_cache: Mutex::new(HashMap::new()),
            revision: AtomicU64::new(0),
        }
    }

    pub fn storage(&self) -> Arc<StorageEngine> {
        Arc::clone(&self.storage)
    }

    pub fn get_account(&self, address: &Address) -> Result<Option<Account>> {
        self.load_account(address)
    }

    pub fn get_balance(&self, address: &Address) -> Result<U256> {
        Ok(self
            .load_account(address)?
            .map(|account| account.balance)
            .unwrap_or_else(U256::zero))
    }

    pub fn get_nonce(&self, address: &Address) -> Result<u64> {
        Ok(self
            .load_account(address)?
            .map(|account| account.nonce)
            .unwrap_or(0))
    }

    pub fn get_storage(&self, address: &Address, key: [u8; 32]) -> Result<Option<[u8; 32]>> {
        let storage_key = Self::storage_key(address, &key);
        match self.storage.state_get(storage_key)? {
            Some(bytes) if bytes.len() == 32 => {
                let mut value = [0u8; 32];
                value.copy_from_slice(&bytes);
                Ok(Some(value))
            }
            Some(bytes) => {
                let mut value = [0u8; 32];
                let copy_len = bytes.len().min(value.len());
                value[..copy_len].copy_from_slice(&bytes[..copy_len]);
                Ok(Some(value))
            }
            None => Ok(None),
        }
    }

    pub fn account_exists(&self, address: &Address) -> Result<bool> {
        Ok(self.load_account(address)?.is_some())
    }

    pub fn load_account(&self, address: &Address) -> Result<Option<Account>> {
        let key = Self::account_key(address);
        if let Some(bytes) = self.storage.state_get(key)? {
            let account: Account = serde_json::from_slice(&bytes)?;
            return Ok(Some(account));
        }
        Ok(None)
    }

    pub fn update_account(&self, address: &Address, account: &Account) -> Result<()> {
        let key = Self::account_key(address);
        let bytes = serde_json::to_vec(account)?;
        self.storage.state_put(key.clone(), bytes)?;
        self.mark_dirty(key.clone());
        self.bump_key_version(key);

        let mut tree = self.tree.lock();
        let account_hash = account.hash();
        if tree.get(*address.as_bytes())?.is_some() {
            tree.update(*address.as_bytes(), account_hash)?;
        } else {
            tree.insert(*address.as_bytes(), account_hash)?;
        }

        Ok(())
    }

    pub fn create_account(&self, address: Address) -> Result<Account> {
        if let Some(account) = self.load_account(&address)? {
            return Ok(account);
        }

        let account = Account::new(address);
        self.update_account(&address, &account)?;
        Ok(account)
    }

    pub fn set_balance(&self, address: &Address, amount: U256) -> Result<()> {
        let mut account = self
            .load_account(address)?
            .unwrap_or_else(|| Account::new(*address));
        account.balance = amount;
        self.update_account(address, &account)
    }

    pub fn increment_nonce(&self, address: &Address) -> Result<u64> {
        let mut account = self
            .load_account(address)?
            .unwrap_or_else(|| Account::new(*address));
        account.increment_nonce();
        let nonce = account.nonce;
        self.update_account(address, &account)?;
        Ok(nonce)
    }

    pub fn set_storage(&self, address: &Address, key: [u8; 32], value: [u8; 32]) -> Result<()> {
        let storage_key = Self::storage_key(address, &key);
        self.storage
            .state_put(storage_key.clone(), value.to_vec())?;
        self.mark_dirty(storage_key);
        self.bump_key_version(Self::storage_key(address, &key));

        let tree_key = storage_proof_key(address, &key);
        let mut tree = self.tree.lock();
        if tree.get(tree_key)?.is_some() {
            tree.update(tree_key, value)?;
        } else {
            tree.insert(tree_key, value)?;
        }
        drop(tree);

        let mut account = self
            .load_account(address)?
            .unwrap_or_else(|| Account::new(*address));
        let mut storage_root_material = Vec::with_capacity(96);
        storage_root_material.extend_from_slice(address.as_bytes());
        storage_root_material.extend_from_slice(&key);
        storage_root_material.extend_from_slice(&value);
        account.set_storage_root(sha256(&storage_root_material));
        self.update_account(address, &account)
    }

    pub fn delete_account(&self, address: &Address) -> Result<()> {
        let account_key = Self::account_key(address);
        self.storage
            .atomic_state_commit(vec![(account_key.clone(), None)])?;
        self.mark_dirty(account_key);
        self.bump_key_version(Self::account_key(address));

        let mut tree = self.tree.lock();
        if tree.get(*address.as_bytes())?.is_some() {
            tree.delete(*address.as_bytes())?;
        }

        Ok(())
    }

    pub fn apply_transaction(&self, tx: &Transaction) -> Result<()> {
        self.state_transition(tx).map(|_| ())
    }

    pub fn apply_block(&self, block: &Block) -> Result<[u8; 32]> {
        block.validate_basic()?;

        for tx in &block.body.transactions {
            self.apply_transaction(tx)?;
        }

        self.update_state_root()
    }

    pub fn state_transition(&self, transaction: &Transaction) -> Result<[u8; 32]> {
        transaction.validate_basic()?;

        let mut sender = self
            .load_account(&transaction.from)?
            .unwrap_or_else(|| Account::new(transaction.from));
        self.validate_state_transition_checks(transaction, &sender)?;

        let gas_cost = self.deduct_gas(&mut sender, transaction)?;
        sender.decrease_balance(transaction.value)?;
        sender.increment_nonce();
        sender.validate()?;
        self.update_account(&transaction.from, &sender)?;

        if let Some(recipient_address) = transaction.to {
            let mut recipient = self
                .load_account(&recipient_address)?
                .unwrap_or_else(|| Account::new(recipient_address));

            if transaction.is_contract_call() {
                self.apply_contract_storage_update(
                    &recipient_address,
                    &transaction.data,
                    transaction.hash(),
                )?;
                recipient = self
                    .load_account(&recipient_address)?
                    .unwrap_or_else(|| Account::new(recipient_address));
            }

            self.apply_balance_update(&mut recipient, transaction.value)?;

            recipient.validate()?;
            self.update_account(&recipient_address, &recipient)?;
        } else {
            let contract_address = Address::from(sha256(&transaction.hash()));
            let mut contract = self
                .load_account(&contract_address)?
                .unwrap_or_else(|| Account::new(contract_address));
            self.apply_balance_update(&mut contract, transaction.value)?;
            contract.apply_contract_deploy(sha256(&transaction.data));
            contract.validate()?;
            self.update_account(&contract_address, &contract)?;
        }

        let _ = gas_cost;
        self.update_state_root()
    }

    /// Read an arbitrary key-value pair from state storage by raw key bytes.
    pub fn get_raw(&self, key: &[u8]) -> Result<Option<Vec<u8>>> {
        self.storage.state_get(key.to_vec())
    }

    /// Write an arbitrary key-value pair to state storage by raw key bytes.
    pub fn set_raw(&self, key: &[u8], value: Vec<u8>) -> Result<()> {
        self.storage.state_put(key.to_vec(), value)?;
        self.mark_dirty(key.to_vec());
        Ok(())
    }

    pub fn get_node(&self, hash: [u8; 32]) -> Result<Option<VerkleNode>> {
        self.lazy_load_node(hash)
    }

    pub fn put_node(&self, hash: [u8; 32], node: &VerkleNode) -> Result<()> {
        self.store_node(hash, node)
    }

    pub fn load_node_from_storage(&self, hash: [u8; 32]) -> Result<Option<VerkleNode>> {
        if let Some(bytes) = self.storage.load_verkle_node(hash)? {
            let node = VerkleNode::deserialize(&bytes)?;
            self.node_cache.lock().insert(hash, node.clone());
            return Ok(Some(node));
        }
        Ok(None)
    }

    pub fn store_node(&self, hash: [u8; 32], node: &VerkleNode) -> Result<()> {
        self.storage.store_verkle_node(hash, node.serialize())?;
        self.node_cache.lock().insert(hash, node.clone());
        Ok(())
    }

    pub fn batch_node_writes(&self, nodes: &Vec<([u8; 32], VerkleNode)>) -> Result<()> {
        let encoded_nodes: Vec<([u8; 32], Vec<u8>)> = nodes
            .iter()
            .map(|(hash, node)| (*hash, node.serialize()))
            .collect();
        self.storage.batch_store_verkle_nodes(&encoded_nodes)?;

        let mut cache = self.node_cache.lock();
        for (hash, node) in nodes {
            cache.insert(*hash, node.clone());
        }
        Ok(())
    }

    pub fn lazy_load_node(&self, hash: [u8; 32]) -> Result<Option<VerkleNode>> {
        if let Some(node) = self.node_cache.lock().get(&hash).cloned() {
            return Ok(Some(node));
        }

        self.load_node_from_storage(hash)
    }

    pub fn tree_root(&self) -> [u8; 32] {
        self.tree.lock().root_commitment()
    }

    pub fn state_root(&self) -> [u8; 32] {
        self.tree_root()
    }

    pub fn initialize_backend(
        &self,
        latest_height: u64,
        expected_root: Option<[u8; 32]>,
    ) -> Result<[u8; 32]> {
        let restored_root = if latest_height > 0
            && self
                .storage
                .state_get(Self::snapshot_type_key(latest_height))?
                .is_some()
        {
            self.load_snapshot(latest_height)?
        } else {
            self.rebuild_tree_from_storage()?
        };

        if let Some(expected_root) = expected_root {
            if restored_root != expected_root {
                bail!(
                    "restored state root mismatch: expected 0x{}, got 0x{}",
                    hex::encode(expected_root),
                    hex::encode(restored_root)
                );
            }
        }

        Ok(restored_root)
    }

    pub fn update_state_root(&self) -> Result<[u8; 32]> {
        let root = self.tree_root();
        self.storage
            .state_put(STATE_ROOT_KEY.to_vec(), root.to_vec())?;
        Ok(root)
    }

    pub fn verify_state_root(&self, root: [u8; 32]) -> Result<bool> {
        let in_memory_root = self.state_root();
        if in_memory_root != root {
            return Ok(false);
        }

        match self.storage.state_get(STATE_ROOT_KEY.to_vec())? {
            Some(bytes) if bytes.len() == 32 => {
                let mut persisted = [0u8; 32];
                persisted.copy_from_slice(&bytes);
                Ok(persisted == root)
            }
            Some(_) => Ok(false),
            None => Ok(root == [0u8; 32]),
        }
    }

    pub fn commit(&self) -> Result<[u8; 32]> {
        let root = self.update_state_root()?;
        let snapshot = self.tree.lock().clone();
        *self.committed_tree.lock() = snapshot;
        *self.committed_state.lock() = self.capture_current_state()?;
        self.storage.flush_to_disk()?;
        Ok(root)
    }

    pub fn rollback(&self) -> Result<[u8; 32]> {
        let committed = self.committed_tree.lock().clone();
        let root = committed.root_commitment();
        self.restore_committed_state()?;
        *self.tree.lock() = committed;
        self.storage
            .state_put(STATE_ROOT_KEY.to_vec(), root.to_vec())?;
        self.dirty_keys.lock().clear();
        Ok(root)
    }

    pub fn generate_account_proof(&self, address: &Address) -> Result<VerkleProof> {
        let tree = self.tree.lock();
        VerkleProof::generate_account_proof(&tree, address)
    }

    pub fn export_account_proof_for_rpc(&self, address: &Address) -> Result<RpcVerkleProof> {
        let proof = self.generate_account_proof(address)?;
        Ok(proof.export_for_rpc(self.state_root()))
    }

    pub fn export_account_proof_for_height(
        &self,
        height: u64,
        address: &Address,
        max_depth: usize,
    ) -> Result<(Account, RpcVerkleProof)> {
        self.ensure_supported_proof_depth(max_depth)?;
        let (tree, entries, root) = self.rebuild_tree_for_height(height)?;
        let key = Self::account_key(address);
        let value = entries
            .get(&key)
            .ok_or_else(|| anyhow::anyhow!("account {} not found at height {}", address, height))?;
        let account: Account = serde_json::from_slice(value)?;
        let proof = VerkleProof::generate_account_proof(&tree, address)?;
        self.ensure_proof_depth(&proof, max_depth)?;
        Ok((account, proof.export_for_rpc(root)))
    }

    pub fn generate_storage_proof(&self, address: &Address, key: [u8; 32]) -> Result<VerkleProof> {
        let tree = self.tree.lock();
        VerkleProof::generate_storage_proof(&tree, address, key)
    }

    pub fn export_storage_proof_for_rpc(
        &self,
        address: &Address,
        key: [u8; 32],
    ) -> Result<RpcVerkleProof> {
        let proof = self.generate_storage_proof(address, key)?;
        Ok(proof.export_for_rpc(self.state_root()))
    }

    pub fn export_storage_proof_for_height(
        &self,
        height: u64,
        address: &Address,
        key: [u8; 32],
        max_depth: usize,
    ) -> Result<([u8; 32], RpcVerkleProof)> {
        self.ensure_supported_proof_depth(max_depth)?;
        let (tree, entries, root) = self.rebuild_tree_for_height(height)?;
        let storage_key = Self::storage_key(address, &key);
        let raw_value = entries
            .get(&storage_key)
            .ok_or_else(|| anyhow::anyhow!("storage key not found at height {}", height))?;
        let mut value = [0u8; 32];
        let copy_len = raw_value.len().min(value.len());
        value[..copy_len].copy_from_slice(&raw_value[..copy_len]);
        let proof = VerkleProof::generate_storage_proof(&tree, address, key)?;
        self.ensure_proof_depth(&proof, max_depth)?;
        Ok((value, proof.export_for_rpc(root)))
    }

    pub fn generate_minimal_proof(&self, key: [u8; 32]) -> Result<VerkleProof> {
        let tree = self.tree.lock();
        tree.generate_minimal_proof(key)
    }

    pub fn export_minimal_proof_for_rpc(&self, key: [u8; 32]) -> Result<RpcVerkleProof> {
        let proof = self.generate_minimal_proof(key)?;
        Ok(proof.export_minimal_for_rpc(self.state_root()))
    }

    pub fn export_minimal_proof_for_height(
        &self,
        height: u64,
        key: [u8; 32],
        max_depth: usize,
    ) -> Result<([u8; 32], RpcVerkleProof)> {
        self.ensure_supported_proof_depth(max_depth)?;
        let (tree, _, root) = self.rebuild_tree_for_height(height)?;
        let proof = VerkleProof::generate_minimal_proof(&tree, key)?;
        self.ensure_proof_depth(&proof, max_depth)?;
        let value = proof.values.last().copied().unwrap_or([0u8; 32]);
        Ok((value, proof.export_minimal_for_rpc(root)))
    }

    pub fn verify_account_proof(&self, proof: &VerkleProof, address: &Address) -> Result<bool> {
        let account = match self.load_account(address)? {
            Some(account) => account,
            None => return Ok(false),
        };
        proof.verify_account_proof(address, &account, self.state_root())
    }

    pub fn verify_storage_proof(
        &self,
        proof: &VerkleProof,
        address: &Address,
        key: [u8; 32],
    ) -> Result<bool> {
        let value = match self.get_storage(address, key)? {
            Some(value) => value,
            None => return Ok(false),
        };
        proof.verify_storage_proof(address, key, value, self.state_root())
    }

    pub fn batch_proof_generation(&self, keys: &[[u8; 32]]) -> Result<Vec<VerkleProof>> {
        let tree = self.tree.lock();
        tree.batch_proof_generation(keys)
    }

    pub fn begin_read_only_snapshot(&self) -> ReadOnlyStateSnapshot {
        ReadOnlyStateSnapshot {
            root: self.state_root(),
            revision: self.revision.load(Ordering::SeqCst),
        }
    }

    pub fn parallel_state_reads(&self, keys: &[Vec<u8>]) -> Result<Vec<Option<Vec<u8>>>> {
        self.storage.parallel_state_reads(keys)
    }

    pub fn write_batch(&self, operations: Vec<StateBatchOp>) -> Result<()> {
        let mut changes = Vec::with_capacity(operations.len());
        for operation in operations {
            match operation {
                StateBatchOp::Put(key, value) => changes.push((key, Some(value))),
                StateBatchOp::Delete(key) => changes.push((key, None)),
            }
        }

        self.storage.atomic_state_commit(changes.clone())?;
        for (key, _) in changes {
            self.mark_dirty(key.clone());
            self.bump_key_version(key);
        }

        Ok(())
    }

    pub fn detect_conflicts(
        &self,
        snapshot: &ReadOnlyStateSnapshot,
        keys: &[Vec<u8>],
    ) -> Result<bool> {
        if snapshot.root != self.state_root() {
            return Ok(true);
        }

        let key_versions = self.key_versions.lock();
        Ok(keys
            .iter()
            .any(|key| key_versions.get(key).copied().unwrap_or(0) > snapshot.revision))
    }

    pub fn snapshot_state(&self, height: u64) -> Result<[u8; 32]> {
        let root = self.state_root();
        let committed_tree = self.tree.lock().clone();
        let dirty_keys: Vec<Vec<u8>> = self.dirty_keys.lock().iter().cloned().collect();
        let has_previous_snapshot = height > 0
            && self
                .storage
                .state_get(Self::snapshot_type_key(height - 1))?
                .is_some();

        if height == 0 || dirty_keys.is_empty() || !has_previous_snapshot {
            self.write_full_snapshot(height, &committed_tree, root)?;
        } else {
            self.write_incremental_snapshot(height, root, &dirty_keys)?;
        }

        *self.committed_tree.lock() = committed_tree;
        self.dirty_keys.lock().clear();
        Ok(root)
    }

    pub fn load_snapshot(&self, height: u64) -> Result<[u8; 32]> {
        let mut chain = self.snapshot_chain(height)?;
        if chain.is_empty() {
            bail!("snapshot at height {} not found", height);
        }

        let base_height = chain.remove(0);
        let _tree_bytes = self
            .storage
            .state_get(Self::snapshot_tree_key(base_height))?
            .ok_or_else(|| anyhow::anyhow!("missing tree data for snapshot {}", base_height))?;
        self.apply_full_snapshot(base_height)?;

        for snapshot_height in chain {
            self.apply_incremental_snapshot(snapshot_height)?;
        }

        let expected_root = self
            .read_snapshot_root(height)?
            .ok_or_else(|| anyhow::anyhow!("missing snapshot root for height {}", height))?;
        let restored_root = self.rebuild_tree_from_storage()?;
        if restored_root != expected_root {
            bail!(
                "restored snapshot root mismatch at height {}: expected 0x{}, got 0x{}",
                height,
                hex::encode(expected_root),
                hex::encode(restored_root)
            );
        }

        self.dirty_keys.lock().clear();
        Ok(restored_root)
    }

    pub fn prune_old_state(&self) -> Result<usize> {
        self.prune_state_versions(SNAPSHOT_RETAIN_COUNT)
    }

    pub fn prune_state_versions(&self, retain_count: usize) -> Result<usize> {
        let entries = self.storage.state_prefix_scan(b"snapshot:".to_vec())?;
        let mut heights: BTreeSet<u64> = BTreeSet::new();

        for (key, _) in &entries {
            if let Some(height) = Self::parse_snapshot_height(key) {
                heights.insert(height);
            }
        }

        if heights.len() <= retain_count {
            return Ok(0);
        }

        let removable: Vec<u64> = heights
            .iter()
            .copied()
            .take(heights.len() - retain_count)
            .collect();

        let mut changes = Vec::new();
        for (key, _) in entries {
            if let Some(height) = Self::parse_snapshot_height(&key) {
                if removable.contains(&height) && !Self::is_snapshot_root_key(&key) {
                    changes.push((key, None));
                }
            }
        }

        let pruned = changes.len();
        if pruned > 0 {
            self.storage.atomic_state_commit(changes)?;
        }
        Ok(pruned)
    }

    fn account_key(address: &Address) -> Vec<u8> {
        let mut key = Vec::with_capacity(ACCOUNT_PREFIX.len() + address.as_bytes().len());
        key.extend_from_slice(ACCOUNT_PREFIX);
        key.extend_from_slice(address.as_bytes());
        key
    }

    fn storage_key(address: &Address, key: &[u8; 32]) -> Vec<u8> {
        let mut storage_key =
            Vec::with_capacity(STORAGE_PREFIX.len() + address.as_bytes().len() + key.len());
        storage_key.extend_from_slice(STORAGE_PREFIX);
        storage_key.extend_from_slice(address.as_bytes());
        storage_key.extend_from_slice(key);
        storage_key
    }

    fn mark_dirty(&self, key: Vec<u8>) {
        self.dirty_keys.lock().insert(key);
    }

    fn bump_key_version(&self, key: Vec<u8>) {
        let version = self.revision.fetch_add(1, Ordering::SeqCst) + 1;
        self.key_versions.lock().insert(key, version);
    }

    fn deduct_gas(&self, sender: &mut Account, transaction: &Transaction) -> Result<U256> {
        let gas_cost = transaction.gas_cost();
        sender.decrease_balance(gas_cost)?;
        Ok(gas_cost)
    }

    fn apply_balance_update(&self, account: &mut Account, amount: U256) -> Result<()> {
        account.increase_balance(amount);
        account.validate()
    }

    fn apply_contract_storage_update(
        &self,
        contract: &Address,
        data: &[u8],
        value: [u8; 32],
    ) -> Result<()> {
        let storage_key = sha256(data);
        self.set_storage(contract, storage_key, value)
    }

    fn validate_state_transition_checks(
        &self,
        transaction: &Transaction,
        sender: &Account,
    ) -> Result<()> {
        if sender.nonce != transaction.nonce {
            bail!(
                "nonce mismatch for {}: expected {}, got {}",
                transaction.from,
                sender.nonce,
                transaction.nonce
            );
        }

        let total_cost = transaction.value.saturating_add(transaction.gas_cost());
        if sender.balance < total_cost {
            bail!(
                "insufficient balance for {}: need {}, have {}",
                transaction.from,
                total_cost,
                sender.balance
            );
        }

        if transaction.is_contract_call() {
            if let Some(recipient) = transaction.to {
                let contract = self
                    .load_account(&recipient)?
                    .unwrap_or_else(|| Account::new(recipient));
                if !contract.is_contract() && !transaction.data.is_empty() {
                    bail!(
                        "contract storage update requires contract account at {}",
                        recipient
                    );
                }
            }
        }

        sender.validate()
    }

    fn rebuild_tree_from_storage(&self) -> Result<[u8; 32]> {
        let mut rebuilt_tree = VerkleTree::new();

        for (key, value) in self.storage.state_prefix_scan(ACCOUNT_PREFIX.to_vec())? {
            let Some(address_bytes) = key.strip_prefix(ACCOUNT_PREFIX) else {
                continue;
            };
            if address_bytes.len() != 32 {
                continue;
            }

            let account: Account = serde_json::from_slice(&value)?;
            let mut address = [0u8; 32];
            address.copy_from_slice(address_bytes);
            rebuilt_tree.insert(address, account.hash())?;
        }

        for (key, value) in self.storage.state_prefix_scan(STORAGE_PREFIX.to_vec())? {
            let Some(storage_key) = key.strip_prefix(STORAGE_PREFIX) else {
                continue;
            };
            if storage_key.len() != 64 {
                continue;
            }

            let mut address_bytes = [0u8; 32];
            address_bytes.copy_from_slice(&storage_key[..32]);
            let address = Address::from(address_bytes);

            let mut slot = [0u8; 32];
            slot.copy_from_slice(&storage_key[32..]);

            let mut slot_value = [0u8; 32];
            let copy_len = value.len().min(slot_value.len());
            slot_value[..copy_len].copy_from_slice(&value[..copy_len]);

            let proof_key = storage_proof_key(&address, &slot);
            rebuilt_tree.insert(proof_key, slot_value)?;
        }

        let restored_root = rebuilt_tree.root_commitment();
        *self.tree.lock() = rebuilt_tree.clone();
        *self.committed_tree.lock() = rebuilt_tree;
        *self.committed_state.lock() = self.capture_current_state()?;
        self.node_cache.lock().clear();
        self.dirty_keys.lock().clear();
        self.storage
            .state_put(STATE_ROOT_KEY.to_vec(), restored_root.to_vec())?;
        Ok(restored_root)
    }

    fn capture_current_state(&self) -> Result<HashMap<Vec<u8>, Vec<u8>>> {
        Self::capture_committed_state(&self.storage)
    }

    fn capture_committed_state(storage: &StorageEngine) -> Result<HashMap<Vec<u8>, Vec<u8>>> {
        let mut entries = HashMap::new();

        for (key, value) in storage.state_prefix_scan(ACCOUNT_PREFIX.to_vec())? {
            entries.insert(key, value);
        }

        for (key, value) in storage.state_prefix_scan(STORAGE_PREFIX.to_vec())? {
            entries.insert(key, value);
        }

        if let Some(root) = storage.state_get(STATE_ROOT_KEY.to_vec())? {
            entries.insert(STATE_ROOT_KEY.to_vec(), root);
        }

        Ok(entries)
    }

    fn restore_committed_state(&self) -> Result<()> {
        let committed = self.committed_state.lock().clone();
        let current = self.capture_current_state()?;
        let mut changes = Vec::new();

        for (key, value) in &committed {
            if current.get(key) != Some(value) {
                changes.push((key.clone(), Some(value.clone())));
            }
        }

        for key in current.keys() {
            if !committed.contains_key(key) {
                changes.push((key.clone(), None));
            }
        }

        if !changes.is_empty() {
            self.storage.atomic_state_commit(changes)?;
        }

        Ok(())
    }

    fn write_full_snapshot(&self, height: u64, tree: &VerkleTree, root: [u8; 32]) -> Result<()> {
        let mut changes = vec![
            (Self::snapshot_type_key(height), Some(b"full".to_vec())),
            (Self::snapshot_root_key(height), Some(root.to_vec())),
            (Self::snapshot_tree_key(height), Some(tree.root.serialize())),
        ];

        for (key, value) in self.storage.state_prefix_scan(ACCOUNT_PREFIX.to_vec())? {
            changes.push((
                Self::snapshot_state_entry_key(SNAPSHOT_FULL_PREFIX, height, &key),
                Some(value),
            ));
        }

        for (key, value) in self.storage.state_prefix_scan(STORAGE_PREFIX.to_vec())? {
            changes.push((
                Self::snapshot_state_entry_key(SNAPSHOT_FULL_PREFIX, height, &key),
                Some(value),
            ));
        }

        self.storage.atomic_state_commit(changes)
    }

    fn apply_full_snapshot(&self, height: u64) -> Result<()> {
        let prefix = Self::snapshot_prefix_for_height(SNAPSHOT_FULL_PREFIX, height);
        let entries = self.storage.state_prefix_scan(prefix)?;
        let mut changes = Vec::new();

        for (snapshot_key, value) in entries {
            if let Some(original_key) = Self::decode_snapshot_state_entry_key(&snapshot_key) {
                changes.push((original_key, Some(value)));
            }
        }

        if !changes.is_empty() {
            self.storage.atomic_state_commit(changes)?;
        }

        Ok(())
    }

    fn write_incremental_snapshot(
        &self,
        height: u64,
        root: [u8; 32],
        dirty_keys: &[Vec<u8>],
    ) -> Result<()> {
        let base_height = height.saturating_sub(1);
        let mut changes = vec![
            (
                Self::snapshot_type_key(height),
                Some(b"incremental".to_vec()),
            ),
            (Self::snapshot_root_key(height), Some(root.to_vec())),
            (
                Self::snapshot_base_key(height),
                Some(base_height.to_le_bytes().to_vec()),
            ),
        ];

        for key in dirty_keys {
            let value = match self.storage.state_get(key.clone())? {
                Some(value) => Some(value),
                None => Some(SNAPSHOT_TOMBSTONE.to_vec()),
            };
            changes.push((
                Self::snapshot_state_entry_key(SNAPSHOT_INCREMENTAL_PREFIX, height, key),
                value,
            ));
        }

        self.storage.atomic_state_commit(changes)
    }

    fn apply_incremental_snapshot(&self, height: u64) -> Result<()> {
        let prefix = Self::snapshot_prefix_for_height(SNAPSHOT_INCREMENTAL_PREFIX, height);
        let entries = self.storage.state_prefix_scan(prefix)?;
        let mut changes = Vec::new();

        for (snapshot_key, value) in entries {
            if let Some(original_key) = Self::decode_snapshot_state_entry_key(&snapshot_key) {
                if value == SNAPSHOT_TOMBSTONE {
                    changes.push((original_key, None));
                } else {
                    changes.push((original_key, Some(value)));
                }
            }
        }

        if !changes.is_empty() {
            self.storage.atomic_state_commit(changes)?;
        }

        Ok(())
    }

    fn snapshot_chain(&self, mut height: u64) -> Result<Vec<u64>> {
        let mut chain = Vec::new();

        loop {
            let snapshot_type = self
                .storage
                .state_get(Self::snapshot_type_key(height))?
                .ok_or_else(|| anyhow::anyhow!("snapshot {} not found", height))?;
            chain.push(height);

            if snapshot_type == b"full" {
                break;
            }

            let base_bytes = self
                .storage
                .state_get(Self::snapshot_base_key(height))?
                .ok_or_else(|| anyhow::anyhow!("incremental snapshot {} missing base", height))?;
            if base_bytes.len() != 8 {
                bail!("invalid base pointer for snapshot {}", height);
            }

            let mut array = [0u8; 8];
            array.copy_from_slice(&base_bytes);
            height = u64::from_le_bytes(array);
        }

        chain.reverse();
        Ok(chain)
    }

    fn read_snapshot_root(&self, height: u64) -> Result<Option<[u8; 32]>> {
        match self.storage.state_get(Self::snapshot_root_key(height))? {
            Some(bytes) if bytes.len() == 32 => {
                let mut root = [0u8; 32];
                root.copy_from_slice(&bytes);
                Ok(Some(root))
            }
            Some(_) => Ok(None),
            None => Ok(None),
        }
    }

    fn snapshot_prefix_for_height(prefix: &[u8], height: u64) -> Vec<u8> {
        let mut key = Vec::with_capacity(prefix.len() + 20);
        key.extend_from_slice(prefix);
        key.extend_from_slice(height.to_string().as_bytes());
        key
    }

    fn snapshot_root_key(height: u64) -> Vec<u8> {
        let mut key = Self::snapshot_prefix_for_height(SNAPSHOT_META_PREFIX, height);
        key.extend_from_slice(SNAPSHOT_ROOT_SUFFIX);
        key
    }

    fn is_snapshot_root_key(key: &[u8]) -> bool {
        key.starts_with(SNAPSHOT_META_PREFIX) && key.ends_with(SNAPSHOT_ROOT_SUFFIX)
    }

    fn snapshot_tree_key(height: u64) -> Vec<u8> {
        let mut key = Self::snapshot_prefix_for_height(SNAPSHOT_META_PREFIX, height);
        key.extend_from_slice(SNAPSHOT_TREE_SUFFIX);
        key
    }

    fn snapshot_base_key(height: u64) -> Vec<u8> {
        let mut key = Self::snapshot_prefix_for_height(SNAPSHOT_META_PREFIX, height);
        key.extend_from_slice(SNAPSHOT_BASE_SUFFIX);
        key
    }

    fn snapshot_type_key(height: u64) -> Vec<u8> {
        let mut key = Self::snapshot_prefix_for_height(SNAPSHOT_META_PREFIX, height);
        key.extend_from_slice(SNAPSHOT_TYPE_SUFFIX);
        key
    }

    fn snapshot_state_entry_key(prefix: &[u8], height: u64, original_key: &[u8]) -> Vec<u8> {
        let mut snapshot_key = Self::snapshot_prefix_for_height(prefix, height);
        snapshot_key.extend_from_slice(SNAPSHOT_KEY_PREFIX);
        snapshot_key.extend_from_slice(original_key);
        snapshot_key
    }

    fn decode_snapshot_state_entry_key(snapshot_key: &[u8]) -> Option<Vec<u8>> {
        let marker = snapshot_key
            .windows(SNAPSHOT_KEY_PREFIX.len())
            .position(|window| window == SNAPSHOT_KEY_PREFIX)?;
        Some(snapshot_key[marker + SNAPSHOT_KEY_PREFIX.len()..].to_vec())
    }

    fn rebuild_tree_for_height(
        &self,
        height: u64,
    ) -> Result<(VerkleTree, HashMap<Vec<u8>, Vec<u8>>, [u8; 32])> {
        let root = self
            .read_snapshot_root(height)?
            .ok_or_else(|| anyhow::anyhow!("missing snapshot root for height {}", height))?;
        let entries = self.snapshot_entries(height)?;
        let tree = Self::build_tree_from_entries(&entries)?;
        if tree.root_commitment() != root {
            bail!(
                "historical snapshot root mismatch at height {}: expected 0x{}, got 0x{}",
                height,
                hex::encode(root),
                hex::encode(tree.root_commitment())
            );
        }
        Ok((tree, entries, root))
    }

    fn snapshot_entries(&self, height: u64) -> Result<HashMap<Vec<u8>, Vec<u8>>> {
        let mut chain = self.snapshot_chain(height)?;
        if chain.is_empty() {
            bail!("snapshot at height {} not found", height);
        }

        let base_height = chain.remove(0);
        let mut entries = HashMap::new();
        let full_prefix = Self::snapshot_prefix_for_height(SNAPSHOT_FULL_PREFIX, base_height);
        for (snapshot_key, value) in self.storage.state_prefix_scan(full_prefix)? {
            if let Some(original_key) = Self::decode_snapshot_state_entry_key(&snapshot_key) {
                entries.insert(original_key, value);
            }
        }

        for snapshot_height in chain {
            let prefix = Self::snapshot_prefix_for_height(SNAPSHOT_INCREMENTAL_PREFIX, snapshot_height);
            for (snapshot_key, value) in self.storage.state_prefix_scan(prefix)? {
                if let Some(original_key) = Self::decode_snapshot_state_entry_key(&snapshot_key) {
                    if value == SNAPSHOT_TOMBSTONE {
                        entries.remove(&original_key);
                    } else {
                        entries.insert(original_key, value);
                    }
                }
            }
        }

        Ok(entries)
    }

    fn build_tree_from_entries(entries: &HashMap<Vec<u8>, Vec<u8>>) -> Result<VerkleTree> {
        let mut rebuilt_tree = VerkleTree::new();

        for (key, value) in entries {
            if let Some(address_bytes) = key.strip_prefix(ACCOUNT_PREFIX) {
                if address_bytes.len() != 32 {
                    continue;
                }
                let account: Account = serde_json::from_slice(value)?;
                let mut address = [0u8; 32];
                address.copy_from_slice(address_bytes);
                rebuilt_tree.insert(address, account.hash())?;
                continue;
            }

            if let Some(storage_key) = key.strip_prefix(STORAGE_PREFIX) {
                if storage_key.len() != 64 {
                    continue;
                }
                let mut address_bytes = [0u8; 32];
                address_bytes.copy_from_slice(&storage_key[..32]);
                let address = Address::from(address_bytes);

                let mut slot = [0u8; 32];
                slot.copy_from_slice(&storage_key[32..]);

                let mut slot_value = [0u8; 32];
                let copy_len = value.len().min(slot_value.len());
                slot_value[..copy_len].copy_from_slice(&value[..copy_len]);

                rebuilt_tree.insert(storage_proof_key(&address, &slot), slot_value)?;
            }
        }

        Ok(rebuilt_tree)
    }

    fn ensure_supported_proof_depth(&self, max_depth: usize) -> Result<()> {
        if max_depth > MAX_VERKLE_PROOF_DEPTH {
            bail!(
                "requested proof depth {} exceeds maximum tree depth {}",
                max_depth,
                MAX_VERKLE_PROOF_DEPTH
            );
        }
        Ok(())
    }

    fn ensure_proof_depth(&self, proof: &VerkleProof, max_depth: usize) -> Result<()> {
        if proof.path.len() > max_depth {
            bail!(
                "proof depth {} exceeds requested max_depth {}",
                proof.path.len(),
                max_depth
            );
        }
        Ok(())
    }

    fn parse_snapshot_height(key: &[u8]) -> Option<u64> {
        for prefix in [
            SNAPSHOT_META_PREFIX,
            SNAPSHOT_FULL_PREFIX,
            SNAPSHOT_INCREMENTAL_PREFIX,
        ] {
            if let Some(rest) = key.strip_prefix(prefix) {
                let height_bytes: Vec<u8> = rest
                    .iter()
                    .copied()
                    .take_while(|byte| byte.is_ascii_digit())
                    .collect();
                if height_bytes.is_empty() {
                    return None;
                }
                let height_str = String::from_utf8(height_bytes).ok()?;
                return height_str.parse::<u64>().ok();
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::{StateBatchOp, StateDb};
    use primitive_types::U256;
    use vage_block::{Block, BlockBody, BlockHeader};
    use vage_crypto::hash::sha256;
    use vage_storage::{Schema, StorageEngine};
    use vage_types::{Account, Address, Receipt, Transaction};
    use std::path::PathBuf;
    use std::sync::Arc;
    use std::time::{SystemTime, UNIX_EPOCH};

    use crate::{VerkleNode, verkle_tree::VerkleTree};

    fn temp_db_path(name: &str) -> PathBuf {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time should be after unix epoch")
            .as_nanos();
        std::env::temp_dir().join(format!("vage-state-{name}-{unique}.redb"))
    }

    fn test_db(name: &str) -> (Arc<StorageEngine>, StateDb, PathBuf) {
        let db_path = temp_db_path(name);
        Schema::init(&db_path).expect("schema should initialize");
        let storage = Arc::new(StorageEngine::new(&db_path).expect("storage should initialize"));
        let state = StateDb::new(storage.clone());
        (storage, state, db_path)
    }

    fn cleanup(storage: Arc<StorageEngine>, path: PathBuf) {
        drop(storage);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn new_initializes_state_db_with_empty_tree() {
        let (storage, state, path) = test_db("new");

        assert_eq!(state.state_root(), VerkleTree::new().root_commitment());
        assert_eq!(state.get_balance(&Address([1u8; 32])).expect("balance read should succeed"), U256::zero());
        assert_eq!(state.get_nonce(&Address([1u8; 32])).expect("nonce read should succeed"), 0);

        cleanup(storage, path);
    }

    #[test]
    fn account_reads_return_persisted_account_data() {
        let (storage, state, path) = test_db("account-reads");
        let address = Address([2u8; 32]);
        let mut account = Account::new(address);
        account.balance = U256::from(55u64);
        account.nonce = 7;

        state
            .update_account(&address, &account)
            .expect("account update should succeed");

        assert_eq!(state.load_account(&address).expect("load account should succeed"), Some(account.clone()));
        assert_eq!(state.get_account(&address).expect("get account should succeed"), Some(account.clone()));
        assert_eq!(state.get_balance(&address).expect("get balance should succeed"), U256::from(55u64));
        assert_eq!(state.get_nonce(&address).expect("get nonce should succeed"), 7);
        assert!(state.account_exists(&address).expect("existence check should succeed"));

        cleanup(storage, path);
    }

    #[test]
    fn missing_account_reads_fall_back_to_empty_values() {
        let (storage, state, path) = test_db("missing-account");
        let address = Address([3u8; 32]);

        assert_eq!(state.load_account(&address).expect("load account should succeed"), None);
        assert_eq!(state.get_account(&address).expect("get account should succeed"), None);
        assert_eq!(state.get_balance(&address).expect("get balance should succeed"), U256::zero());
        assert_eq!(state.get_nonce(&address).expect("get nonce should succeed"), 0);
        assert!(!state.account_exists(&address).expect("existence check should succeed"));

        cleanup(storage, path);
    }

    #[test]
    fn storage_reads_return_written_values_and_none_when_absent() {
        let (storage, state, path) = test_db("storage-reads");
        let address = Address([4u8; 32]);
        let storage_key = [5u8; 32];
        let storage_value = [6u8; 32];

        assert_eq!(
            state
                .get_storage(&address, storage_key)
                .expect("missing storage read should succeed"),
            None
        );

        state
            .set_storage(&address, storage_key, storage_value)
            .expect("storage write should succeed");

        assert_eq!(
            state
                .get_storage(&address, storage_key)
                .expect("storage read should succeed"),
            Some(storage_value)
        );

        cleanup(storage, path);
    }

    #[test]
    fn create_account_set_balance_and_increment_nonce_work() {
        let (storage, state, path) = test_db("account-writes");
        let address = Address([7u8; 32]);

        let created = state
            .create_account(address)
            .expect("account creation should succeed");
        assert_eq!(created.address, address);
        assert!(state.account_exists(&address).expect("existence check should succeed"));

        state
            .set_balance(&address, U256::from(99u64))
            .expect("balance update should succeed");
        assert_eq!(state.get_balance(&address).expect("balance read should succeed"), U256::from(99u64));

        let nonce = state
            .increment_nonce(&address)
            .expect("nonce increment should succeed");
        assert_eq!(nonce, 1);
        assert_eq!(state.get_nonce(&address).expect("nonce read should succeed"), 1);

        cleanup(storage, path);
    }

    #[test]
    fn set_storage_updates_slot_and_account_storage_root() {
        let (storage, state, path) = test_db("set-storage");
        let address = Address([8u8; 32]);
        let slot = [9u8; 32];
        let value = [10u8; 32];

        state
            .set_storage(&address, slot, value)
            .expect("storage write should succeed");

        let account = state
            .load_account(&address)
            .expect("account load should succeed")
            .expect("account should exist after storage write");

        assert_eq!(state.get_storage(&address, slot).expect("storage read should succeed"), Some(value));
        assert_ne!(account.storage_root, [0u8; 32]);

        cleanup(storage, path);
    }

    #[test]
    fn delete_account_removes_persisted_state() {
        let (storage, state, path) = test_db("delete-account");
        let address = Address([11u8; 32]);

        state
            .create_account(address)
            .expect("account creation should succeed");
        state
            .delete_account(&address)
            .expect("account deletion should succeed");

        assert!(!state.account_exists(&address).expect("existence check should succeed"));
        assert_eq!(state.get_account(&address).expect("account read should succeed"), None);

        cleanup(storage, path);
    }

    #[test]
    fn apply_transaction_transfers_balance_and_updates_nonce() {
        let (storage, state, path) = test_db("apply-transaction");
        let from = Address([12u8; 32]);
        let to = Address([13u8; 32]);
        let mut sender = Account::new(from);
        sender.balance = U256::from(100_000u64);
        state
            .update_account(&from, &sender)
            .expect("sender update should succeed");

        let tx = Transaction::new_transfer(from, to, U256::from(500u64), 0);
        let gas_cost = tx.gas_cost();
        state
            .apply_transaction(&tx)
            .expect("transaction application should succeed");

        assert_eq!(
            state.get_balance(&from).expect("sender balance read should succeed"),
            U256::from(100_000u64) - U256::from(500u64) - gas_cost
        );
        assert_eq!(state.get_nonce(&from).expect("sender nonce read should succeed"), 1);
        assert_eq!(state.get_balance(&to).expect("recipient balance read should succeed"), U256::from(500u64));

        cleanup(storage, path);
    }

    #[test]
    fn apply_block_processes_transactions_and_updates_state_root() {
        let (storage, state, path) = test_db("apply-block");
        let from = Address([14u8; 32]);
        let to = Address([15u8; 32]);
        let mut sender = Account::new(from);
        sender.balance = U256::from(200_000u64);
        state
            .update_account(&from, &sender)
            .expect("sender update should succeed");

        let tx = Transaction::new_transfer(from, to, U256::from(750u64), 0);
        let receipt = Receipt::new_success(tx.hash(), tx.gas_limit, None);
        let mut body = BlockBody::new();
        body.add_transaction(tx.clone());
        body.add_receipt(receipt);

        let mut header = BlockHeader::new([1u8; 32], 1);
        header.set_state_root(state.state_root());
        let mut block = Block::new(header, body);
        block.compute_roots();

        let resulting_root = state.apply_block(&block).expect("block application should succeed");

        assert_eq!(resulting_root, state.state_root());
        assert_eq!(state.get_nonce(&from).expect("sender nonce read should succeed"), 1);
        assert_eq!(state.get_balance(&to).expect("recipient balance read should succeed"), U256::from(750u64));

        cleanup(storage, path);
    }

    #[test]
    fn state_root_update_and_verify_round_trip() {
        let (storage, state, path) = test_db("state-root");
        let address = Address([16u8; 32]);

        state
            .set_balance(&address, U256::from(42u64))
            .expect("balance update should succeed");
        let root = state
            .update_state_root()
            .expect("state root update should succeed");

        assert_eq!(root, state.state_root());
        assert!(state
            .verify_state_root(root)
            .expect("state root verification should succeed"));
        assert!(!state
            .verify_state_root([0u8; 32])
            .expect("mismatched root verification should succeed"));

        cleanup(storage, path);
    }

    #[test]
    fn commit_persists_snapshot_and_rollback_restores_it() {
        let (_storage, state, _path) = test_db("commit-rollback");
        let address = Address([17u8; 32]);

        state
            .set_balance(&address, U256::from(100u64))
            .expect("initial balance update should succeed");
        let committed_root = state.commit().expect("commit should succeed");
        assert_eq!(committed_root, state.state_root());

        state
            .set_balance(&address, U256::from(250u64))
            .expect("second balance update should succeed");
        let updated_root = state.state_root();
        assert_ne!(updated_root, committed_root);

        let rolled_back_root = state.rollback().expect("rollback should succeed");

        assert_eq!(rolled_back_root, committed_root);
        assert_eq!(state.state_root(), committed_root);
        assert!(state
            .verify_state_root(committed_root)
            .expect("rolled back root verification should succeed"));
        assert_eq!(state.get_balance(&address).expect("balance read should succeed"), U256::from(100u64));
    }

    #[test]
    fn snapshot_state_writes_full_then_incremental_snapshots() {
        let (storage, state, path) = test_db("snapshots");
        let address = Address([18u8; 32]);

        state
            .set_balance(&address, U256::from(10u64))
            .expect("initial balance update should succeed");
        let full_root = state
            .snapshot_state(0)
            .expect("full snapshot should succeed");

        let snapshot_type_zero = storage
            .state_get(b"snapshot:meta:0:type".to_vec())
            .expect("snapshot type read should succeed")
            .expect("snapshot type should exist");
        assert_eq!(snapshot_type_zero, b"full".to_vec());

        state
            .set_balance(&address, U256::from(25u64))
            .expect("second balance update should succeed");
        let incremental_root = state
            .snapshot_state(1)
            .expect("incremental snapshot should succeed");

        let snapshot_type_one = storage
            .state_get(b"snapshot:meta:1:type".to_vec())
            .expect("snapshot type read should succeed")
            .expect("incremental snapshot type should exist");
        assert_eq!(snapshot_type_one, b"incremental".to_vec());
        assert_ne!(full_root, incremental_root);

        cleanup(storage, path);
    }

    #[test]
    fn load_snapshot_restores_historical_state() {
        let (storage, state, path) = test_db("load-snapshot");
        let address = Address([19u8; 32]);

        state
            .set_balance(&address, U256::from(50u64))
            .expect("initial balance update should succeed");
        let root_zero = state
            .snapshot_state(0)
            .expect("snapshot zero should succeed");

        state
            .set_balance(&address, U256::from(75u64))
            .expect("second balance update should succeed");
        let root_one = state
            .snapshot_state(1)
            .expect("snapshot one should succeed");

        assert_eq!(state.get_balance(&address).expect("balance read should succeed"), U256::from(75u64));

        let restored_zero = state
            .load_snapshot(0)
            .expect("loading first snapshot should succeed");
        assert_eq!(restored_zero, root_zero);
        assert_eq!(state.state_root(), root_zero);
        assert_eq!(state.get_balance(&address).expect("balance read should succeed"), U256::from(50u64));

        let restored_one = state
            .load_snapshot(1)
            .expect("loading second snapshot should succeed");
        assert_eq!(restored_one, root_one);
        assert_eq!(state.state_root(), root_one);
        assert_eq!(state.get_balance(&address).expect("balance read should succeed"), U256::from(75u64));

        cleanup(storage, path);
    }

    #[test]
    fn prune_old_state_removes_snapshots_beyond_retention_window() {
        let (storage, state, path) = test_db("prune-snapshots");
        let address = Address([20u8; 32]);

        for height in 0..10u64 {
            state
                .set_balance(&address, U256::from(height + 1))
                .expect("balance update should succeed");
            state
                .snapshot_state(height)
                .expect("snapshot creation should succeed");
        }

        let pruned = state.prune_old_state().expect("snapshot pruning should succeed");
        assert!(pruned > 0);

        assert!(storage
            .state_get(b"snapshot:meta:0:type".to_vec())
            .expect("snapshot lookup should succeed")
            .is_none());
        assert!(storage
            .state_get(b"snapshot:meta:9:type".to_vec())
            .expect("latest snapshot lookup should succeed")
            .is_some());

        cleanup(storage, path);
    }

    #[test]
    fn read_only_snapshot_captures_root_and_revision() {
        let (_storage, state, _path) = test_db("read-only-snapshot");
        let address = Address([21u8; 32]);
        let initial = state.begin_read_only_snapshot();

        state
            .set_balance(&address, U256::from(5u64))
            .expect("balance update should succeed");
        let updated = state.begin_read_only_snapshot();

        assert_eq!(initial.root, VerkleTree::new().root_commitment());
        assert!(updated.revision > initial.revision);
        assert_ne!(updated.root, initial.root);
    }

    #[test]
    fn parallel_state_reads_return_values_in_key_order() {
        let (storage, state, path) = test_db("parallel-reads");
        let first_key = b"custom:key:1".to_vec();
        let second_key = b"custom:key:2".to_vec();

        state
            .write_batch(vec![
                StateBatchOp::Put(first_key.clone(), b"one".to_vec()),
                StateBatchOp::Put(second_key.clone(), b"two".to_vec()),
            ])
            .expect("write batch should succeed");

        let values = state
            .parallel_state_reads(&[first_key.clone(), b"missing".to_vec(), second_key.clone()])
            .expect("parallel reads should succeed");

        assert_eq!(values, vec![Some(b"one".to_vec()), None, Some(b"two".to_vec())]);

        cleanup(storage, path);
    }

    #[test]
    fn write_batch_applies_puts_and_deletes() {
        let (storage, state, path) = test_db("write-batch");
        let key = b"batch:key".to_vec();
        let other_key = b"batch:other".to_vec();

        state
            .write_batch(vec![
                StateBatchOp::Put(key.clone(), b"value".to_vec()),
                StateBatchOp::Put(other_key.clone(), b"other".to_vec()),
            ])
            .expect("initial batch should succeed");
        state
            .write_batch(vec![StateBatchOp::Delete(other_key.clone())])
            .expect("delete batch should succeed");

        assert_eq!(
            storage
                .state_get(key)
                .expect("state read should succeed"),
            Some(b"value".to_vec())
        );
        assert_eq!(
            storage
                .state_get(other_key)
                .expect("state read should succeed"),
            None
        );

        cleanup(storage, path);
    }

    #[test]
    fn conflict_detection_uses_root_and_key_versions() {
        let (storage, state, path) = test_db("conflict-detection");
        let watched_key = b"watched:key".to_vec();
        let untouched_key = b"untouched:key".to_vec();

        let snapshot = state.begin_read_only_snapshot();
        assert!(!state
            .detect_conflicts(&snapshot, std::slice::from_ref(&watched_key))
            .expect("conflict detection should succeed"));

        state
            .write_batch(vec![StateBatchOp::Put(watched_key.clone(), b"value".to_vec())])
            .expect("write batch should succeed");
        assert!(state
            .detect_conflicts(&snapshot, std::slice::from_ref(&watched_key))
            .expect("conflict detection should succeed"));

        let fresh_snapshot = state.begin_read_only_snapshot();
        assert!(!state
            .detect_conflicts(&fresh_snapshot, std::slice::from_ref(&untouched_key))
            .expect("conflict detection should succeed"));

        state
            .set_balance(&Address([22u8; 32]), U256::from(1u64))
            .expect("balance update should succeed");
        assert!(state
            .detect_conflicts(&fresh_snapshot, std::slice::from_ref(&untouched_key))
            .expect("conflict detection should succeed"));

        cleanup(storage, path);
    }

    #[test]
    fn store_and_load_verkle_node_round_trip() {
        let (storage, state, path) = test_db("node-store-load");
        let hash = [23u8; 32];
        let mut node = VerkleNode::new_internal(0);
        node.set_child(1, VerkleNode::new_internal(1))
            .expect("set_child should succeed");

        state
            .store_node(hash, &node)
            .expect("node store should succeed");

        let loaded = state
            .load_node_from_storage(hash)
            .expect("node load should succeed")
            .expect("node should exist in storage");

        assert_eq!(loaded.commitment(), node.commitment());
        assert_eq!(loaded.children_count(), node.children_count());

        cleanup(storage, path);
    }

    #[test]
    fn batch_node_writes_persist_all_nodes() {
        let (storage, state, path) = test_db("batch-node-writes");
        let first_hash = [24u8; 32];
        let second_hash = [25u8; 32];
        let first_node = VerkleNode::new_internal(0);
        let mut second_node = VerkleNode::new_internal(0);
        second_node.set_child(2, VerkleNode::new_internal(1))
            .expect("set_child should succeed");

        state
            .batch_node_writes(&vec![
                (first_hash, first_node.clone()),
                (second_hash, second_node.clone()),
            ])
            .expect("batch node write should succeed");

        assert!(state
            .load_node_from_storage(first_hash)
            .expect("first node load should succeed")
            .is_some());
        let loaded_second = state
            .load_node_from_storage(second_hash)
            .expect("second node load should succeed")
            .expect("second node should exist");
        assert_eq!(loaded_second.commitment(), second_node.commitment());

        cleanup(storage, path);
    }

    #[test]
    fn lazy_load_node_uses_cache_after_storage_fetch() {
        let (storage, state, path) = test_db("lazy-node-load");
        let hash = [26u8; 32];
        let mut node = VerkleNode::new_internal(0);
        node.set_child(3, VerkleNode::new_internal(1))
            .expect("set_child should succeed");

        storage
            .store_verkle_node(hash, node.serialize())
            .expect("raw node store should succeed");

        let first = state
            .lazy_load_node(hash)
            .expect("initial lazy load should succeed")
            .expect("node should load from storage");
        let second = state
            .lazy_load_node(hash)
            .expect("cached lazy load should succeed")
            .expect("node should load from cache");

        assert_eq!(first.commitment(), node.commitment());
        assert_eq!(second.commitment(), node.commitment());
        assert!(state
            .lazy_load_node([27u8; 32])
            .expect("missing lazy load should succeed")
            .is_none());

        cleanup(storage, path);
    }

    #[test]
    fn state_transition_deducts_gas_and_updates_balances() {
        let (storage, state, path) = test_db("state-transition-transfer");
        let from = Address([28u8; 32]);
        let to = Address([29u8; 32]);
        let mut sender = Account::new(from);
        sender.balance = U256::from(100_000u64);
        state
            .update_account(&from, &sender)
            .expect("sender update should succeed");

        let tx = Transaction::new_transfer(from, to, U256::from(1_000u64), 0);
        let gas_cost = tx.gas_cost();
        let root = state
            .state_transition(&tx)
            .expect("state transition should succeed");

        assert_eq!(root, state.state_root());
        assert_eq!(
            state.get_balance(&from).expect("sender balance read should succeed"),
            U256::from(100_000u64) - U256::from(1_000u64) - gas_cost
        );
        assert_eq!(state.get_nonce(&from).expect("sender nonce read should succeed"), 1);
        assert_eq!(state.get_balance(&to).expect("recipient balance read should succeed"), U256::from(1_000u64));

        cleanup(storage, path);
    }

    #[test]
    fn state_transition_updates_contract_storage_for_contract_calls() {
        let (storage, state, path) = test_db("state-transition-contract-call");
        let from = Address([30u8; 32]);
        let contract = Address([31u8; 32]);

        let mut sender = Account::new(from);
        sender.balance = U256::from(200_000u64);
        state
            .update_account(&from, &sender)
            .expect("sender update should succeed");

        let mut contract_account = Account::new(contract);
        contract_account.apply_contract_deploy([1u8; 32]);
        state
            .update_account(&contract, &contract_account)
            .expect("contract account update should succeed");

        let data = vec![1u8, 2, 3, 4];
        let tx = Transaction::new_contract_call(from, contract, U256::from(500u64), 0, data.clone());
        let expected_storage_key = sha256(&data);
        let expected_storage_value = tx.hash();

        state
            .state_transition(&tx)
            .expect("contract call state transition should succeed");

        assert_eq!(
            state
                .get_storage(&contract, expected_storage_key)
                .expect("storage read should succeed"),
            Some(expected_storage_value)
        );
        assert_eq!(state.get_balance(&contract).expect("contract balance read should succeed"), U256::from(500u64));

        cleanup(storage, path);
    }

    #[test]
    fn state_transition_rejects_nonce_and_balance_violations() {
        let (storage, state, path) = test_db("state-transition-validation");
        let from = Address([32u8; 32]);
        let to = Address([33u8; 32]);

        let mut sender = Account::new(from);
        sender.balance = U256::from(500u64);
        sender.nonce = 3;
        state
            .update_account(&from, &sender)
            .expect("sender update should succeed");

        let wrong_nonce_tx = Transaction::new_transfer(from, to, U256::from(1u64), 0);
        assert!(state.state_transition(&wrong_nonce_tx).is_err());

        let insufficient_balance_tx = Transaction::new_transfer(from, to, U256::from(10_000u64), 3);
        assert!(state.state_transition(&insufficient_balance_tx).is_err());

        cleanup(storage, path);
    }
}
