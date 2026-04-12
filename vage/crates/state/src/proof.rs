use crate::node::VerkleNode;
use crate::verkle_tree::VerkleTree;
use anyhow::{bail, Result};
use serde::{Deserialize, Serialize};
use vage_crypto::hash::domain_hash;
use vage_types::{Account, Address};

const DOMAIN_VERKLE_PROOF: &str = "VAGE_VERKLE_PROOF";

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct VerkleProof {
    pub commitments: Vec<[u8; 32]>,
    pub path: Vec<usize>,
    pub values: Vec<[u8; 32]>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct RpcVerkleProof {
    pub root: [u8; 32],
    pub commitments: Vec<[u8; 32]>,
    pub path: Vec<usize>,
    pub values: Vec<[u8; 32]>,
    pub minimal: bool,
}

impl VerkleProof {
    pub fn generate_proof(tree: &VerkleTree, key: [u8; 32]) -> Result<Self> {
        let path = tree.path_indices(key);
        let mut commitments = Vec::with_capacity(path.len() + 1);
        let mut values = Vec::with_capacity(path.len() + 1);
        let mut current = &tree.root;

        commitments.push(current.commitment());
        values.push(current.value.unwrap_or([0u8; 32]));

        for index in &path {
            current = current
                .child(*index)
                .ok_or_else(|| anyhow::anyhow!("missing node on proof path"))?;
            commitments.push(current.commitment());
            values.push(current.value.unwrap_or([0u8; 32]));
        }

        Ok(Self {
            commitments,
            path,
            values,
        })
    }

    pub fn verify_proof(&self, key: [u8; 32], value: [u8; 32], root: [u8; 32]) -> Result<bool> {
        self.validate_full_shape(key)?;

        if self.commitments[0] != root {
            return Ok(false);
        }

        if self.values.last().copied().unwrap_or([0u8; 32]) != value {
            return Ok(false);
        }

        if self.commitments.last().copied().unwrap_or([0u8; 32]) != Self::leaf_commitment(value) {
            return Ok(false);
        }

        let derived = self.proof_digest();
        Ok(derived != [0u8; 32])
    }

    pub fn generate_account_proof(tree: &VerkleTree, address: &Address) -> Result<Self> {
        Self::generate_proof(tree, *address.as_bytes())
    }

    pub fn generate_storage_proof(
        tree: &VerkleTree,
        address: &Address,
        key: [u8; 32],
    ) -> Result<Self> {
        let storage_key = storage_proof_key(address, &key);
        Self::generate_proof(tree, storage_key)
    }

    pub fn verify_account_proof(
        &self,
        address: &Address,
        account: &Account,
        root: [u8; 32],
    ) -> Result<bool> {
        self.verify_proof(*address.as_bytes(), account.hash(), root)
    }

    pub fn verify_storage_proof(
        &self,
        address: &Address,
        key: [u8; 32],
        value: [u8; 32],
        root: [u8; 32],
    ) -> Result<bool> {
        self.verify_proof(storage_proof_key(address, &key), value, root)
    }

    pub fn batch_proof_generation(tree: &VerkleTree, keys: &[[u8; 32]]) -> Result<Vec<Self>> {
        keys.iter()
            .map(|key| Self::generate_proof(tree, *key))
            .collect()
    }

    pub fn generate_minimal_proof(tree: &VerkleTree, key: [u8; 32]) -> Result<Self> {
        let full = Self::generate_proof(tree, key)?;
        let minimal_commitments = full
            .commitments
            .first()
            .copied()
            .into_iter()
            .chain(full.commitments.last().copied())
            .collect();
        let minimal_values = full.values.last().copied().into_iter().collect();

        Ok(Self {
            commitments: minimal_commitments,
            path: full.path,
            values: minimal_values,
        })
    }

    pub fn export_for_rpc(&self, root: [u8; 32]) -> RpcVerkleProof {
        RpcVerkleProof {
            root,
            commitments: self.commitments.clone(),
            path: self.path.clone(),
            values: self.values.clone(),
            minimal: false,
        }
    }

    pub fn export_minimal_for_rpc(&self, root: [u8; 32]) -> RpcVerkleProof {
        RpcVerkleProof {
            root,
            commitments: self
                .commitments
                .first()
                .copied()
                .into_iter()
                .chain(self.commitments.last().copied())
                .collect(),
            path: self.path.clone(),
            values: self.values.last().copied().into_iter().collect(),
            minimal: true,
        }
    }

    pub fn verify_for_light_client(
        rpc_proof: &RpcVerkleProof,
        key: [u8; 32],
        value: [u8; 32],
    ) -> Result<bool> {
        if rpc_proof.minimal {
            Self::verify_minimal_rpc_proof(rpc_proof, key, value)
        } else {
            let full_like = VerkleProof {
                commitments: rpc_proof.commitments.clone(),
                path: rpc_proof.path.clone(),
                values: rpc_proof.values.clone(),
            };
            full_like.verify_proof(key, value, rpc_proof.root)
        }
    }

    pub fn verify(
        &self,
        root_hash: [u8; 32],
        keys: &[[u8; 32]],
        values: &[[u8; 32]],
    ) -> Result<bool> {
        if keys.len() != 1 || values.len() != 1 {
            bail!("current proof verifier expects a single key/value pair");
        }

        self.verify_proof(keys[0], values[0], root_hash)
    }

    fn proof_digest(&self) -> [u8; 32] {
        let mut bytes = Vec::with_capacity(self.commitments.len() * 32 + self.values.len() * 32);
        for commitment in &self.commitments {
            bytes.extend_from_slice(commitment);
        }
        for index in &self.path {
            bytes.push(*index as u8);
        }
        for value in &self.values {
            bytes.extend_from_slice(value);
        }
        domain_hash(DOMAIN_VERKLE_PROOF, &bytes)
    }

    fn validate_full_shape(&self, key: [u8; 32]) -> Result<()> {
        if self.commitments.is_empty() {
            bail!("proof commitments cannot be empty");
        }

        if self.values.len() != self.commitments.len() {
            bail!("proof values length must match commitments length");
        }

        let expected_path: Vec<usize> = key.iter().map(|byte| *byte as usize).collect();
        if self.path != expected_path {
            bail!("proof path does not match key bytes");
        }

        if self.commitments.len() != self.path.len() + 1 {
            bail!("proof commitments length must be path length plus one");
        }

        Ok(())
    }

    fn verify_minimal_rpc_proof(
        rpc_proof: &RpcVerkleProof,
        key: [u8; 32],
        value: [u8; 32],
    ) -> Result<bool> {
        if rpc_proof.commitments.len() != 2 {
            bail!("minimal rpc proof must contain exactly root and leaf commitments");
        }

        if rpc_proof.values.len() != 1 {
            bail!("minimal rpc proof must contain exactly one leaf value");
        }

        let expected_path: Vec<usize> = key.iter().map(|byte| *byte as usize).collect();
        if rpc_proof.path != expected_path {
            return Ok(false);
        }

        if rpc_proof.root != rpc_proof.commitments[0] {
            return Ok(false);
        }

        if rpc_proof.values[0] != value {
            return Ok(false);
        }

        Ok(rpc_proof.commitments[1] == Self::leaf_commitment(value))
    }

    fn leaf_commitment(value: [u8; 32]) -> [u8; 32] {
        VerkleNode::new_leaf([0u8; 32], value).commitment()
    }
}

impl VerkleTree {
    pub fn generate_proof(&self, key: [u8; 32]) -> Result<VerkleProof> {
        VerkleProof::generate_proof(self, key)
    }

    pub fn batch_proof_generation(&self, keys: &[[u8; 32]]) -> Result<Vec<VerkleProof>> {
        VerkleProof::batch_proof_generation(self, keys)
    }

    pub fn generate_minimal_proof(&self, key: [u8; 32]) -> Result<VerkleProof> {
        VerkleProof::generate_minimal_proof(self, key)
    }
}

pub fn storage_proof_key(address: &Address, key: &[u8; 32]) -> [u8; 32] {
    let mut combined = [0u8; 32];
    for (index, byte) in address.as_bytes().iter().enumerate() {
        combined[index] ^= *byte;
    }
    for (index, byte) in key.iter().enumerate() {
        combined[index] ^= *byte;
    }
    combined
}

#[cfg(test)]
mod tests {
    use super::{storage_proof_key, RpcVerkleProof, VerkleProof};
    use crate::verkle_tree::VerkleTree;
    use vage_types::{Account, Address};

    fn hash(byte: u8) -> [u8; 32] {
        [byte; 32]
    }

    #[test]
    fn generate_and_verify_basic_proof() {
        let mut tree = VerkleTree::new();
        let key = hash(1);
        let value = hash(2);
        tree.insert(key, value).expect("tree insert should succeed");

        let proof =
            VerkleProof::generate_proof(&tree, key).expect("proof generation should succeed");

        assert_eq!(proof.path, tree.path_indices(key));
        assert_eq!(
            proof.commitments.first().copied(),
            Some(tree.root_commitment())
        );
        assert_eq!(proof.values.last().copied(), Some(value));
        assert!(proof
            .verify_proof(key, value, tree.root_commitment())
            .expect("proof verification should succeed"));
        assert!(!proof
            .verify_proof(key, hash(9), tree.root_commitment())
            .expect("mismatched value check should succeed"));
    }

    #[test]
    fn account_and_storage_proof_helpers_round_trip() {
        let mut tree = VerkleTree::new();
        let address = Address(hash(3));
        let account = Account::new(address);
        let account_hash = account.hash();
        tree.insert(*address.as_bytes(), account_hash)
            .expect("account insert should succeed");

        let account_proof = VerkleProof::generate_account_proof(&tree, &address)
            .expect("account proof generation should succeed");
        assert!(account_proof
            .verify_account_proof(&address, &account, tree.root_commitment())
            .expect("account proof verification should succeed"));

        let storage_slot = hash(4);
        let storage_value = hash(5);
        let proof_key = storage_proof_key(&address, &storage_slot);
        tree.insert(proof_key, storage_value)
            .expect("storage insert should succeed");

        let storage_proof = VerkleProof::generate_storage_proof(&tree, &address, storage_slot)
            .expect("storage proof generation should succeed");
        assert!(storage_proof
            .verify_storage_proof(
                &address,
                storage_slot,
                storage_value,
                tree.root_commitment()
            )
            .expect("storage proof verification should succeed"));
    }

    #[test]
    fn batch_proof_generation_returns_all_requested_proofs() {
        let mut tree = VerkleTree::new();
        let keys = vec![hash(6), hash(7), hash(8)];

        for (index, key) in keys.iter().enumerate() {
            tree.insert(*key, hash(index as u8 + 10))
                .expect("tree insert should succeed");
        }

        let proofs = VerkleProof::batch_proof_generation(&tree, &keys)
            .expect("batch proof generation should succeed");

        assert_eq!(proofs.len(), keys.len());
        for (index, proof) in proofs.iter().enumerate() {
            assert!(proof
                .verify_proof(keys[index], hash(index as u8 + 10), tree.root_commitment())
                .expect("proof verification should succeed"));
        }
    }

    #[test]
    fn verify_proof_rejects_invalid_shape() {
        let proof = VerkleProof {
            commitments: vec![[1u8; 32]],
            path: vec![1, 2, 3],
            values: vec![],
        };

        assert!(proof.verify_proof(hash(1), hash(2), hash(3)).is_err());
    }

    #[test]
    fn minimal_proof_exports_and_verifies_for_light_clients() {
        let mut tree = VerkleTree::new();
        let key = hash(11);
        let value = hash(12);
        tree.insert(key, value).expect("tree insert should succeed");

        let proof = VerkleProof::generate_minimal_proof(&tree, key)
            .expect("minimal proof generation should succeed");
        let rpc = proof.export_minimal_for_rpc(tree.root_commitment());

        assert!(VerkleProof::verify_for_light_client(&rpc, key, value)
            .expect("minimal rpc proof verification should succeed"));
        assert!(!VerkleProof::verify_for_light_client(&rpc, key, hash(99))
            .expect("minimal rpc proof mismatch check should succeed"));
    }

    #[test]
    fn minimal_rpc_proof_rejects_invalid_shape() {
        let rpc = RpcVerkleProof {
            root: hash(1),
            commitments: vec![hash(1)],
            path: vec![1; 32],
            values: vec![hash(2)],
            minimal: true,
        };

        assert!(VerkleProof::verify_for_light_client(&rpc, hash(1), hash(2)).is_err());
    }
}
