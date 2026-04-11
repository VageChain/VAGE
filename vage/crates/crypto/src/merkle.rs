use vage_types::Hash;
use anyhow::{Result, bail};
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct MerkleTree {
    pub leaves: Vec<Hash>,
    pub layers: Vec<Vec<Hash>>,
}

impl MerkleTree {
    /// Create a new Merkle tree from a set of leaf hashes.
    pub fn new(leaves: Vec<Hash>) -> Self {
        let mut tree = Self {
            leaves,
            layers: Vec::new(),
        };
        tree.build_layers();
        tree
    }

    /// Return the number of leaves in the tree.
    pub fn leaf_count(&self) -> usize {
        self.leaves.len()
    }

    /// Returns true if the tree has no leaves.
    pub fn is_empty(&self) -> bool {
        self.leaves.is_empty()
    }

    /// Return the root hash of the Merkle tree.
    pub fn root(&self) -> Hash {
        if self.layers.is_empty() {
            return Self::empty_root();
        }
        self.layers.last().unwrap()[0]
    }

    /// Return the hash of an empty tree.
    pub fn empty_root() -> Hash {
        [0u8; 32]
    }

    /// Append a new leaf and rebuild the tree layers.
    pub fn append_leaf(&mut self, hash: Hash) {
        self.leaves.push(hash);
        self.build_layers();
    }

    /// Hash a pair of child nodes to produce a parent node.
    pub fn hash_pair(left: &Hash, right: &Hash) -> Hash {
        let mut h = [0u8; 32];
        Self::hash_pair_into(left, right, &mut h);
        h
    }

    /// Hash a pair of child nodes into a caller-provided output buffer.
    pub fn hash_pair_into(left: &Hash, right: &Hash, out: &mut Hash) {
        let mut hasher = Sha256::new();
        hasher.update(left);
        hasher.update(right);
        let result = hasher.finalize();
        out.copy_from_slice(&result);
    }

    /// Optimized build_layers to minimize clones and re-use buffers where possible.
    pub fn build_layers(&mut self) {
        if self.leaves.is_empty() {
            self.layers = Vec::new();
            return;
        }

        let depth = (self.leaves.len() as f64).log2().ceil() as usize + 1;
        let mut layers = Vec::with_capacity(depth);
        let mut current_layer = self.leaves.clone();
        let mut scratch = Vec::new();

        loop {
            layers.push(current_layer.clone());
            if current_layer.len() == 1 {
                break;
            }

            Self::build_next_layer_into(&current_layer, &mut scratch);
            std::mem::swap(&mut current_layer, &mut scratch);
        }

        self.layers = layers;
    }

    /// Build multiple Merkle trees in parallel from batches of leaf hashes.
    pub fn batch_build(batches: Vec<Vec<Hash>>) -> Vec<Self> {
        batches.into_par_iter().map(Self::new).collect()
    }

    /// Build multiple Merkle roots in parallel without materializing full trees.
    pub fn parallel_roots(batches: &[Vec<Hash>]) -> Vec<Hash> {
        batches
            .par_iter()
            .map(|leaves| Self::new(leaves.clone()).parallel_root())
            .collect()
    }

    /// High-performance parallel root computation using Rayon.
    pub fn parallel_root(&self) -> Hash {
        if self.leaves.is_empty() { return Self::empty_root(); }
        if self.leaves.len() == 1 { return self.leaves[0]; }

        let mut current_layer = self.leaves.clone();
        let mut scratch = Vec::new();
        while current_layer.len() > 1 {
            Self::build_next_layer_parallel_into(&current_layer, &mut scratch);
            std::mem::swap(&mut current_layer, &mut scratch);
        }
        current_layer[0]
    }

    /// Return the index of the node within each layer from leaf to root.
    pub fn proof_path(&self, index: usize) -> Result<Vec<usize>> {
        if index >= self.leaves.len() {
            bail!("Index out of bounds for Merkle proof path");
        }

        let mut path = Vec::with_capacity(self.layers.len());
        let mut current_index = index;
        for _layer in &self.layers {
            path.push(current_index);
            current_index /= 2;
        }

        Ok(path)
    }

    /// Generate an inclusion proof for a leaf at the given index.
    pub fn generate_proof(&self, index: usize) -> Result<Vec<Hash>> {
        if index >= self.leaves.len() {
            bail!("Index out of bounds for Merkle proof generation");
        }

        let mut proof = Vec::new();
        let mut current_index = index;

        // Iterate through layers from bottom up, excluding the root layer
        for i in 0..self.layers.len() - 1 {
            let layer = &self.layers[i];
            let is_right_node = current_index % 2 == 1;
            let sibling_index = if is_right_node {
                current_index - 1
            } else {
                if current_index + 1 < layer.len() {
                    current_index + 1
                } else {
                    current_index // Sibling is itself for odd counts
                }
            };
            proof.push(layer[sibling_index]);
            current_index /= 2;
        }

        Ok(proof)
    }

    /// Verify an inclusion proof against a known Merkle root.
    pub fn verify_proof(leaf: Hash, proof: &[Hash], root: Hash, mut index: usize) -> bool {
        let mut current_hash = leaf;

        for sibling_hash in proof {
            let is_right_node = index % 2 == 1;
            current_hash = if is_right_node {
                Self::hash_pair(sibling_hash, &current_hash)
            } else {
                Self::hash_pair(&current_hash, sibling_hash)
            };
            index /= 2;
        }

        current_hash == root
    }

    /// Perform a pre-verification check on the structure of the Merkle proof.
    pub fn validate_proof_structure(&self, proof: &[Hash]) -> Result<()> {
        if self.leaves.is_empty() {
            if proof.is_empty() {
                return Ok(());
            }
            bail!("Merkle proof cannot exist for an empty tree");
        }

        if self.layers.is_empty() || self.layers[0].len() != self.leaves.len() {
            bail!("Merkle tree layers are inconsistent with leaves");
        }

        let expected_depth = self.layers.len().saturating_sub(1);
        if proof.len() != expected_depth {
            bail!("Invalid proof depth: expected {}, got {}", expected_depth, proof.len());
        }
        Ok(())
    }

    // --- Fuzz Testing Hooks ---

    /// A robust entry point for fuzzing the tree construction and proof logic.
    pub fn fuzz_target_merkle(data: &[Hash], index: usize) {
        let tree = Self::new(data.to_vec());
        if !tree.is_empty() && index < tree.leaf_count() {
            let root = tree.root();
            if let Ok(proof) = tree.generate_proof(index) {
                tree.validate_proof_structure(&proof)
                    .expect("generated Merkle proof should have a valid structure");
                assert!(Self::verify_proof(data[index], &proof, root, index));
            }
        }
    }

    pub fn fuzz_target_verify_proof(leaf: Hash, proof: &[Hash], root: Hash, index: usize) {
        let _ = Self::verify_proof(leaf, proof, root, index);
    }

    /// Serialize the entire tree to bincode bytes.
    pub fn serialize(&self) -> Vec<u8> {
        bincode::serialize(self).expect("Merkle tree serialization should succeed")
    }

    /// Deserialize a tree from bincode bytes.
    pub fn deserialize(bytes: &[u8]) -> Result<Self> {
        bincode::deserialize(bytes).map_err(|e| anyhow::anyhow!("Merkle tree deserialization failed: {:?}", e))
    }

    fn build_next_layer_into(current_layer: &[Hash], next_layer: &mut Vec<Hash>) {
        let next_len = current_layer.len().div_ceil(2);
        next_layer.clear();
        next_layer.resize(next_len, [0u8; 32]);

        for (slot, pair_index) in next_layer.iter_mut().zip((0..current_layer.len()).step_by(2)) {
            let left = &current_layer[pair_index];
            let right = current_layer.get(pair_index + 1).unwrap_or(left);
            Self::hash_pair_into(left, right, slot);
        }
    }

    fn build_next_layer_parallel_into(current_layer: &[Hash], next_layer: &mut Vec<Hash>) {
        let next_len = current_layer.len().div_ceil(2);
        next_layer.clear();
        next_layer.resize(next_len, [0u8; 32]);

        next_layer
            .par_iter_mut()
            .enumerate()
            .for_each(|(index, slot)| {
                let pair_index = index * 2;
                let left = &current_layer[pair_index];
                let right = current_layer.get(pair_index + 1).unwrap_or(left);
                Self::hash_pair_into(left, right, slot);
            });
    }
}

#[cfg(test)]
mod tests {
    use super::MerkleTree;
    use vage_types::Hash;

    fn leaf(byte: u8) -> Hash {
        [byte; 32]
    }

    #[test]
    fn new_tree_builds_layers_and_root() {
        let tree = MerkleTree::new(vec![leaf(1), leaf(2), leaf(3), leaf(4)]);

        assert_eq!(tree.leaf_count(), 4);
        assert_eq!(tree.layers.len(), 3);
        assert_eq!(tree.root(), tree.parallel_root());
    }

    #[test]
    fn empty_tree_uses_empty_root() {
        let tree = MerkleTree::new(Vec::new());

        assert!(tree.is_empty());
        assert_eq!(tree.root(), MerkleTree::empty_root());
        assert_eq!(tree.parallel_root(), MerkleTree::empty_root());
    }

    #[test]
    fn append_leaf_rebuilds_tree() {
        let mut tree = MerkleTree::new(vec![leaf(1), leaf(2)]);
        let original_root = tree.root();

        tree.append_leaf(leaf(3));

        assert_eq!(tree.leaf_count(), 3);
        assert_ne!(tree.root(), original_root);
    }

    #[test]
    fn generate_and_verify_proof_work() {
        let tree = MerkleTree::new(vec![leaf(10), leaf(20), leaf(30), leaf(40), leaf(50)]);
        let index = 3;
        let proof = tree.generate_proof(index).expect("proof generation should succeed");

        tree.validate_proof_structure(&proof)
            .expect("proof structure should be valid");
        assert!(MerkleTree::verify_proof(tree.leaves[index], &proof, tree.root(), index));
        assert!(!MerkleTree::verify_proof(tree.leaves[index], &proof, leaf(0), index));
    }

    #[test]
    fn proof_path_tracks_indices_to_root() {
        let tree = MerkleTree::new(vec![leaf(1), leaf(2), leaf(3), leaf(4), leaf(5)]);

        assert_eq!(tree.proof_path(4).expect("proof path should succeed"), vec![4, 2, 1, 0]);
    }

    #[test]
    fn serialization_round_trip_preserves_tree() {
        let tree = MerkleTree::new(vec![leaf(1), leaf(2), leaf(3)]);
        let bytes = tree.serialize();
        let decoded = MerkleTree::deserialize(&bytes).expect("tree deserialization should succeed");

        assert_eq!(decoded.leaves, tree.leaves);
        assert_eq!(decoded.layers, tree.layers);
        assert_eq!(decoded.root(), tree.root());
    }

    #[test]
    fn batch_build_creates_multiple_trees() {
        let trees = MerkleTree::batch_build(vec![vec![leaf(1), leaf(2)], vec![leaf(3)], Vec::new()]);

        assert_eq!(trees.len(), 3);
        assert_eq!(trees[0].leaf_count(), 2);
        assert_eq!(trees[1].root(), leaf(3));
        assert_eq!(trees[2].root(), MerkleTree::empty_root());
    }

    #[test]
    fn parallel_roots_match_tree_roots() {
        let batches = vec![vec![leaf(1), leaf(2), leaf(3)], vec![leaf(4), leaf(5)], Vec::new()];
        let roots = MerkleTree::parallel_roots(&batches);

        assert_eq!(roots[0], MerkleTree::new(batches[0].clone()).root());
        assert_eq!(roots[1], MerkleTree::new(batches[1].clone()).root());
        assert_eq!(roots[2], MerkleTree::empty_root());
    }

    #[test]
    fn invalid_proof_structure_is_rejected() {
        let tree = MerkleTree::new(vec![leaf(1), leaf(2), leaf(3), leaf(4)]);

        assert!(tree.validate_proof_structure(&[]).is_err());
        assert!(MerkleTree::new(Vec::new())
            .validate_proof_structure(&[leaf(9)])
            .is_err());
    }
}
