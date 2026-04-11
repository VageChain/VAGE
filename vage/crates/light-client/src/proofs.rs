use anyhow::Result;
use vage_block::Block;
use vage_state::{VerkleProof, RpcVerkleProof};
use vage_types::{Account, Address, BlockHeight};
use vage_zk::{ZkEngine, ZkPublicInputs};
use tracing::{info, warn};

/// A utility for light clients to verify cryptographic proofs of state inclusion 
/// against a verified block header root.
pub struct ProofVerifier;

impl ProofVerifier {
    /// Verify a single Verkle inclusion proof for an arbitrary key-value pair.
    pub fn verify_inclusion_proof(
        proof: &VerkleProof,
        key: [u8; 32],
        value: [u8; 32],
        root_hash: [u8; 32],
    ) -> Result<bool> {
        info!("Verifying Verkle inclusion proof for key 0x{} against root 0x{}", hex::encode(key), hex::encode(root_hash));
        proof.verify_proof(key, value, root_hash)
    }

    /// Verify an account's state (balance, nonce, etc.) using a Verkle proof.
    pub fn verify_account_state(
        proof: &VerkleProof,
        address: &Address,
        account: &Account,
        root_hash: [u8; 32],
    ) -> Result<bool> {
        info!("Verifying account state proof for address {} against root 0x{}", address, hex::encode(root_hash));
        proof.verify_account_proof(address, account, root_hash)
    }

    /// Verify the value of a specific contract storage slot.
    pub fn verify_contract_storage(
        proof: &VerkleProof,
        address: &Address,
        storage_key: [u8; 32],
        storage_value: [u8; 32],
        root_hash: [u8; 32],
    ) -> Result<bool> {
        info!(
            "Verifying storage proof for contract {} at key 0x{} against root 0x{}", 
            address, hex::encode(storage_key), hex::encode(root_hash)
        );
        proof.verify_storage_proof(address, storage_key, storage_value, root_hash)
    }

    /// Verify a proof received via the RPC layer (which may be in a minimal format).
    pub fn verify_rpc_proof(
        rpc_proof: &RpcVerkleProof,
        key: [u8; 32],
        value: [u8; 32],
    ) -> Result<bool> {
        info!("Verifying RPC-format Verkle proof for key 0x{} against proof root 0x{}", hex::encode(key), hex::encode(rpc_proof.root));
        VerkleProof::verify_for_light_client(rpc_proof, key, value)
    }

    pub fn verify_rpc_account_proof(
        rpc_proof: &RpcVerkleProof,
        address: &Address,
        account: &Account,
    ) -> Result<bool> {
        info!(
            "Verifying RPC account proof for address {} against proof root 0x{}",
            address,
            hex::encode(rpc_proof.root)
        );
        Self::verify_rpc_proof(rpc_proof, *address.as_bytes(), account.hash())
    }

    pub fn verify_rpc_storage_proof(
        rpc_proof: &RpcVerkleProof,
        address: &Address,
        storage_key: [u8; 32],
        storage_value: [u8; 32],
    ) -> Result<bool> {
        info!(
            "Verifying RPC storage proof for contract {} at key 0x{} against proof root 0x{}",
            address,
            hex::encode(storage_key),
            hex::encode(rpc_proof.root)
        );
        Self::verify_rpc_proof(
            rpc_proof,
            vage_state::storage_proof_key(address, &storage_key),
            storage_value,
        )
    }

    pub fn verify_minimal_rpc_proof(
        rpc_proof: &RpcVerkleProof,
        key: [u8; 32],
        value: [u8; 32],
    ) -> Result<bool> {
        info!(
            "Verifying minimal RPC proof for key 0x{} against proof root 0x{}",
            hex::encode(key),
            hex::encode(rpc_proof.root)
        );
        Self::verify_rpc_proof(rpc_proof, key, value)
    }

    /// Validates a high-level state query by checking the proof against a specific verified block height.
    /// This requires the caller to provide the root of that block.
    pub fn validate_proof_at_height(
        proof: &VerkleProof,
        key: [u8; 32],
        value: [u8; 32],
        height: BlockHeight,
        verified_root: [u8; 32],
    ) -> Result<bool> {
        if !Self::verify_inclusion_proof(proof, key, value, verified_root)? {
            warn!("Proof validation failed at block height {}", height);
            return Ok(false);
        }
        
        info!("Proof successfully validated for block height {}", height);
        Ok(true)
    }

    // -----------------------------------------------------------------------
    // ZK block-validity proof verification (item 20)
    // -----------------------------------------------------------------------

    /// Item 20 â€” Verify the ZK block-validity proof attached to a block header.
    ///
    /// This is the primary ZK verification entry point for light clients.
    /// A light client cannot re-execute transactions, so it relies on this
    /// proof to confirm that the state transition encoded in the block header
    /// (`state_root_before â†’ state_root_after` over the transactions identified
    /// by `block_hash`) was carried out correctly.
    ///
    /// # Parameters
    /// * `block`             â€” the candidate block whose `header.zk_proof` will
    ///   be verified.
    /// * `state_root_before` â€” the state root of the **parent** block, obtained
    ///   from the light client's trusted chain view.
    /// * `engine`            â€” a `ZkEngine` instance (typically a shared
    ///   `Arc<ZkEngine>` held by the light client).
    ///
    /// Returns `Ok(true)` when the proof is valid.  Returns an error when
    /// the proof is missing, malformed, or fails any of the public-input
    /// checks (items 14â€“16), allowing the light client to **reject the block**
    /// (item 17).
    pub fn verify_block_zk_proof(
        block: &Block,
        state_root_before: [u8; 32],
        engine: &ZkEngine,
    ) -> Result<bool> {
        info!(
            "Light client verifying ZK proof for block {} (hash 0x{})",
            block.header.height,
            hex::encode(block.hash())
        );

        // Delegate to ZkEngine which orchestrates the full Sp1Verifier pipeline.
        engine.validate_block_proof(block, state_root_before)?;

        info!(
            "ZK proof accepted by light client for block {}",
            block.header.height
        );
        Ok(true)
    }

    /// Item 20 â€” Verify a batch of consecutive blocks' ZK proofs.
    ///
    /// The light client calls this after downloading a header range so that
    /// all blocks in the range are validated in one pass.  Each block's
    /// `state_root_after` becomes the next block's `state_root_before`.
    ///
    /// Returns `Ok(true)` only when every proof in the range is valid.
    pub fn verify_block_range_zk_proofs(
        blocks: &[Block],
        initial_state_root: [u8; 32],
        engine: &ZkEngine,
    ) -> Result<bool> {
        if blocks.is_empty() {
            return Ok(true);
        }

        let mut state_root_before = initial_state_root;

        for block in blocks {
            Self::verify_block_zk_proof(block, state_root_before, engine)?;
            // The post-execution state root becomes the pre-execution root for the
            // next block, establishing a verifiable state-root chain.
            state_root_before = block.header.state_root;
        }

        info!(
            "All {} ZK proofs in range validated by light client",
            blocks.len()
        );
        Ok(true)
    }

    /// Item 20 â€” Construct the `ZkPublicInputs` the light client expects for a
    /// given block so it can be compared against the proof's committed inputs
    /// without re-running the prover.
    pub fn expected_public_inputs(
        block: &Block,
        state_root_before: [u8; 32],
    ) -> ZkPublicInputs {
        ZkPublicInputs::new(state_root_before, block.header.state_root, block.hash())
    }
}

#[cfg(test)]
mod tests {
    use super::ProofVerifier;
    use vage_state::{storage_proof_key, VerkleProof, VerkleTree};
    use vage_types::{Account, Address};

    fn hash(byte: u8) -> [u8; 32] {
        [byte; 32]
    }

    #[test]
    fn verifies_rpc_account_proofs() {
        let mut tree = VerkleTree::new();
        let address = Address(hash(1));
        let account = Account::new(address);
        tree.insert(*address.as_bytes(), account.hash())
            .expect("account insert should succeed");

        let proof = VerkleProof::generate_account_proof(&tree, &address)
            .expect("account proof generation should succeed")
            .export_for_rpc(tree.root_commitment());

        assert!(ProofVerifier::verify_rpc_account_proof(&proof, &address, &account)
            .expect("rpc account proof verification should succeed"));
    }

    #[test]
    fn verifies_rpc_storage_proofs() {
        let mut tree = VerkleTree::new();
        let address = Address(hash(2));
        let storage_key = hash(3);
        let storage_value = hash(4);
        tree.insert(storage_proof_key(&address, &storage_key), storage_value)
            .expect("storage insert should succeed");

        let proof = VerkleProof::generate_storage_proof(&tree, &address, storage_key)
            .expect("storage proof generation should succeed")
            .export_for_rpc(tree.root_commitment());

        assert!(ProofVerifier::verify_rpc_storage_proof(&proof, &address, storage_key, storage_value)
            .expect("rpc storage proof verification should succeed"));
    }

    #[test]
    fn verifies_minimal_rpc_proofs() {
        let mut tree = VerkleTree::new();
        let key = hash(5);
        let value = hash(6);
        tree.insert(key, value).expect("tree insert should succeed");

        let proof = VerkleProof::generate_minimal_proof(&tree, key)
            .expect("minimal proof generation should succeed")
            .export_minimal_for_rpc(tree.root_commitment());

        assert!(ProofVerifier::verify_minimal_rpc_proof(&proof, key, value)
            .expect("minimal rpc proof verification should succeed"));
    }
}
