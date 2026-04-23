use crate::body::BlockBody;
use crate::header::BlockHeader;
use anyhow::{bail, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use vage_types::{BlockHeight, Canonical, Hash};

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Block {
    pub header: BlockHeader,
    pub body: BlockBody,
}

impl Block {
    /// Create a new block with its header and body components.
    pub fn new(header: BlockHeader, body: BlockBody) -> Self {
        Self { header, body }
    }

    /// Create the genesis block (height 0).
    pub fn genesis(genesis_state_root: Hash) -> Self {
        let mut header = BlockHeader::genesis();
        header.set_state_root(genesis_state_root);
        Self {
            header,
            body: BlockBody::empty(),
        }
    }

    /// Return the block's height.
    pub fn height(&self) -> BlockHeight {
        self.header.height
    }

    /// Return the parent block's hash.
    pub fn parent_hash(&self) -> Hash {
        self.header.parent_hash
    }

    /// Check if this block is the genesis block.
    pub fn is_genesis(&self) -> bool {
        self.height() == 0
    }

    /// Return the number of transactions in the block.
    pub fn transaction_count(&self) -> usize {
        self.body.transaction_count()
    }

    /// Return the block's canonical hash (header hash).
    pub fn hash(&self) -> Hash {
        self.header.hash()
    }

    pub fn encode(&self) -> Vec<u8> {
        <Self as Canonical>::encode(self)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        <Self as Canonical>::decode(bytes)
    }

    /// Compute and set the transaction and receipt roots in the block header.
    pub fn compute_roots(&mut self) {
        let tx_root = self.body.compute_tx_root();
        let receipt_root = self.body.compute_receipt_root();

        self.header.set_tx_root(tx_root);
        self.header.set_receipts_root(receipt_root);
    }

    /// Verify that the header roots correctly match the body contents.
    pub fn verify_merkle_roots(&self) -> bool {
        let tx_root = self.body.compute_tx_root();
        let receipt_root = self.body.compute_receipt_root();

        self.header.tx_root == tx_root && self.header.receipts_root == receipt_root
    }

    /// Verify the proposer signature of the block header.
    pub fn verify_header_signature(&self, public_key_bytes: &[u8; 32]) -> Result<bool> {
        self.header.verify_signature(public_key_bytes)
    }

    /// Verify the block link sequence correctly points to the previous block.
    pub fn verify_parent_link(&self, previous_block: &Block) -> bool {
        self.header.verify_parent(previous_block.hash())
            && self.header.verify_height(previous_block.height() + 1)
    }

    /// Perform basic block structural and integrity checks.
    pub fn validate_basic(&self) -> Result<()> {
        self.header.validate_basic()?;

        // 1. Transaction and Size Limits
        if self.transaction_count() > crate::MAX_TRANSACTIONS_PER_BLOCK {
            bail!(
                "Transaction count {} exceeds limit of {}",
                self.transaction_count(),
                crate::MAX_TRANSACTIONS_PER_BLOCK
            );
        }
        if self.size_bytes() > crate::MAX_BLOCK_SIZE_BYTES {
            bail!(
                "Block size {} exceeds limit of {} bytes",
                self.size_bytes(),
                crate::MAX_BLOCK_SIZE_BYTES
            );
        }

        // 2. Merkle Root Consistency
        if !self.verify_merkle_roots() {
            bail!("Merkle root mismatch in block {}", self.height());
        }
        self.body.validate_transactions()?;
        self.body.validate_receipts()?;
        Ok(())
    }

    /// Perform transaction-level validation within the block.
    pub fn validate_transactions(&self) -> Result<()> {
        self.body.validate_transactions()
    }

    /// Perform receipt-level validation within the block.
    pub fn validate_receipts(&self) -> Result<()> {
        self.body.validate_receipts()
    }

    /// Return the full binary size of the block.
    pub fn size_bytes(&self) -> usize {
        self.header.size_bytes() + self.body.size_bytes()
    }

    // --- Specialized Verification Methods ---

    /// Verify the full structural integrity of the block (header vs body).
    pub fn verify_block_structure(&self) -> bool {
        self.verify_merkle_roots()
    }

    /// Verify that the block doesn't exceed the network's maximum allowed size.
    pub fn verify_block_size_limit(&self, max_size: usize) -> bool {
        self.size_bytes() <= max_size
    }

    /// Verify that the block timestamp doesn't drift too far from the provided local time.
    pub fn verify_block_timestamp_drift(&self, local_time: u64, max_drift: u64) -> bool {
        let diff = self.header.timestamp.abs_diff(local_time);
        diff <= max_drift
    }

    /// Explicitly verify the transaction Merkle root against the block body.
    pub fn verify_tx_merkle_root(&self) -> bool {
        let tx_root = self.body.compute_tx_root();
        self.header.tx_root == tx_root
    }

    /// Explicitly verify the receipt Merkle root against the block body.
    pub fn verify_receipt_merkle_root(&self) -> bool {
        let receipt_root = self.body.compute_receipt_root();
        self.header.receipts_root == receipt_root
    }

    /// Verify the block's state root against a known or computed root.
    pub fn verify_state_root(&self, expected_root: Hash) -> bool {
        self.header.state_root == expected_root
    }

    pub fn has_zk_proof(&self) -> bool {
        self.header.zk_proof.is_some()
    }

    pub fn zk_proof_bytes(&self) -> Option<&[u8]> {
        self.header.zk_proof.as_deref()
    }

    pub fn attach_validity_proof(&mut self, proof: Vec<u8>) {
        self.header.set_zk_proof(proof);
    }

    /// High-level check for the proposer's Ed25519 signature on the header.
    pub fn verify_proposer_signature(&self, public_key_bytes: &[u8; 32]) -> Result<bool> {
        self.header.verify_signature(public_key_bytes)
    }

    // --- Consensus Support Methods ---

    /// Serialize the block into a canonical proposal message for HotStuff BFT.
    pub fn proposal_message(&self) -> Vec<u8> {
        self.encode()
    }

    /// Calculate the canonical hash used for consensus voting (the header hash).
    pub fn vote_hash(&self) -> Hash {
        self.hash()
    }

    /// Calculate a hash commitment for a Quorum Certificate (QC) covering this block.
    pub fn quorum_cert_hash(&self) -> Hash {
        // A QC hash is usually a hash over the tuple (height, block_hash)
        let mut hasher = Sha256::new();
        hasher.update(self.height().to_le_bytes());
        hasher.update(self.hash());
        let result = hasher.finalize();
        let mut h = [0u8; 32];
        h.copy_from_slice(&result);
        h
    }

    /// Verify that a specific address was the authorized proposer for this block.
    pub fn verify_proposer(&self, expected_proposer: vage_types::Address) -> bool {
        self.header.proposer == expected_proposer
    }

    // --- Networking Serialization Methods ---

    /// Encode the block into its canonical network payload representation.
    pub fn encode_network(&self) -> Vec<u8> {
        self.encode()
    }

    /// Decode a block from its canonical network payload representation.
    pub fn decode_network(bytes: &[u8]) -> Result<Self> {
        Self::decode(bytes)
    }

    /// Convert the block into a serialized gossip message for P2P propagation.
    pub fn gossip_message(&self) -> vage_types::NetworkMessage {
        vage_types::NetworkMessage::GossipProposedBlock(self.encode_network())
    }

    /// Format the block as a response for a sync-related block request.
    pub fn build_sync_response(&self) -> vage_types::NetworkMessage {
        // Blocks are typically wrapped in a list or specific rpc response type
        vage_types::NetworkMessage::BlockHeaders(vec![self.header.encode()])
    }

    // --- Storage Interface Methods ---

    /// Encode the block into its canonical storage representation.
    pub fn encode_storage(&self) -> Vec<u8> {
        self.encode()
    }

    /// Decode a block from its canonical storage representation.
    pub fn decode_storage(bytes: &[u8]) -> Result<Self> {
        Self::decode(bytes)
    }

    /// Create a storage index entry mapping height to the block's current hash.
    pub fn height_index(&self) -> (vage_types::BlockHeight, Hash) {
        (self.height(), self.hash())
    }

    /// Return the lookup key used for hash-based retrieval in storage.
    pub fn hash_lookup_key(&self) -> Hash {
        self.hash()
    }
}

// Removed Canonical impl

/// High-level builder for assembling blocks during consensus or execution.
pub struct BlockBuilder {
    pub header: BlockHeader,
    pub body: BlockBody,
}

impl BlockBuilder {
    /// Create a new block builder starting from a parent block header.
    pub fn new(parent_header: &BlockHeader) -> Self {
        let mut header = BlockHeader::new(parent_header.hash(), parent_header.height + 1);
        header.set_timestamp(parent_header.timestamp + 1); // Minimum possible timestamp increment

        Self {
            header,
            body: BlockBody::new(),
        }
    }

    /// Add a transaction to the block being built.
    pub fn add_transaction(&mut self, tx: vage_types::Transaction) {
        self.body.add_transaction(tx);
    }

    /// Add a transaction receipt to the block being built.
    pub fn add_receipt(&mut self, receipt: vage_types::Receipt) {
        self.body.add_receipt(receipt);
    }

    /// Update the block timestamp.
    pub fn set_timestamp(&mut self, ts: vage_types::Timestamp) {
        self.header.set_timestamp(ts);
    }

    /// Update the block proposer address.
    pub fn set_proposer(&mut self, proposer: vage_types::Address) {
        self.header.proposer = proposer;
    }

    /// Update the block's state root commitment.
    pub fn set_state_root(&mut self, state_root: Hash) {
        self.header.set_state_root(state_root);
    }

    pub fn set_zk_validity_proof(&mut self, proof: Vec<u8>) {
        self.header.set_zk_proof(proof);
    }

    /// Build the block by computing all necessary Merkle roots and returning a Block.
    pub fn build(mut self) -> Block {
        // Automatically compute Merkle roots for the header
        let tx_root = self.body.compute_tx_root();
        let receipt_root = self.body.compute_receipt_root();

        self.header.set_tx_root(tx_root);
        self.header.set_receipts_root(receipt_root);

        Block {
            header: self.header,
            body: self.body,
        }
    }

    /// Sign the building block and return the finalized Block.
    pub fn sign(self, signing_key: &ed25519_dalek::SigningKey) -> Result<Block> {
        let mut block = self.build();
        block.header.sign(signing_key)?;
        Ok(block)
    }

    /// Perform pre-build integrity and safety checks on the assembling block components.
    pub fn validate_before_commit(&self) -> Result<()> {
        if self.body.transaction_count() == 0 {
            // Usually, empty blocks are allowed for consensus heartbeats, but can be checked.
        }
        self.header.validate_basic()?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::Block;
    use crate::{BlockBody, BlockHeader};
    use ed25519_dalek::SigningKey;
    use vage_types::{Address, Receipt, Transaction};

    fn sample_block() -> Block {
        let mut header = BlockHeader::new([1u8; 32], 2);
        let mut body = BlockBody::new();
        let tx = Transaction::new_transfer(Address([2u8; 32]), Address([3u8; 32]), 5u64.into(), 1);
        let receipt = Receipt::new_success(tx.hash(), 21_000, Some([4u8; 32]));
        body.add_transaction(tx);
        body.add_receipt(receipt);

        let mut block = Block::new(header.clone(), body);
        block.compute_roots();
        header = block.header.clone();
        Block::new(header, block.body)
    }

    #[test]
    fn new_block_exposes_header_body_metadata() {
        let block = sample_block();

        assert_eq!(block.height(), 2);
        assert_eq!(block.parent_hash(), [1u8; 32]);
        assert_eq!(block.transaction_count(), 1);
        assert_eq!(block.hash(), block.header.hash());
        assert!(!block.is_genesis());
    }

    #[test]
    fn compute_roots_and_verify_merkle_roots_match() {
        let mut block = sample_block();
        block.header.set_tx_root([0u8; 32]);
        block.header.set_receipts_root([0u8; 32]);

        assert!(!block.verify_merkle_roots());
        block.compute_roots();
        assert!(block.verify_merkle_roots());
    }

    #[test]
    fn verify_parent_link_and_genesis_work() {
        let genesis = Block::genesis([9u8; 32]);
        let child = Block::new(BlockHeader::new(genesis.hash(), 1), BlockBody::empty());

        assert!(genesis.is_genesis());
        assert!(child.verify_parent_link(&genesis));
    }

    #[test]
    fn validate_basic_checks_roots_transactions_and_receipts() {
        let block = sample_block();
        block.validate_basic().expect("valid block should pass");
        block
            .validate_transactions()
            .expect("transactions should validate");
        block.validate_receipts().expect("receipts should validate");
        assert!(block.size_bytes() > 0);
    }

    #[test]
    fn encode_decode_and_storage_network_helpers_round_trip() {
        let block = sample_block();
        let encoded = block.encode();

        let decoded = Block::decode(&encoded).expect("decode should succeed");
        let storage_round_trip =
            Block::decode_storage(&block.encode_storage()).expect("storage decode should succeed");
        let network_round_trip =
            Block::decode_network(&block.encode_network()).expect("network decode should succeed");

        assert_eq!(decoded, block);
        assert_eq!(storage_round_trip, block);
        assert_eq!(network_round_trip, block);
    }

    #[test]
    fn verify_header_signature_uses_header_signature_verification() {
        let signing_key = SigningKey::from_bytes(&[10u8; 32]);
        let public_key = signing_key.verifying_key().to_bytes();
        let proposer = Address::from_public_key(&public_key);
        let mut block = sample_block();
        block.header.proposer = proposer;
        block
            .header
            .sign(&signing_key)
            .expect("signing should succeed");

        assert!(block
            .verify_header_signature(&public_key)
            .expect("verification should succeed"));
    }
}
