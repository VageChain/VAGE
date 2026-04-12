use anyhow::{bail, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use vage_types::{Canonical, Hash, Receipt, Transaction, Validator};

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct BlockBody {
    pub transactions: Vec<Transaction>,
    pub receipts: Vec<Receipt>,
}

impl BlockBody {
    /// Create a new block body.
    pub fn new() -> Self {
        Self {
            transactions: Vec::new(),
            receipts: Vec::new(),
        }
    }

    /// Create an empty block body for the genesis block.
    pub fn empty() -> Self {
        Self::new()
    }

    /// Add a transaction to the block body.
    pub fn add_transaction(&mut self, tx: Transaction) {
        self.transactions.push(tx);
    }

    /// Add a transaction receipt to the block body.
    pub fn add_receipt(&mut self, receipt: Receipt) {
        self.receipts.push(receipt);
    }

    pub fn transaction_count(&self) -> usize {
        self.transactions.len()
    }
    pub fn receipt_count(&self) -> usize {
        self.receipts.len()
    }

    pub fn encode(&self) -> Vec<u8> {
        <Self as Canonical>::encode(self)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        <Self as Canonical>::decode(bytes)
    }

    /// Calculate the binary size of the block body for block gas/size limits.
    pub fn size_bytes(&self) -> usize {
        self.encode().len()
    }

    pub fn tx_root(&self) -> Hash {
        self.compute_tx_root()
    }

    pub fn receipts_root(&self) -> Hash {
        self.compute_receipt_root()
    }

    /// Compute the Merkle tree root of all transactions in the block.
    pub fn compute_tx_root(&self) -> Hash {
        if self.transactions.is_empty() {
            return [0u8; 32];
        }
        let hashes: Vec<Hash> = self.transactions.iter().map(|tx| tx.hash()).collect();
        Self::calculate_merkle_root(hashes)
    }

    /// Compute the Merkle tree root of all receipts in the block.
    pub fn compute_receipt_root(&self) -> Hash {
        if self.receipts.is_empty() {
            return [0u8; 32];
        }
        let hashes: Vec<Hash> = self.receipts.iter().map(|r| r.hash()).collect();
        Self::calculate_merkle_root(hashes)
    }

    /// Internal helper for computing a binary Merkle tree root.
    fn calculate_merkle_root(mut leaves: Vec<Hash>) -> Hash {
        if leaves.is_empty() {
            return [0u8; 32];
        }

        while leaves.len() > 1 {
            if !leaves.len().is_multiple_of(2) {
                leaves.push(*leaves.last().unwrap());
            }
            let mut next_level = Vec::new();
            for i in (0..leaves.len()).step_by(2) {
                let mut hasher = Sha256::new();
                hasher.update(leaves[i]);
                hasher.update(leaves[i + 1]);
                let result = hasher.finalize();
                let mut h = [0u8; 32];
                h.copy_from_slice(&result);
                next_level.push(h);
            }
            leaves = next_level;
        }
        leaves[0]
    }

    /// Basic structural validation for transactions in the body.
    pub fn validate_transactions(&self) -> Result<()> {
        for tx in &self.transactions {
            tx.validate_basic()?;
        }
        Ok(())
    }

    /// Basic structural validation for receipts in the body.
    pub fn validate_receipts(&self) -> Result<()> {
        if self.receipts.len() != self.transactions.len() {
            anyhow::bail!(
                "Receipt count mismatch: {} receipts for {} transactions",
                self.receipts.len(),
                self.transactions.len()
            );
        }
        Ok(())
    }

    // --- Merkle Utilities ---

    /// Static helper for computing a validator set commitment root.
    pub fn compute_validator_root(validators: &[Validator]) -> Hash {
        if validators.is_empty() {
            return [0u8; 32];
        }
        let hashes: Vec<Hash> = validators.iter().map(|v| v.hash()).collect();
        Self::calculate_merkle_root(hashes)
    }

    /// Generate a Merkle inclusion proof for a transaction at a specific index.
    pub fn generate_tx_merkle_proof(&self, index: usize) -> Result<Vec<Hash>> {
        if index >= self.transactions.len() {
            bail!("Transaction index out of bounds for proof generation");
        }

        let mut leaves: Vec<Hash> = self.transactions.iter().map(|tx| tx.hash()).collect();
        let mut proof = Vec::new();
        let mut current_index = index;

        while leaves.len() > 1 {
            if !leaves.len().is_multiple_of(2) {
                leaves.push(*leaves.last().unwrap());
            }

            let mut next_level = Vec::new();
            for i in (0..leaves.len()).step_by(2) {
                // If it's our target index or its sibling, we add the sibling to the proof
                if i == current_index || i + 1 == current_index {
                    let sib_index = if i == current_index { i + 1 } else { i };
                    proof.push(leaves[sib_index]);
                    current_index /= 2;
                }

                let mut hasher = Sha256::new();
                hasher.update(leaves[i]);
                hasher.update(leaves[i + 1]);
                let result = hasher.finalize();
                let mut h = [0u8; 32];
                h.copy_from_slice(&result);
                next_level.push(h);
            }
            leaves = next_level;
        }
        Ok(proof)
    }

    /// Verify a transaction's inclusion in a block using a Merkle proof against the tx_root.
    pub fn verify_tx_merkle_proof(tx_hash: Hash, index: usize, proof: &[Hash], root: Hash) -> bool {
        let mut current_hash = tx_hash;
        let mut current_index = index;

        for sib_hash in proof {
            let mut hasher = Sha256::new();
            if current_index.is_multiple_of(2) {
                hasher.update(current_hash);
                hasher.update(sib_hash);
            } else {
                hasher.update(sib_hash);
                hasher.update(current_hash);
            }
            let result = hasher.finalize();
            current_hash.copy_from_slice(&result);
            current_index /= 2;
        }
        current_hash == root
    }
}

// Removed Canonical impl

#[cfg(test)]
mod tests {
    use super::BlockBody;
    use vage_types::{Address, Receipt, Transaction};

    fn sample_transaction(nonce: u64) -> Transaction {
        Transaction::new_transfer(
            Address([1u8; 32]),
            Address([2u8; 32]),
            (10u64 + nonce).into(),
            nonce,
        )
    }

    fn sample_receipt(tx_hash: [u8; 32]) -> Receipt {
        Receipt::new_success(tx_hash, 21_000, Some([9u8; 32]))
    }

    #[test]
    fn new_and_empty_bodies_start_without_entries() {
        let body = BlockBody::new();
        let empty = BlockBody::empty();

        assert_eq!(body.transaction_count(), 0);
        assert_eq!(body.receipt_count(), 0);
        assert_eq!(empty, body);
    }

    #[test]
    fn add_transaction_and_receipt_updates_counts() {
        let tx = sample_transaction(1);
        let receipt = sample_receipt(tx.hash());
        let mut body = BlockBody::new();

        body.add_transaction(tx);
        body.add_receipt(receipt);

        assert_eq!(body.transaction_count(), 1);
        assert_eq!(body.receipt_count(), 1);
    }

    #[test]
    fn tx_and_receipt_roots_match_compute_aliases() {
        let tx_one = sample_transaction(1);
        let tx_two = sample_transaction(2);
        let receipt_one = sample_receipt(tx_one.hash());
        let receipt_two = sample_receipt(tx_two.hash());
        let mut body = BlockBody::new();

        body.add_transaction(tx_one);
        body.add_transaction(tx_two);
        body.add_receipt(receipt_one);
        body.add_receipt(receipt_two);

        assert_eq!(body.tx_root(), body.compute_tx_root());
        assert_eq!(body.receipts_root(), body.compute_receipt_root());
        assert_ne!(body.tx_root(), [0u8; 32]);
        assert_ne!(body.receipts_root(), [0u8; 32]);
    }

    #[test]
    fn validate_transactions_and_receipts_enforce_structure() {
        let tx = sample_transaction(3);
        let mut body = BlockBody::new();
        body.add_transaction(tx);

        assert!(body.validate_transactions().is_ok());
        assert!(body.validate_receipts().is_err());

        body.add_receipt(sample_receipt(body.transactions[0].hash()));
        assert!(body.validate_receipts().is_ok());
    }

    #[test]
    fn encode_decode_and_size_bytes_are_consistent() {
        let tx = sample_transaction(4);
        let receipt = sample_receipt(tx.hash());
        let mut body = BlockBody::new();
        body.add_transaction(tx);
        body.add_receipt(receipt);

        let encoded = body.encode();
        let decoded = BlockBody::decode(&encoded).expect("decode should succeed");

        assert_eq!(decoded, body);
        assert_eq!(body.size_bytes(), encoded.len());
    }
}
