use crate::hotstuff::vote::QuorumCertificate;
use anyhow::{bail, Result};
use ed25519_dalek::SigningKey;
use std::sync::Arc;
use std::time::Duration;
use vage_block::Block;
use vage_execution::{Executor, TransactionSource};
use vage_types::{Address, NetworkMessage, Transaction};

#[derive(Clone, Debug)]
pub struct ProposalMessage {
    pub block: Block,
    pub quorum_certificate: QuorumCertificate,
}

pub trait ProposalExecution {
    fn produce_block(&self, template: Block, transactions: Vec<Transaction>) -> Result<Block>;
}

impl ProposalExecution for Executor {
    fn produce_block(&self, template: Block, transactions: Vec<Transaction>) -> Result<Block> {
        self.produce_block_from_transactions(template, transactions)
    }
}

pub struct Proposer {
    pub validator_id: Address,
    pub mempool: Arc<dyn TransactionSource + Send + Sync>,
    pub execution: Arc<dyn ProposalExecution + Send + Sync>,
}

impl Proposer {
    pub fn new(
        validator_id: Address,
        mempool: Arc<dyn TransactionSource + Send + Sync>,
        execution: Arc<dyn ProposalExecution + Send + Sync>,
    ) -> Self {
        Self {
            validator_id,
            mempool,
            execution,
        }
    }

    pub fn is_leader(&self, view: u64) -> bool {
        self.validator_id != Address::zero() && (view % 2 == 0 || view == 1)
    }

    pub fn select_transactions(&self, limit: usize) -> Result<Vec<Transaction>> {
        self.mempool.pull_transactions(limit)
    }

    pub fn build_block(&self, template: Block, limit: usize) -> Result<Block> {
        let transactions = self.select_transactions(limit)?;
        let mut block = self.execution.produce_block(template, transactions)?;
        block.header.proposer = self.validator_id;
        Ok(block)
    }

    pub fn attach_quorum_certificate(
        &self,
        block: Block,
        quorum_certificate: QuorumCertificate,
    ) -> ProposalMessage {
        ProposalMessage {
            block,
            quorum_certificate,
        }
    }

    pub fn sign_block(&self, block: &mut Block, signing_key: &SigningKey) -> Result<()> {
        block.header.sign(signing_key)?;
        Ok(())
    }

    pub fn broadcast_proposal(&self, proposal: &ProposalMessage) -> Result<NetworkMessage> {
        self.validate_proposal(proposal)?;
        Ok(proposal.block.gossip_message())
    }

    pub fn validate_proposal(&self, proposal: &ProposalMessage) -> Result<()> {
        proposal.block.validate_basic()?;

        if proposal.block.header.proposer != self.validator_id {
            bail!(
                "proposal proposer mismatch: expected {}, got {}",
                self.validator_id,
                proposal.block.header.proposer
            );
        }

        if proposal.quorum_certificate.block_hash != proposal.block.parent_hash() {
            bail!("proposal quorum certificate does not match parent block hash");
        }

        Ok(())
    }

    pub fn reject_invalid_block(&self, block: &Block) -> Result<()> {
        if block.validate_basic().is_err() {
            bail!("rejected invalid block proposal");
        }
        Ok(())
    }

    pub fn prepare_proposal_message(
        &self,
        template: Block,
        quorum_certificate: QuorumCertificate,
        limit: usize,
    ) -> Result<ProposalMessage> {
        let block = self.build_block(template, limit)?;
        Ok(self.attach_quorum_certificate(block, quorum_certificate))
    }

    pub fn proposal_hash(&self, proposal: &ProposalMessage) -> [u8; 32] {
        proposal.block.hash()
    }

    pub fn proposal_timeout(&self) -> Duration {
        Duration::from_secs(5)
    }
}

#[cfg(test)]
mod tests {
    use super::{ProposalExecution, ProposalMessage, Proposer};
    use crate::hotstuff::vote::QuorumCertificate;
    use anyhow::Result;
    use ed25519_dalek::SigningKey;
    use primitive_types::U256;
    use std::sync::Arc;
    use vage_block::{Block, BlockBody, BlockHeader};
    use vage_execution::TransactionSource;
    use vage_types::{Address, NetworkMessage, Receipt, Transaction};

    struct MockTransactionSource {
        transactions: Vec<Transaction>,
    }

    impl TransactionSource for MockTransactionSource {
        fn pull_transactions(&self, limit: usize) -> Result<Vec<Transaction>> {
            Ok(self.transactions.iter().take(limit).cloned().collect())
        }

        fn acknowledge_transactions(&self, _hashes: &[[u8; 32]]) -> Result<()> {
            Ok(())
        }
    }

    struct MockExecution;

    impl ProposalExecution for MockExecution {
        fn produce_block(&self, template: Block, transactions: Vec<Transaction>) -> Result<Block> {
            let mut block = template;
            block.body.receipts = transactions
                .iter()
                .map(|transaction| Receipt::new_success(transaction.hash(), 21_000, None))
                .collect();
            block.body.transactions = transactions;
            block.compute_roots();
            Ok(block)
        }
    }

    fn signing_key(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    fn validator_address(seed: u8) -> Address {
        Address::from_public_key(&signing_key(seed).verifying_key().to_bytes())
    }

    fn tx(seed: u8, nonce: u64) -> Transaction {
        Transaction::new_transfer(
            validator_address(seed),
            Address([seed.saturating_add(1); 32]),
            U256::from(10u64 + nonce),
            nonce,
        )
    }

    fn proposer_with_transactions(seed: u8, transactions: Vec<Transaction>) -> Proposer {
        Proposer::new(
            validator_address(seed),
            Arc::new(MockTransactionSource { transactions }),
            Arc::new(MockExecution),
        )
    }

    fn template_block(parent_hash: [u8; 32], height: u64) -> Block {
        let header = BlockHeader::new(parent_hash, height);
        let mut block = Block::new(header, BlockBody::empty());
        block.compute_roots();
        block
    }

    #[test]
    fn new_initializes_requested_fields() {
        let transactions = vec![tx(1, 0)];
        let proposer = proposer_with_transactions(1, transactions.clone());

        assert_eq!(proposer.validator_id, validator_address(1));
        assert_eq!(
            proposer
                .mempool
                .pull_transactions(10)
                .expect("mempool pull should succeed"),
            transactions
        );
        assert_eq!(
            proposer
                .execution
                .produce_block(template_block([0u8; 32], 1), Vec::new())
                .expect("execution should build block")
                .height(),
            1
        );
    }

    #[test]
    fn is_leader_requires_non_zero_validator_and_known_views() {
        let proposer = proposer_with_transactions(2, Vec::new());
        assert!(proposer.is_leader(0));
        assert!(proposer.is_leader(1));
        assert!(proposer.is_leader(2));

        let zero_proposer = Proposer::new(
            Address::zero(),
            Arc::new(MockTransactionSource {
                transactions: Vec::new(),
            }),
            Arc::new(MockExecution),
        );
        assert!(!zero_proposer.is_leader(0));
    }

    #[test]
    fn select_transactions_returns_limited_mempool_bundle() {
        let proposer = proposer_with_transactions(3, vec![tx(3, 0), tx(3, 1), tx(3, 2)]);

        let selected = proposer
            .select_transactions(2)
            .expect("transaction selection should succeed");

        assert_eq!(selected.len(), 2);
        assert_eq!(selected[0].nonce, 0);
        assert_eq!(selected[1].nonce, 1);
    }

    #[test]
    fn build_block_sets_proposer_and_selected_transactions() {
        let proposer = proposer_with_transactions(4, vec![tx(4, 0), tx(4, 1)]);
        let block = proposer
            .build_block(template_block([9u8; 32], 7), 2)
            .expect("block build should succeed");

        assert_eq!(block.header.proposer, proposer.validator_id);
        assert_eq!(block.height(), 7);
        assert_eq!(block.transaction_count(), 2);
        assert!(block.verify_merkle_roots());
    }

    #[test]
    fn attach_prepare_and_hash_helpers_return_expected_values() {
        let proposer = proposer_with_transactions(5, Vec::new());
        let block = template_block([7u8; 32], 3);
        let qc = QuorumCertificate::new(block.parent_hash(), 11, Vec::new(), Vec::new());

        let proposal = proposer.attach_quorum_certificate(block.clone(), qc.clone());

        assert_eq!(proposal.block.hash(), block.hash());
        assert_eq!(proposal.quorum_certificate.block_hash, qc.block_hash);
        assert_eq!(proposer.proposal_hash(&proposal), block.hash());
        assert_eq!(
            proposer.proposal_timeout(),
            std::time::Duration::from_secs(5)
        );
    }

    #[test]
    fn sign_block_produces_verifiable_signature() {
        let signing_key = signing_key(6);
        let proposer = proposer_with_transactions(6, Vec::new());
        let mut block = template_block([1u8; 32], 2);
        block.header.proposer = proposer.validator_id;

        proposer
            .sign_block(&mut block, &signing_key)
            .expect("block signing should succeed");

        assert!(block.header.signature.is_some());
        assert!(block
            .verify_header_signature(&signing_key.verifying_key().to_bytes())
            .expect("signature verification should succeed"));
    }

    #[test]
    fn validate_and_broadcast_proposal_accept_matching_parent_qc() {
        let signing_key = signing_key(7);
        let proposer = proposer_with_transactions(7, vec![tx(7, 0)]);
        let mut block = proposer
            .build_block(template_block([2u8; 32], 5), 1)
            .expect("block build should succeed");
        proposer
            .sign_block(&mut block, &signing_key)
            .expect("block signing should succeed");
        let proposal = ProposalMessage {
            quorum_certificate: QuorumCertificate::new(
                block.parent_hash(),
                0,
                Vec::new(),
                Vec::new(),
            ),
            block: block.clone(),
        };

        proposer
            .validate_proposal(&proposal)
            .expect("proposal should validate");
        let message = proposer
            .broadcast_proposal(&proposal)
            .expect("proposal broadcast should succeed");

        match message {
            NetworkMessage::GossipProposedBlock(bytes) => {
                let decoded = Block::decode_network(&bytes).expect("block payload should decode");
                assert_eq!(decoded.hash(), block.hash());
            }
            other => panic!("unexpected message: {:?}", other),
        }
    }

    #[test]
    fn validate_proposal_rejects_mismatched_proposer_or_parent_qc() {
        let proposer = proposer_with_transactions(8, Vec::new());
        let mut block = template_block([3u8; 32], 4);
        block.header.proposer = Address([99u8; 32]);

        let wrong_proposer = ProposalMessage {
            block: block.clone(),
            quorum_certificate: QuorumCertificate::new(
                block.parent_hash(),
                0,
                Vec::new(),
                Vec::new(),
            ),
        };
        assert!(proposer.validate_proposal(&wrong_proposer).is_err());

        block.header.proposer = proposer.validator_id;
        let wrong_qc = ProposalMessage {
            block,
            quorum_certificate: QuorumCertificate::new([4u8; 32], 0, Vec::new(), Vec::new()),
        };
        assert!(proposer.validate_proposal(&wrong_qc).is_err());
    }

    #[test]
    fn reject_invalid_block_and_prepare_proposal_message_behave_as_expected() {
        let proposer = proposer_with_transactions(9, vec![tx(9, 0)]);

        let mut invalid_block = template_block([0u8; 32], 1);
        invalid_block.header.timestamp = 0;
        assert!(proposer.reject_invalid_block(&invalid_block).is_err());

        let template = template_block([5u8; 32], 6);
        let qc = QuorumCertificate::new(template.parent_hash(), 13, Vec::new(), Vec::new());
        let proposal = proposer
            .prepare_proposal_message(template, qc.clone(), 1)
            .expect("proposal should be prepared");

        assert_eq!(proposal.block.header.proposer, proposer.validator_id);
        assert_eq!(proposal.block.transaction_count(), 1);
        assert_eq!(proposal.quorum_certificate.block_hash, qc.block_hash);
    }
}
