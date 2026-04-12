pub mod groth16;
pub mod sp1;

use anyhow::{bail, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use vage_block::Block;
use vage_execution::runtime::ExecutionResult;
use vage_state::VerkleProof;
use vage_storage::StorageEngine;

pub use crate::groth16::Groth16Verifier;
pub use crate::sp1::{
    Sp1ExecutionEnvironment, Sp1ExecutionTrace, Sp1Proof, Sp1Prover, Sp1Verifier, ZkBlockWitness,
    ZkPublicInputs,
};

#[derive(Clone, Debug, Default)]
pub struct ZkEngine {
    pub prover: Sp1Prover,
    pub verifier: Sp1Verifier,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ExecutionTrace {
    pub program: Vec<u8>,
    pub inputs: Vec<u8>,
    pub state_reads: Vec<StateRead>,
    pub state_writes: Vec<StateWrite>,
    pub accessed_account_proofs: Vec<AccountProofWitness>,
    pub gas_used: u64,
    pub transaction_output: Option<TransactionOutput>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct StateRead {
    pub key: Vec<u8>,
    pub value: Vec<u8>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct StateWrite {
    pub key: Vec<u8>,
    pub value: Vec<u8>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct TransactionOutput {
    pub status: bool,
    pub gas_used: u64,
    pub log_count: usize,
    pub return_data: Vec<u8>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct AccountProofWitness {
    pub account_key: [u8; 32],
    pub proof: VerkleProof,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ZkProof {
    pub bytes: Vec<u8>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct BlockValidityProof {
    pub block_hash: [u8; 32],
    pub transaction_proofs: Vec<ZkProof>,
    pub aggregated_proof: ZkProof,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct RecursiveProof {
    pub proof: ZkProof,
    pub children: Vec<ZkProof>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct MultiBlockProof {
    pub block_hashes: Vec<[u8; 32]>,
    pub block_proofs: Vec<BlockValidityProof>,
    pub aggregated_proof: RecursiveProof,
}

impl ZkEngine {
    pub fn new() -> Self {
        Self {
            prover: Sp1Prover::default(),
            verifier: Sp1Verifier::new(Vec::new()),
        }
    }

    pub fn generate_proof(&self, execution_trace: &ExecutionTrace) -> Result<ZkProof> {
        let program = Sp1Prover::load_program_binary(&execution_trace.program)?;
        let prover = Sp1Prover::new(program);
        let proof = prover.prove(&execution_trace.serialize_for_zkvm_input()?)?;
        Ok(ZkProof {
            bytes: bincode::serialize(&proof)?,
        })
    }

    pub fn verify_proof(&self, proof: &ZkProof, public_inputs: &[u8]) -> Result<bool> {
        if proof.bytes.is_empty() {
            bail!("proof bytes cannot be empty");
        }

        let verifier = Sp1Verifier::new(execution_trace_verification_key(public_inputs));
        verifier.verify(&proof.bytes, public_inputs)
    }

    pub fn serialize_proof(&self, proof: &ZkProof) -> Result<Vec<u8>> {
        Ok(bincode::serialize(proof)?)
    }

    pub fn deserialize_proof(&self, bytes: &[u8]) -> Result<ZkProof> {
        Ok(bincode::deserialize(bytes)?)
    }

    pub fn proof_hash(&self, proof: &ZkProof) -> Result<[u8; 32]> {
        let encoded = self.serialize_proof(proof)?;
        let mut hasher = Sha256::new();
        hasher.update(encoded);
        let digest = hasher.finalize();
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&digest);
        Ok(hash)
    }

    pub fn proof_size(&self, proof: &ZkProof) -> Result<usize> {
        Ok(self.serialize_proof(proof)?.len())
    }

    pub fn batch_verify(&self, proofs: &[ZkProof], public_inputs: &[Vec<u8>]) -> Result<bool> {
        if proofs.len() != public_inputs.len() {
            bail!(
                "proof/public input length mismatch ({} != {})",
                proofs.len(),
                public_inputs.len()
            );
        }

        for (proof, inputs) in proofs.iter().zip(public_inputs.iter()) {
            if !self.verify_proof(proof, inputs)? {
                return Ok(false);
            }
        }

        Ok(true)
    }

    pub fn prove_all_transactions_in_block(
        &self,
        block: &Block,
        execution_traces: &[ExecutionTrace],
    ) -> Result<Vec<ZkProof>> {
        if block.body.transactions.len() != execution_traces.len() {
            bail!(
                "transaction/trace length mismatch ({} != {})",
                block.body.transactions.len(),
                execution_traces.len()
            );
        }

        execution_traces
            .iter()
            .map(|trace| self.generate_proof(trace))
            .collect()
    }

    pub fn aggregate_transaction_proofs(&self, proofs: &[ZkProof]) -> Result<RecursiveProof> {
        if proofs.is_empty() {
            bail!("cannot aggregate an empty set of transaction proofs");
        }

        Ok(RecursiveProof {
            proof: self.aggregate_recursive_layer(b"zk:tx", proofs)?,
            children: proofs.to_vec(),
        })
    }

    pub fn generate_block_validity_proof(
        &self,
        block: &Block,
        execution_traces: &[ExecutionTrace],
    ) -> Result<BlockValidityProof> {
        let transaction_proofs = self.prove_all_transactions_in_block(block, execution_traces)?;
        let transaction_aggregate = self.aggregate_transaction_proofs(&transaction_proofs)?;
        let aggregated_proof =
            self.aggregate_block_proof(block, &transaction_proofs, &transaction_aggregate.proof)?;

        Ok(BlockValidityProof {
            block_hash: block.hash(),
            transaction_proofs,
            aggregated_proof,
        })
    }

    pub fn generate_proof_after_block_execution(
        &self,
        block: &Block,
        execution_traces: &[ExecutionTrace],
    ) -> Result<BlockValidityProof> {
        self.generate_block_validity_proof(block, execution_traces)
    }

    pub fn attach_proof_to_block_header(
        &self,
        block: &mut Block,
        proof: &BlockValidityProof,
    ) -> Result<()> {
        block.attach_validity_proof(bincode::serialize(proof)?);
        Ok(())
    }

    pub fn store_block_proof(
        &self,
        storage: &StorageEngine,
        height: u64,
        proof: &BlockValidityProof,
    ) -> Result<()> {
        storage.store_zk_proof(height, bincode::serialize(proof)?)
    }

    pub fn load_block_proof(
        &self,
        storage: &StorageEngine,
        height: u64,
    ) -> Result<Option<BlockValidityProof>> {
        storage
            .get_zk_proof(height)?
            .map(|bytes| bincode::deserialize(&bytes).map_err(Into::into))
            .transpose()
    }

    pub fn aggregate_block_proofs(
        &self,
        block_proofs: &[BlockValidityProof],
    ) -> Result<RecursiveProof> {
        if block_proofs.is_empty() {
            bail!("cannot aggregate an empty set of block proofs");
        }

        let child_proofs: Vec<ZkProof> = block_proofs
            .iter()
            .map(|proof| proof.aggregated_proof.clone())
            .collect();

        Ok(RecursiveProof {
            proof: self.aggregate_recursive_layer(b"zk:block", &child_proofs)?,
            children: child_proofs,
        })
    }

    pub fn generate_recursive_proof(&self, proofs: &[ZkProof]) -> Result<RecursiveProof> {
        if proofs.is_empty() {
            bail!("cannot generate a recursive proof from an empty proof set");
        }

        Ok(RecursiveProof {
            proof: self.aggregate_recursive_layer(b"zk:recursive", proofs)?,
            children: proofs.to_vec(),
        })
    }

    pub fn produce_single_proof_for_multiple_blocks(
        &self,
        blocks: &[Block],
        block_traces: &[Vec<ExecutionTrace>],
    ) -> Result<MultiBlockProof> {
        if blocks.len() != block_traces.len() {
            bail!(
                "block/trace batch length mismatch ({} != {})",
                blocks.len(),
                block_traces.len()
            );
        }

        let block_proofs: Result<Vec<_>> = blocks
            .iter()
            .zip(block_traces.iter())
            .map(|(block, traces)| self.generate_block_validity_proof(block, traces))
            .collect();
        let block_proofs = block_proofs?;
        let aggregated_proof = self.aggregate_block_proofs(&block_proofs)?;

        Ok(MultiBlockProof {
            block_hashes: blocks.iter().map(Block::hash).collect(),
            block_proofs,
            aggregated_proof,
        })
    }
}

impl ExecutionTrace {
    pub fn new(program: Vec<u8>, inputs: Vec<u8>) -> Self {
        Self {
            program,
            inputs,
            state_reads: Vec::new(),
            state_writes: Vec::new(),
            accessed_account_proofs: Vec::new(),
            gas_used: 0,
            transaction_output: None,
        }
    }

    pub fn capture_from_execution_engine(
        program: Vec<u8>,
        inputs: Vec<u8>,
        execution_result: &ExecutionResult,
        state_reads: Vec<(Vec<u8>, Vec<u8>)>,
        state_writes: Vec<(Vec<u8>, Vec<u8>)>,
    ) -> Self {
        let mut trace = Self::new(program, inputs);
        for (key, value) in state_reads {
            trace.record_state_read(key, value);
        }
        for (key, value) in state_writes {
            trace.record_state_write(key, value);
        }
        trace.record_gas_usage(execution_result.gas_used);
        trace.record_transaction_output(execution_result);
        trace
    }

    pub fn generate_verkle_proof_for_accessed_accounts(
        &mut self,
        proofs: Vec<([u8; 32], VerkleProof)>,
    ) {
        self.accessed_account_proofs = proofs
            .into_iter()
            .map(|(account_key, proof)| AccountProofWitness { account_key, proof })
            .collect();
    }

    pub fn attach_proof_to_zk_witness(&mut self, account_key: [u8; 32], proof: VerkleProof) {
        self.accessed_account_proofs
            .push(AccountProofWitness { account_key, proof });
    }

    pub fn record_state_read(&mut self, key: Vec<u8>, value: Vec<u8>) {
        self.state_reads.push(StateRead { key, value });
    }

    pub fn record_state_write(&mut self, key: Vec<u8>, value: Vec<u8>) {
        self.state_writes.push(StateWrite { key, value });
    }

    pub fn record_gas_usage(&mut self, gas_used: u64) {
        self.gas_used = gas_used;
    }

    pub fn record_transaction_output(&mut self, execution_result: &ExecutionResult) {
        self.transaction_output = Some(TransactionOutput {
            status: execution_result.status,
            gas_used: execution_result.gas_used,
            log_count: execution_result.logs.len(),
            return_data: execution_result.return_data.clone(),
        });
    }

    pub fn serialize_for_zkvm_input(&self) -> Result<Vec<u8>> {
        Ok(bincode::serialize(self)?)
    }

    pub fn verkle_proof_commitment(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        for witness in &self.accessed_account_proofs {
            hasher.update(witness.account_key);
            for commitment in &witness.proof.commitments {
                hasher.update(commitment);
            }
            for path_index in &witness.proof.path {
                hasher.update([*path_index as u8]);
            }
            for value in &witness.proof.values {
                hasher.update(value);
            }
        }
        let digest = hasher.finalize();
        let mut commitment = [0u8; 32];
        commitment.copy_from_slice(&digest);
        commitment
    }
}

fn execution_trace_verification_key(public_inputs: &[u8]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(public_inputs);
    hasher.finalize().to_vec()
}

impl ZkEngine {
    fn aggregate_block_proof(
        &self,
        block: &Block,
        proofs: &[ZkProof],
        transaction_aggregate: &ZkProof,
    ) -> Result<ZkProof> {
        let mut hasher = Sha256::new();
        hasher.update(block.hash());
        for proof in proofs {
            let proof_hash = self.proof_hash(proof)?;
            hasher.update(proof_hash);
        }
        hasher.update(self.proof_hash(transaction_aggregate)?);

        Ok(ZkProof {
            bytes: hasher.finalize().to_vec(),
        })
    }

    fn aggregate_recursive_layer(&self, domain: &[u8], proofs: &[ZkProof]) -> Result<ZkProof> {
        let mut hasher = Sha256::new();
        hasher.update(domain);
        for proof in proofs {
            hasher.update(self.proof_hash(proof)?);
        }

        Ok(ZkProof {
            bytes: hasher.finalize().to_vec(),
        })
    }

    // -----------------------------------------------------------------------
    // Block-witness construction (items 3, 4, 5)
    // -----------------------------------------------------------------------

    /// Items 3 + 4 â€” Build a `ZkBlockWitness` from a block and its execution traces.
    ///
    /// Captures the execution trace for each transaction (item 4), derives the
    /// `ZkPublicInputs` from the parent state root, the post-execution state
    /// root, and the block hash (items 14â€“16), then wraps everything in a
    /// `ZkBlockWitness` ready to be passed to the SP1 prover (item 5).
    ///
    /// # Parameters
    /// * `block`              â€” the finalized block.
    /// * `state_root_before`  â€” Verkle root **before** applying the block.
    /// * `execution_traces`   â€” one `ExecutionTrace` per transaction.
    pub fn build_block_witness(
        &self,
        block: &Block,
        state_root_before: [u8; 32],
        execution_traces: &[ExecutionTrace],
    ) -> Result<ZkBlockWitness> {
        if block.body.transactions.len() != execution_traces.len() {
            bail!(
                "transaction/trace count mismatch ({} vs {})",
                block.body.transactions.len(),
                execution_traces.len()
            );
        }

        // Aggregate all individual traces into a single canonical trace for
        // the block.  We use the first transaction's program ELF; in a real
        // deployment every transaction in a block shares the same guest ELF.
        let program = execution_traces
            .first()
            .map(|t| t.program.clone())
            .unwrap_or_default();
        let inputs = bincode::serialize(execution_traces)?;
        let block_trace = Sp1ExecutionTrace {
            program: program.clone(),
            witness_input: inputs.clone(),
            execution_trace: self.prover.capture_execution_trace(&inputs)?,
            public_inputs: Vec::new(), // filled below
        };

        let public_inputs =
            ZkPublicInputs::new(state_root_before, block.header.state_root, block.hash());

        Ok(ZkBlockWitness::new(block_trace, public_inputs))
    }

    // -----------------------------------------------------------------------
    // Block-proof validation (item 17)
    // -----------------------------------------------------------------------

    /// Item 17 â€” Reject a block if its attached ZK proof is invalid.
    ///
    /// Deserialises the `block.header.zk_proof` bytes, reconstructs the
    /// `ZkPublicInputs` expected for this block from the block header's own
    /// fields, and runs the full `Sp1Verifier::verify_block_proof` pipeline
    /// (items 12â€“16).
    ///
    /// Returns `Ok(())` when the proof is valid, or an error describing the
    /// exact validation failure so that the consensus layer can reject the
    /// block.
    ///
    /// # Parameters
    /// * `block`             â€” the candidate block containing `header.zk_proof`.
    /// * `state_root_before` â€” Verkle root of the **parent** block (not stored
    ///   in the candidate header itself).
    pub fn validate_block_proof(&self, block: &Block, state_root_before: [u8; 32]) -> Result<()> {
        let proof_bytes = block.header.zk_proof.as_ref().ok_or_else(|| {
            anyhow::anyhow!(
                "block at height {} has no attached ZK proof",
                block.header.height
            )
        })?;

        // Deserialise the proof envelope stored in the block header.
        let sp1_proof: Sp1Proof = bincode::deserialize(proof_bytes)
            .map_err(|e| anyhow::anyhow!("failed to deserialise block ZK proof: {}", e))?;

        // Reconstruct the public inputs we expect for this block (items 14â€“16).
        let public_inputs =
            ZkPublicInputs::new(state_root_before, block.header.state_root, block.hash());

        // Derive the verification key from the encoded public inputs.
        let encoded_pi = public_inputs.encode();
        let verifier = Sp1Verifier::new(execution_trace_verification_key(&encoded_pi));

        // Item 12 â€” full verify_block_proof pipeline (also covers items 13â€“16).
        verifier.verify_block_proof(&sp1_proof, &public_inputs)?;

        tracing::info!(
            "ZK block proof validated for block {} (hash 0x{})",
            block.header.height,
            hex::encode(block.hash())
        );
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Storage helpers (item 19)
    // -----------------------------------------------------------------------

    /// Item 19 â€” Store a `BlockValidityProof` indexed by both block height and
    /// block hash, allowing lookups from either direction.
    pub fn store_proof_indexed(
        &self,
        storage: &StorageEngine,
        height: u64,
        block_hash: [u8; 32],
        proof: &BlockValidityProof,
    ) -> Result<()> {
        let bytes = bincode::serialize(proof)?;
        // Primary index: by height (used during sequential validation).
        storage.store_zk_proof(height, bytes.clone())?;
        // Secondary index: by block hash (used by light clients / RPC).
        let hash_key = [b"zk:proof:hash:".as_ref(), block_hash.as_slice()].concat();
        storage.state_put(hash_key, bytes)?;
        Ok(())
    }

    /// Item 19 â€” Load a `BlockValidityProof` by block hash (complements the
    /// existing `load_block_proof` which looks up by height).
    pub fn load_proof_by_hash(
        &self,
        storage: &StorageEngine,
        block_hash: [u8; 32],
    ) -> Result<Option<BlockValidityProof>> {
        let hash_key = [b"zk:proof:hash:".as_ref(), block_hash.as_slice()].concat();
        storage
            .state_get(hash_key)?
            .map(|bytes| bincode::deserialize(&bytes).map_err(Into::into))
            .transpose()
    }
}
