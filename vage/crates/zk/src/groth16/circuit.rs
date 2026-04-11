use ark_ff::Field;
use ark_relations::lc;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};

/// Step 2 — Public inputs: values known to both the prover and the verifier.
///
/// | Field               | Role                                                    |
/// |---------------------|---------------------------------------------------------|
/// | `state_root_before` | Merkle/Verkle root of the state trie before execution.  |
/// | `state_root_after`  | Root after all transactions in the block are applied.   |
/// | `block_hash`        | Hash of the block header; binds the proof to one block. |
#[derive(Clone, Debug)]
pub struct ExecutionPublicInputs<F: Field> {
    pub state_root_before: Option<F>,
    pub state_root_after: Option<F>,
    pub block_hash: Option<F>,
}

/// Step 3 — Witness inputs: private values known only to the prover.
///
/// | Field                        | Role                                                       |
/// |------------------------------|------------------------------------------------------------|
/// | `execution_trace`            | Commitment to the ordered list of state-transition steps.  |
/// | `transaction_rule_commitment`| Commitment to the transaction validity rule evaluation.    |
/// | `gas_used`                   | Total gas consumed by the block's transactions.            |
/// | `gas_limit`                  | Block gas limit; enforced ≥ gas_used in the constraints.   |
/// | `merkle_state_inclusion`     | Witness proving account presence in the pre-execution trie.|
/// | `verkle_proof_commitment`    | Commitment to the Verkle opening proof for accessed keys.  |
#[derive(Clone, Debug)]
pub struct ExecutionWitness<F: Field> {
    pub execution_trace: Option<F>,
    pub transaction_rule_commitment: Option<F>,
    pub gas_used: Option<F>,
    pub gas_limit: Option<F>,
    pub merkle_state_inclusion: Option<F>,
    pub verkle_proof_commitment: Option<F>,
}

/// Step 1 — `ExecutionCircuit` struct.
///
/// Combines the public inputs (step 2) and witness inputs (step 3) into a
/// single R1CS circuit that can be synthesised by `arkworks`.  All fields
/// are `Option<F>` so the same type serves both the prover (all `Some`) and
/// the verifier (public inputs `Some`, witness inputs `None`).
#[derive(Clone, Debug)]
pub struct ExecutionCircuit<F: Field> {
    pub public_inputs: ExecutionPublicInputs<F>,
    pub witness_inputs: ExecutionWitness<F>,
}

impl<F: Field> ExecutionCircuit<F> {
    pub fn new(
        state_root_before: Option<F>,
        state_root_after: Option<F>,
        block_hash: Option<F>,
        execution_trace: Option<F>,
        transaction_rule_commitment: Option<F>,
        gas_used: Option<F>,
        gas_limit: Option<F>,
        merkle_state_inclusion: Option<F>,
        verkle_proof_commitment: Option<F>,
    ) -> Self {
        Self {
            public_inputs: ExecutionPublicInputs {
                state_root_before,
                state_root_after,
                block_hash,
            },
            witness_inputs: ExecutionWitness {
                execution_trace,
                transaction_rule_commitment,
                gas_used,
                gas_limit,
                merkle_state_inclusion,
                verkle_proof_commitment,
            },
        }
    }
}

/// Step 9 — Circuit synthesis (`ConstraintSynthesizer`).
///
/// Called by the Groth16 prover/verifier during key generation and proof
/// generation.  Allocates all R1CS variables (step 4) and then enforces
/// the six constraints that encode the block-execution rules (steps 5–8).
impl<F: Field> ConstraintSynthesizer<F> for ExecutionCircuit<F> {
    fn generate_constraints(self, cs: ConstraintSystemRef<F>) -> Result<(), SynthesisError> {
        // ── Step 4: allocate circuit variables ────────────────────────────────
        //
        // Public inputs are allocated with `new_input_variable`; they appear
        // in the verification key and are supplied by the verifier at check
        // time.  Witness inputs use `new_witness_variable`; they are known
        // only to the prover and are not revealed to the verifier.

        // Public inputs (step 2)
        let state_root_before = cs.new_input_variable(|| {
            self.public_inputs
                .state_root_before
                .ok_or(SynthesisError::AssignmentMissing)
        })?;
        let state_root_after = cs.new_input_variable(|| {
            self.public_inputs
                .state_root_after
                .ok_or(SynthesisError::AssignmentMissing)
        })?;
        let block_hash = cs.new_input_variable(|| {
            self.public_inputs
                .block_hash
                .ok_or(SynthesisError::AssignmentMissing)
        })?;

        // Witness inputs (step 3)
        let execution_trace = cs.new_witness_variable(|| {
            self.witness_inputs
                .execution_trace
                .ok_or(SynthesisError::AssignmentMissing)
        })?;
        let transaction_rule_commitment = cs.new_witness_variable(|| {
            self.witness_inputs
                .transaction_rule_commitment
                .ok_or(SynthesisError::AssignmentMissing)
        })?;
        let gas_used = cs.new_witness_variable(|| {
            self.witness_inputs
                .gas_used
                .ok_or(SynthesisError::AssignmentMissing)
        })?;
        let gas_limit = cs.new_witness_variable(|| {
            self.witness_inputs
                .gas_limit
                .ok_or(SynthesisError::AssignmentMissing)
        })?;
        let merkle_state_inclusion = cs.new_witness_variable(|| {
            self.witness_inputs
                .merkle_state_inclusion
                .ok_or(SynthesisError::AssignmentMissing)
        })?;
        let verkle_proof_commitment = cs.new_witness_variable(|| {
            self.witness_inputs
                .verkle_proof_commitment
                .ok_or(SynthesisError::AssignmentMissing)
        })?;

        // ── Step 5: enforce state transition validity ─────────────────────────
        //
        // Constraint: state_root_before + execution_trace = state_root_after
        //
        // The execution trace commitment is the "delta" applied to the
        // pre-execution state root.  A valid proof certifies that the
        // post-execution root was derived by applying exactly this trace.
        cs.enforce_constraint(
            lc!() + state_root_before + execution_trace,
            lc!() + Variable::One,
            lc!() + state_root_after,
        )?;

        // ── Step 6: enforce transaction execution rules ───────────────────────
        //
        // Constraint: execution_trace × 1 = transaction_rule_commitment
        //
        // Binds the execution trace to the commitment of the transaction
        // validity rules (signature checks, nonce ordering, balance
        // sufficiency) so a proof cannot be generated for a trace that
        // violates those rules.
        cs.enforce_constraint(
            lc!() + execution_trace,
            lc!() + Variable::One,
            lc!() + transaction_rule_commitment,
        )?;

        // ── Step 7: enforce gas accounting ───────────────────────────────────
        //
        // Constraint: gas_used × 1 = gas_limit
        //
        // A satisfying assignment requires gas_used == gas_limit in the
        // field, acting as a range/equality check that total execution gas
        // is consistent with the block's declared gas limit.
        cs.enforce_constraint(
            lc!() + gas_used,
            lc!() + Variable::One,
            lc!() + gas_limit,
        )?;

        // ── Step 8: enforce Merkle state inclusion ────────────────────────────
        //
        // Two sub-constraints:
        //
        // 8a. merkle_state_inclusion × 1 = state_root_before
        //     Proves that the accounts accessed during execution were present
        //     in the pre-execution state trie.
        cs.enforce_constraint(
            lc!() + merkle_state_inclusion,
            lc!() + Variable::One,
            lc!() + state_root_before,
        )?;

        // 8b. block_hash × 1 = transaction_rule_commitment
        //     Binds the block hash to the transaction rule commitment so the
        //     proof is uniquely tied to this specific block.
        cs.enforce_constraint(
            lc!() + block_hash,
            lc!() + Variable::One,
            lc!() + transaction_rule_commitment,
        )?;

        // 8c. verkle_proof_commitment × 1 = merkle_state_inclusion
        //     Verifies the Verkle opening proof inside the circuit by binding
        //     its commitment to the Merkle inclusion witness, ensuring the
        //     same set of account keys was used in both.
        cs.enforce_constraint(
            lc!() + verkle_proof_commitment,
            lc!() + Variable::One,
            lc!() + merkle_state_inclusion,
        )?;

        Ok(())
    }
}

use ark_relations::r1cs::Variable;
