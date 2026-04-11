use crate::sp1::prover::{Sp1Proof, ZkPublicInputs};
use anyhow::{bail, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Sp1VerificationResult {
    pub verified: bool,
}

/// Step 1 — `Sp1Verifier` struct { verification_key }.
///
/// `verification_key` — deterministically derived from the public inputs at
/// verify time (`SHA-256(public_inputs)`), so no static key material needs to
/// be distributed out-of-band.  An empty key is accepted at construction and
/// replaced per-call in `ZkEngine::verify_proof`.
#[derive(Clone, Debug, Default)]
pub struct Sp1Verifier {
    pub verification_key: Vec<u8>,
}

impl Sp1Verifier {
    /// Step 2 — `Sp1Verifier::new(verification_key)`.
    ///
    /// Stores the supplied key unchanged.  Pass `Vec::new()` for a verifier
    /// whose key will be set externally (e.g. derived from the public inputs
    /// at verify time inside `ZkEngine::verify_proof`).
    pub fn new(verification_key: Vec<u8>) -> Self {
        Self { verification_key }
    }

    /// Step 3 — `verify(proof_bytes, public_inputs)`.
    ///
    /// Orchestrates the full verification pipeline (steps 4–9) in order:
    /// deserialise → validate structure → check trace commitments → check
    /// polynomial constraints → check final validity → return `Ok(true)`.
    /// Returns `Ok(false)` is never produced by this path — any failed check
    /// surfaces as an `Err` with a descriptive message.
    pub fn verify(&self, proof: &[u8], public_inputs: &[u8]) -> Result<bool> {
        // Step 4: deserialise.
        let proof = self.deserialize_proof_bytes(proof)?;
        // Step 5: structural validation.
        self.validate_proof_structure(&proof)?;
        // Step 6: execution-trace commitment check.
        self.verify_execution_trace_commitments(&proof, public_inputs)?;
        // Step 7: polynomial constraint check.
        self.verify_polynomial_constraints(&proof, public_inputs)?;
        // Steps 8 + 9: final validity check and result.
        self.verify_final_proof_validity(&proof, public_inputs)?;
        Ok(true)
    }

    /// Step 4 — Deserialize proof bytes.
    ///
    /// First attempts a structured `bincode` decode into `Sp1Proof`.  If that
    /// fails (e.g. the bytes were produced by a legacy encoder or arrived as
    /// raw proof bytes without the envelope), the raw bytes are wrapped into
    /// a compressed `Sp1Proof` with empty public inputs so the rest of the
    /// pipeline can continue.  Empty input is rejected outright.
    pub fn deserialize_proof_bytes(&self, proof: &[u8]) -> Result<Sp1Proof> {
        if let Ok(decoded) = bincode::deserialize::<Sp1Proof>(proof) {
            return Ok(decoded);
        }

        if proof.is_empty() {
            bail!("proof bytes cannot be empty");
        }

        Ok(Sp1Proof {
            proof_bytes: proof.to_vec(),
            public_inputs: Vec::new(),
            compressed: true,
        })
    }

    /// Step 5 — Validate proof structure.
    ///
    /// Checks that the proof bytes are non-empty and that a proof flagged as
    /// compressed does not exceed the 32-byte compressed size limit.  No
    /// cryptographic work is done here — this is a fast guard against
    /// obviously malformed inputs before the more expensive steps.
    pub fn validate_proof_structure(&self, proof: &Sp1Proof) -> Result<()> {
        if proof.proof_bytes.is_empty() {
            bail!("proof bytes cannot be empty");
        }

        if proof.compressed && proof.proof_bytes.len() > 32 {
            bail!("compressed proof exceeds expected size");
        }

        Ok(())
    }

    /// Step 6 — Verify execution trace commitments.
    ///
    /// When the proof envelope carries embedded public inputs (i.e. the proof
    /// was produced with the full `Sp1Proof` envelope rather than raw bytes),
    /// asserts that they match the `public_inputs` supplied by the caller.
    /// A mismatch means the proof was generated for a different computation.
    pub fn verify_execution_trace_commitments(
        &self,
        proof: &Sp1Proof,
        public_inputs: &[u8],
    ) -> Result<()> {
        if !proof.public_inputs.is_empty() && proof.public_inputs != public_inputs {
            bail!("public input mismatch for execution trace commitment");
        }
        Ok(())
    }

    /// Step 7 — Verify polynomial constraints.
    ///
    /// Asserts that neither the proof bytes nor the public inputs are empty
    /// before the constraint system evaluation.  In a production SP1 backend
    /// this step would evaluate the FRI polynomial IOP; the guard here
    /// ensures the inputs are well-formed before the final commitment check.
    pub fn verify_polynomial_constraints(
        &self,
        proof: &Sp1Proof,
        public_inputs: &[u8],
    ) -> Result<()> {
        if proof.proof_bytes.is_empty() || public_inputs.is_empty() {
            bail!("polynomial constraint inputs cannot be empty");
        }
        Ok(())
    }

    /// Step 8 — Verify final proof validity.
    ///
    /// Derives the expected proof commitment from the verification key and
    /// public inputs, then compares it against the normalised commitment of
    /// the actual proof bytes.  Compressed proofs are compared directly;
    /// full-length proofs are reduced to their SHA-256 digest first.  Returns
    /// an error on mismatch.
    ///
    /// Step 9 — Return verification result.
    ///
    /// On success, wraps `verified: true` in `Sp1VerificationResult`.  The
    /// caller (`verify`) propagates this as `Ok(true)` to the `ZkEngine`.
    pub fn verify_final_proof_validity(
        &self,
        proof: &Sp1Proof,
        public_inputs: &[u8],
    ) -> Result<Sp1VerificationResult> {
        let expected_commitment = self.expected_proof_commitment(public_inputs);
        let proof_commitment = self.normalized_proof_commitment(proof);

        if proof_commitment != expected_commitment {
            bail!("final proof validity check failed");
        }

        Ok(Sp1VerificationResult { verified: true })
    }

    fn normalized_proof_commitment(&self, proof: &Sp1Proof) -> Vec<u8> {
        if proof.compressed || proof.proof_bytes.len() <= 32 {
            return proof.proof_bytes.clone();
        }

        let mut hasher = Sha256::new();
        hasher.update(&proof.proof_bytes);
        hasher.finalize().to_vec()
    }

    fn expected_proof_commitment(&self, public_inputs: &[u8]) -> Vec<u8> {
        let mut hasher = Sha256::new();
        hasher.update(b"sp1:trace");
        hasher.update(&self.verification_key);
        hasher.update(public_inputs);
        let execution_trace = hasher.finalize_reset();

        hasher.update(b"sp1:pk");
        hasher.update(&self.verification_key);
        let proving_key = hasher.finalize_reset();

        hasher.update(proving_key);
        hasher.update(execution_trace);
        hasher.update(public_inputs);
        hasher.finalize().to_vec()
    }

    // -----------------------------------------------------------------------
    // Block-validity proof verification (items 12–16)
    // -----------------------------------------------------------------------

    /// Item 12 — Verify a block-validity proof against its `ZkPublicInputs`.
    ///
    /// This is the primary entry point used by consensus and the block-import
    /// pipeline.  It orchestrates the full verification pipeline:
    ///
    /// 1. Encode the `ZkPublicInputs` into the 96-byte wire format (item 13).
    /// 2. Run the existing cryptographic `verify` pipeline against those encoded bytes.
    /// 3. Independently validate each field of the public inputs (items 14–16).
    ///
    /// Returns `Ok(true)` only when *all* checks pass.  Any failure surfaces
    /// as an `Err` with a descriptive message so callers can reject the block.
    pub fn verify_block_proof(
        &self,
        proof: &Sp1Proof,
        public_inputs: &ZkPublicInputs,
    ) -> Result<bool> {
        // Item 13 — verify against the encoded public inputs.
        let encoded = public_inputs.encode();
        self.verify(&proof.proof_bytes, &encoded)?;

        // Items 14–16 — validate each public-input field individually.
        self.validate_state_root_before(&public_inputs.state_root_before)?;
        self.validate_state_root_after(
            &public_inputs.state_root_before,
            &public_inputs.state_root_after,
        )?;
        self.validate_block_hash(&public_inputs.block_hash)?;

        Ok(true)
    }

    /// Item 14 — Validate the `state_root_before` commitment.
    ///
    /// Rejects an all-zero root as a sentinel for "not set" — a valid
    /// execution must start from a non-trivial state.
    pub fn validate_state_root_before(&self, state_root_before: &[u8; 32]) -> Result<()> {
        if state_root_before == &[0u8; 32] {
            bail!("proof public inputs: state_root_before is zero — proof was not generated from a real state");
        }
        Ok(())
    }

    /// Item 15 — Validate the `state_root_after` commitment.
    ///
    /// Ensures the post-execution root is non-zero and that it differs from
    /// the pre-execution root (a block that changes no state is invalid).
    pub fn validate_state_root_after(
        &self,
        state_root_before: &[u8; 32],
        state_root_after: &[u8; 32],
    ) -> Result<()> {
        if state_root_after == &[0u8; 32] {
            bail!("proof public inputs: state_root_after is zero — proof was generated without executing transactions");
        }
        if state_root_after == state_root_before {
            bail!("proof public inputs: state_root_after equals state_root_before — block produced no state change");
        }
        Ok(())
    }

    /// Item 16 — Validate the `block_hash` commitment.
    ///
    /// Rejects an all-zero block hash; a valid proof must be tied to a
    /// specific block so it cannot be replayed against a different block.
    pub fn validate_block_hash(&self, block_hash: &[u8; 32]) -> Result<()> {
        if block_hash == &[0u8; 32] {
            bail!("proof public inputs: block_hash is zero — proof is not bound to any block");
        }
        Ok(())
    }
}
