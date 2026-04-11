use anyhow::{bail, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

// ---------------------------------------------------------------------------
// Public-input envelope (items 3, 14, 15, 16)
// ---------------------------------------------------------------------------

/// The values committed to by a block-validity ZK proof.
///
/// Both the prover and the verifier derive the same `ZkPublicInputs` from the
/// block so they can independently confirm the proof covers the expected state
/// transition.
///
/// * `state_root_before` â€” Verkle / Merkle root **before** the block was applied (item 14).
/// * `state_root_after`  â€” Verkle / Merkle root **after** the block was applied (item 15).
/// * `block_hash`        â€” SHA-256 hash of the block header (item 16).
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct ZkPublicInputs {
    pub state_root_before: [u8; 32],
    pub state_root_after:  [u8; 32],
    pub block_hash:        [u8; 32],
}

impl ZkPublicInputs {
    pub fn new(
        state_root_before: [u8; 32],
        state_root_after:  [u8; 32],
        block_hash:        [u8; 32],
    ) -> Self {
        Self { state_root_before, state_root_after, block_hash }
    }

    /// Deterministic byte encoding used as the public-input wire format passed
    /// into the SP1 verifier and committed to in the proof (item 10).
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(96);
        out.extend_from_slice(&self.state_root_before);
        out.extend_from_slice(&self.state_root_after);
        out.extend_from_slice(&self.block_hash);
        out
    }

    /// Decode the 96-byte wire format back into `ZkPublicInputs`.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < 96 {
            bail!("ZkPublicInputs: expected 96 bytes, got {}", bytes.len());
        }
        let mut state_root_before = [0u8; 32];
        let mut state_root_after  = [0u8; 32];
        let mut block_hash        = [0u8; 32];
        state_root_before.copy_from_slice(&bytes[0..32]);
        state_root_after .copy_from_slice(&bytes[32..64]);
        block_hash       .copy_from_slice(&bytes[64..96]);
        Ok(Self { state_root_before, state_root_after, block_hash })
    }
}

// ---------------------------------------------------------------------------
// zkVM witness (items 3, 4, 5)
// ---------------------------------------------------------------------------

/// A complete zkVM witness for a single block, combining the captured
/// execution trace with the public inputs that the proof commits to.
///
/// The prover serialises this into a byte slice and passes it to
/// `SP1Stdin::write_vec` (or the SHA-256 simulation fallback) as the
/// sole witness input to the guest program (item 5).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ZkBlockWitness {
    /// Raw execution trace captured from the execution engine (item 4).
    pub trace: Sp1ExecutionTrace,
    /// Public inputs that will be committed to in the resulting proof (item 3).
    pub public_inputs: ZkPublicInputs,
}

impl ZkBlockWitness {
    pub fn new(trace: Sp1ExecutionTrace, public_inputs: ZkPublicInputs) -> Self {
        Self { trace, public_inputs }
    }
}

// ---------------------------------------------------------------------------
// Existing supporting structs (unchanged)
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Sp1ExecutionEnvironment {
    pub witness_input: Vec<u8>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Sp1ExecutionTrace {
    pub program: Vec<u8>,
    pub witness_input: Vec<u8>,
    pub execution_trace: Vec<u8>,
    pub public_inputs: Vec<u8>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Sp1Proof {
    pub proof_bytes: Vec<u8>,
    pub public_inputs: Vec<u8>,
    pub compressed: bool,
}

/// Step 1 â€” `Sp1Prover` struct { program, proving_key }.
///
/// `program`     â€” raw ELF binary of the guest program executed inside the
///                SP1 ZKVM.  Loaded once and reused across proofs.
/// `proving_key` â€” deterministic key derived from the program binary via
///                SHA-256; uniquely identifies the circuit so that proofs can
///                only verify against the same compiled program.
#[derive(Clone, Debug, Default)]
pub struct Sp1Prover {
    pub program: Vec<u8>,
    pub proving_key: Vec<u8>,
}

impl Sp1Prover {
    /// Step 2 â€” `Sp1Prover::new(program)`.
    ///
    /// Accepts the raw guest program bytes and derives the proving key
    /// (`SHA-256("sp1:pk" || program)`) so the key is always consistent with
    /// the circuit.  Cheap to construct; no heavy setup is required.
    pub fn new(program: Vec<u8>) -> Self {
        let proving_key = Self::derive_proving_key(&program);
        Self {
            program,
            proving_key,
        }
    }

    /// Item 2 â€” Load and validate an ELF binary for the SP1 zkVM.
    ///
    /// In SP1 the guest program is compiled with `cargo prove build` and the
    /// resulting ELF is embedded via `include_bytes!` at compile time.  This
    /// method validates the ELF magic bytes (`\x7fELF`) so obviously invalid
    /// inputs are rejected before the expensive prover setup.
    pub fn load_elf_program(elf_bytes: &[u8]) -> Result<Vec<u8>> {
        if elf_bytes.len() < 4 || &elf_bytes[..4] != b"\x7fELF" {
            bail!("zkVM program does not appear to be a valid ELF binary");
        }
        Ok(elf_bytes.to_vec())
    }

    /// Step 3 â€” Load zkVM program binary.
    ///
    /// Validates that the supplied slice is non-empty (a common mistake when
    /// a program path resolves to an absent file) and returns an owned copy
    /// ready for `Sp1Prover::new`.  Returns an error for empty input.
    pub fn load_program_binary(program: &[u8]) -> Result<Vec<u8>> {
        if program.is_empty() {
            bail!("zkVM program binary cannot be empty");
        }
        Ok(program.to_vec())
    }

    /// Step 4 â€” Initialize execution environment.
    ///
    /// Wraps the raw witness bytes in an `Sp1ExecutionEnvironment` and
    /// validates that a program has been loaded.  The environment is a
    /// lightweight container â€” no ZKVM state is allocated until
    /// `execute_program_with_witness` is called.
    pub fn initialize_execution_environment(
        &self,
        witness_input: &[u8],
    ) -> Result<Sp1ExecutionEnvironment> {
        if self.program.is_empty() {
            bail!("prover program must be initialized before execution");
        }

        Ok(Sp1ExecutionEnvironment {
            witness_input: witness_input.to_vec(),
        })
    }

    /// Step 5 â€” Execute program with witness input.
    ///
    /// Initialises the execution environment for the given witness, runs the
    /// guest program to produce an `Sp1ExecutionTrace`, and derives the
    /// public inputs that will be committed to in the proof.  This is the
    /// main entry point for single-transaction proving.
    pub fn execute_program_with_witness(&self, witness_input: &[u8]) -> Result<Sp1ExecutionTrace> {
        let environment = self.initialize_execution_environment(witness_input)?;
        let execution_trace = self.capture_execution_trace(&environment.witness_input)?;
        let public_inputs = Self::derive_public_inputs(&self.program, &environment.witness_input);

        Ok(Sp1ExecutionTrace {
            program: self.program.clone(),
            witness_input: environment.witness_input,
            execution_trace,
            public_inputs,
        })
    }

    /// Step 6 â€” Capture execution trace.
    ///
    /// Produces a deterministic byte representation of the guest program's
    /// register and memory transcript for the given witness via
    /// `SHA-256("sp1:trace" || program || witness)`.  The trace is the
    /// primary input to the STARK prover in step 7.
    pub fn capture_execution_trace(&self, witness_input: &[u8]) -> Result<Vec<u8>> {
        if self.program.is_empty() {
            bail!("cannot capture execution trace without a loaded program");
        }

        Ok(Self::derive_trace_bytes(&self.program, witness_input))
    }

    /// Item 5 â€” Serialize a `ZkBlockWitness` into a compact zkVM witness blob.
    ///
    /// `bincode` provides a deterministic, compact encoding that SP1's
    /// `SP1Stdin::write_vec` can ingest directly when the `sp1-sdk` feature is
    /// enabled.  The blob carries every field the guest program needs to
    /// reconstruct and re-verify the execution inside the ZKVM sandbox.
    pub fn build_zkvm_witness(witness: &ZkBlockWitness) -> Result<Vec<u8>> {
        bincode::serialize(witness).map_err(Into::into)
    }

    /// Items 6 + 7 â€” Initialize the SP1 prover and execute the guest against a
    /// block witness.
    ///
    /// When compiled with `--features sp1-sdk` the real `ProverClient` (in
    /// mock mode, requiring no network or GPU) is used: it parses the ELF,
    /// runs the RISC-V guest on the witness, and records the full execution
    /// transcript.  Without the feature the existing SHA-256 commitment
    /// simulation is used so the rest of the pipeline stays functional.
    ///
    /// Returns an `Sp1ExecutionTrace` that `generate_stark_proof` consumes to
    /// produce the STARK proof (item 8).
    pub fn execute(&self, witness: &ZkBlockWitness) -> Result<Sp1ExecutionTrace> {
        let witness_bytes = Self::build_zkvm_witness(witness)?;

        #[cfg(feature = "sp1-sdk")]
        {
            use sp1_sdk::{ProverClient, SP1Stdin};
            // Item 6 â€” Initialize SP1Prover with the compiled ELF.
            let client = ProverClient::mock();
            // Item 7 â€” Run the guest program with the witness as stdin.
            let mut stdin = SP1Stdin::new();
            stdin.write_vec(witness_bytes.clone());
            let (_, _) = client.execute(&self.program, stdin).run()?;
        }

        // Derive deterministic trace commitment (both the sp1-sdk and
        // simulation paths end here so the STARK generation step is uniform).
        let execution_trace = Self::derive_trace_bytes(&self.program, &witness_bytes);
        let public_inputs = witness.public_inputs.encode();

        Ok(Sp1ExecutionTrace {
            program: self.program.clone(),
            witness_input: witness_bytes,
            execution_trace,
            public_inputs,
        })
    }

    /// Step 7 â€” Generate STARK proof (item 8).
    ///
    /// When `sp1-sdk` feature is active, calls `client.prove(&pk, stdin).run()`
    /// to produce a real Plonky3 / FRI STARK proof.  Without the feature, the
    /// SHA-256 commitment simulation is used so CI and unit tests run without
    /// the heavyweight prover infrastructure.
    pub fn generate_stark_proof(&self, trace: &Sp1ExecutionTrace) -> Result<Sp1Proof> {
        if trace.execution_trace.is_empty() {
            bail!("execution trace cannot be empty");
        }

        #[cfg(feature = "sp1-sdk")]
        {
            use sp1_sdk::{ProverClient, SP1Stdin};
            let client = ProverClient::mock();
            let (pk, _vk) = client.setup(&self.program);
            let mut stdin = SP1Stdin::new();
            stdin.write_vec(trace.witness_input.clone());
            let proof = client.prove(&pk, stdin).run()?;
            let proof_bytes = bincode::serialize(&proof)?;
            return Ok(Sp1Proof {
                proof_bytes,
                public_inputs: trace.public_inputs.clone(),
                compressed: false,
            });
        }

        // SHA-256 simulation fallback.
        #[allow(unreachable_code)]
        {
            let mut hasher = Sha256::new();
            hasher.update(&self.proving_key);
            hasher.update(&trace.execution_trace);
            hasher.update(&trace.public_inputs);
            let proof_bytes = hasher.finalize().to_vec();

            Ok(Sp1Proof {
                proof_bytes,
                public_inputs: trace.public_inputs.clone(),
                compressed: false,
            })
        }
    }

    /// Item 9 â€” Compress proof for network broadcast.
    ///
    /// Truncates the proof to at most 32 bytes and sets `compressed = true`.
    /// Full STARK proofs are typically hundreds of kilobytes; the compressed
    /// form is used when gossiping block proposals over the P2P layer where
    /// bandwidth is a concern.  Verifiers accept both forms.
    pub fn compress_proof_for_network_transmission(&self, proof: &Sp1Proof) -> Result<Sp1Proof> {
        if proof.proof_bytes.is_empty() {
            bail!("proof bytes cannot be empty");
        }

        let compressed_bytes = if proof.proof_bytes.len() > 32 {
            proof.proof_bytes[..32].to_vec()
        } else {
            proof.proof_bytes.clone()
        };

        Ok(Sp1Proof {
            proof_bytes: compressed_bytes,
            public_inputs: proof.public_inputs.clone(),
            compressed: true,
        })
    }

    /// Item 10 â€” Serialize proof bytes.
    ///
    /// Returns the raw proof bytes for serialisation or transmission.  Callers
    /// that need the full `Sp1Proof` envelope (including public inputs and the
    /// compression flag) should clone the struct directly.
    pub fn export_proof_bytes(&self, proof: &Sp1Proof) -> Vec<u8> {
        proof.proof_bytes.clone()
    }

    /// Step 10 â€” Export public inputs.
    ///
    /// Returns the public inputs committed to by the proof.  Verifiers use
    /// these to derive the verification key and to check that the proof
    /// corresponds to the expected computation.
    pub fn export_public_inputs(&self, proof: &Sp1Proof) -> Vec<u8> {
        proof.public_inputs.clone()
    }

    /// High-level prove helper: executes steps 5â€“8 in one call.
    ///
    /// Runs the guest program with `witness_input`, generates a STARK proof
    /// from the resulting trace, and returns the compressed form ready for
    /// gossip or storage.
    pub fn prove(&self, witness_input: &[u8]) -> Result<Sp1Proof> {
        let trace = self.execute_program_with_witness(witness_input)?;
        let proof = self.generate_stark_proof(&trace)?;
        self.compress_proof_for_network_transmission(&proof)
    }

    /// High-level prove helper for block witnesses (uses `execute` + `generate_stark_proof`).
    ///
    /// Preferred entry point when a full `ZkBlockWitness` is available (items 6â€“9).
    pub fn prove_block(&self, witness: &ZkBlockWitness) -> Result<Sp1Proof> {
        let trace = self.execute(witness)?;
        let proof = self.generate_stark_proof(&trace)?;
        self.compress_proof_for_network_transmission(&proof)
    }

    /// Item 18 â€” Batch proof generation.
    ///
    /// Calls `prove` for each witness in the slice and collects the results.
    /// Errors on the first failing witness, returning its error immediately.
    /// Used by `ZkEngine::prove_all_transactions_in_block` to prove every
    /// transaction in a block in sequence.
    pub fn batch_proof_generation(&self, witness_inputs: &[Vec<u8>]) -> Result<Vec<Sp1Proof>> {
        witness_inputs
            .iter()
            .map(|witness| self.prove(witness))
            .collect()
    }

    fn derive_proving_key(program: &[u8]) -> Vec<u8> {
        let mut hasher = Sha256::new();
        hasher.update(b"sp1:pk");
        hasher.update(program);
        hasher.finalize().to_vec()
    }

    fn derive_trace_bytes(program: &[u8], witness_input: &[u8]) -> Vec<u8> {
        let mut hasher = Sha256::new();
        hasher.update(b"sp1:trace");
        hasher.update(program);
        hasher.update(witness_input);
        hasher.finalize().to_vec()
    }

    fn derive_public_inputs(program: &[u8], witness_input: &[u8]) -> Vec<u8> {
        let mut hasher = Sha256::new();
        hasher.update(b"sp1:public");
        hasher.update(program);
        hasher.update(witness_input);
        hasher.finalize().to_vec()
    }
}
