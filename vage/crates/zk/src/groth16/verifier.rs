use anyhow::{anyhow, bail, Result};
use ark_bls12_381::{Bls12_381, Fr};
use ark_groth16::{Groth16, PreparedVerifyingKey, Proof};
use ark_serialize::CanonicalDeserialize;
use ark_snark::SNARK;

#[derive(Clone)]
pub struct Groth16Verifier {
    pub verifying_key: PreparedVerifyingKey<Bls12_381>,
}

impl Groth16Verifier {
    pub fn new(verifying_key: PreparedVerifyingKey<Bls12_381>) -> Self {
        Self { verifying_key }
    }

    pub fn deserialize_proof(&self, proof_bytes: &[u8]) -> Result<Proof<Bls12_381>> {
        if proof_bytes.is_empty() {
            bail!("proof bytes cannot be empty");
        }

        Proof::<Bls12_381>::deserialize_compressed(proof_bytes)
            .map_err(|e| anyhow!("Groth16 proof deserialization failed: {:?}", e))
    }

    pub fn verify_pairing_equations(
        &self,
        proof: &Proof<Bls12_381>,
        public_inputs: &[Fr],
    ) -> Result<bool> {
        Groth16::<Bls12_381>::verify_with_processed_vk(&self.verifying_key, public_inputs, proof)
            .map_err(|e| anyhow!("Groth16 pairing verification failed: {:?}", e))
    }

    pub fn verify_public_inputs(&self, public_inputs: &[Fr]) -> Result<()> {
        if public_inputs.is_empty() {
            bail!("public inputs cannot be empty");
        }
        Ok(())
    }

    pub fn verify(&self, proof: &Proof<Bls12_381>, public_inputs: &[Fr]) -> Result<bool> {
        self.verify_public_inputs(public_inputs)?;
        self.verify_pairing_equations(proof, public_inputs)
    }

    pub fn verify_serialized(&self, proof_bytes: &[u8], public_inputs: &[Fr]) -> Result<bool> {
        let proof = self.deserialize_proof(proof_bytes)?;
        self.verify(&proof, public_inputs)
    }

    pub fn batch_verify(
        &self,
        proofs: &[Proof<Bls12_381>],
        public_inputs: &[Vec<Fr>],
    ) -> Result<bool> {
        if proofs.len() != public_inputs.len() {
            bail!(
                "proof/public input length mismatch ({} != {})",
                proofs.len(),
                public_inputs.len()
            );
        }

        for (proof, inputs) in proofs.iter().zip(public_inputs.iter()) {
            if !self.verify(proof, inputs)? {
                return Ok(false);
            }
        }

        Ok(true)
    }
}
