use anyhow::{bail, Result};
use ark_bls12_381::{Bls12_381, Fr, G1Affine, G1Projective, G2Affine, G2Projective};
use ark_ec::{pairing::Pairing, Group};
use ark_ff::{PrimeField, UniformRand, Zero};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct BlsPublicKey(pub Vec<u8>); // Compressed G1

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct BlsPrivateKey(pub Vec<u8>); // Field element Fr

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct BlsSignature(pub Vec<u8>); // Compressed G2

impl BlsPublicKey {
    pub fn from_g1(g1: &G1Projective) -> Self {
        let mut bytes = Vec::new();
        g1.serialize_compressed(&mut bytes)
            .expect("G1Projective serialization to compressed bytes should never fail");
        Self(bytes)
    }

    pub fn to_g1(&self) -> Result<G1Projective> {
        if self.0.len() != G1Affine::default().compressed_size() {
            bail!("Invalid BLS G1 public key length: {}", self.0.len());
        }
        let pk = G1Projective::deserialize_compressed(&self.0[..])
            .map_err(|e| anyhow::anyhow!("Invalid BLS G1 public key format: {:?}", e))?;
        // Security check: ensure public key is not the identity point (zero)
        if pk.is_zero() {
            bail!("BLS Public Key cannot be the identity point");
        }
        Ok(pk)
    }

    pub fn encode_storage(&self) -> Vec<u8> {
        bincode::serialize(self).expect("BLS public key storage serialization should succeed")
    }
}

impl BlsPrivateKey {
    pub fn encode_storage(&self) -> Vec<u8> {
        bincode::serialize(self).expect("BLS private key storage serialization should succeed")
    }
}

impl BlsSignature {
    pub fn from_g2(g2: &G2Projective) -> Self {
        let mut bytes = Vec::new();
        g2.serialize_compressed(&mut bytes)
            .expect("G2Projective serialization to compressed bytes should never fail");
        Self(bytes)
    }

    pub fn to_g2(&self) -> Result<G2Projective> {
        if self.0.len() != G2Affine::default().compressed_size() {
            bail!("Invalid BLS G2 signature length: {}", self.0.len());
        }
        let sig = G2Projective::deserialize_compressed(&self.0[..])
            .map_err(|e| anyhow::anyhow!("Invalid BLS G2 signature: {:?}", e))?;
        if sig.is_zero() {
            bail!("BLS signature cannot be the identity point");
        }
        Ok(sig)
    }

    pub fn encode_storage(&self) -> Vec<u8> {
        bincode::serialize(self).expect("BLS signature storage serialization should succeed")
    }
}

/// Generate a new BLS keypair (G1 public key, Fr private key).
pub fn bls_generate_keypair() -> (BlsPrivateKey, BlsPublicKey) {
    let mut rng = OsRng;
    let sk = Fr::rand(&mut rng);
    let pk = G1Projective::generator() * sk;

    let mut sk_bytes = Vec::new();
    sk.serialize_compressed(&mut sk_bytes)
        .expect("Fr field element serialization to compressed bytes should never fail");

    (BlsPrivateKey(sk_bytes), BlsPublicKey::from_g1(&pk))
}

/// Sign a message using a BLS private key (returns compressed G2 signature).
pub fn bls_sign(sk_bytes: &BlsPrivateKey, message: &[u8]) -> Result<BlsSignature> {
    let sk = Fr::deserialize_compressed(&sk_bytes.0[..])
        .map_err(|e| anyhow::anyhow!("Invalid BLS private key: {:?}", e))?;
    // Hash message to G2 for signing
    let h = hash_to_g2(message);
    let sig = h * sk;
    Ok(BlsSignature::from_g2(&sig))
}

/// Verify a single BLS signature against a public key and message.
pub fn bls_verify(pk_bytes: &BlsPublicKey, message: &[u8], sig_bytes: &BlsSignature) -> bool {
    let pk = match pk_bytes.to_g1() {
        Ok(p) => p,
        Err(_) => return false,
    };
    let sig = match sig_bytes.to_g2() {
        Ok(s) => s,
        Err(_) => return false,
    };
    let h = hash_to_g2(message);

    // Check e(PK, H(m)) == e(G1, sig)
    let p1 = Bls12_381::pairing(pk, h);
    let p2 = Bls12_381::pairing(G1Projective::generator(), sig);
    p1 == p2
}

/// Aggregate multiple BLS signatures into a single signature.
pub fn aggregate_signatures(sigs: &[BlsSignature]) -> Result<BlsSignature> {
    if sigs.is_empty() {
        bail!("Empty signature list for aggregation");
    }
    let mut agg = G2Projective::default(); // Identity
    for s_bytes in sigs {
        agg += s_bytes.to_g2()?;
    }
    Ok(BlsSignature::from_g2(&agg))
}

/// Aggregate multiple BLS public keys into a single public key.
pub fn aggregate_public_keys(pks: &[BlsPublicKey]) -> Result<BlsPublicKey> {
    if pks.is_empty() {
        bail!("Empty public key list for aggregation");
    }
    let mut agg = G1Projective::default();
    for pk_bytes in pks {
        agg += pk_bytes.to_g1()?;
    }
    Ok(BlsPublicKey::from_g1(&agg))
}

/// Verify an aggregated BLS signature against an aggregated public key and the original message.
pub fn verify_aggregate_signature(
    agg_pk: &BlsPublicKey,
    message: &[u8],
    agg_sig: &BlsSignature,
) -> bool {
    bls_verify(agg_pk, message, agg_sig)
}

/// NOTE: Fixed hash-to-G2 function for pedagogical and system consistency.
/// In production, use SWU map or similar secure map-to-curve.
fn hash_to_g2(message: &[u8]) -> G2Projective {
    // Apply domain separation to the message before hashing to the curve
    let d_hash = crate::hash::domain_hash(crate::hash::DOMAIN_CONSENSUS, message);

    G2Projective::generator() * Fr::from_be_bytes_mod_order(&d_hash)
}

/// Calculate a domain-separated hash for consensus messages (voting/proposals).
pub fn consensus_message_hash(data: &[u8]) -> crate::hash::Hash {
    crate::hash::domain_hash(crate::hash::DOMAIN_CONSENSUS, data)
}

// --- Specialized Consensus Voting Methods ---

/// Sign a consensus vote (typically a block hash) using a validator's BLS private key.
pub fn sign_vote(sk: &BlsPrivateKey, block_hash: &[u8]) -> Result<BlsSignature> {
    bls_sign(sk, block_hash)
}

pub fn validator_vote_signature(sk: &BlsPrivateKey, block_hash: &[u8]) -> Result<BlsSignature> {
    sign_vote(sk, block_hash)
}

/// Verify a single validator's vote signature against their public key and the voted block hash.
pub fn verify_vote_signature(pk: &BlsPublicKey, block_hash: &[u8], sig: &BlsSignature) -> bool {
    bls_verify(pk, block_hash, sig)
}

/// Aggregate multiple validator votes into a single aggregated BLS signature.
pub fn aggregate_votes(votes: &[BlsSignature]) -> Result<BlsSignature> {
    aggregate_signatures(votes)
}

/// Verify a Quorum Certificate (QC) signature against the aggregated public key of the committee.
pub fn verify_quorum_certificate(
    agg_pk: &BlsPublicKey,
    block_hash: &[u8],
    agg_sig: &BlsSignature,
) -> bool {
    verify_aggregate_signature(agg_pk, block_hash, agg_sig)
}

/// High-performance batch verification of multiple (PK, message, signature) triples.
/// Uses random linear combinations to verify all signatures in O(1) pairing operations on the signature side.
pub fn batch_signature_verification(
    pks: &[BlsPublicKey],
    messages: &[&[u8]],
    sigs: &[BlsSignature],
) -> bool {
    if pks.len() != messages.len() || pks.len() != sigs.len() || pks.is_empty() {
        return false;
    }

    let mut combined_sig = G2Projective::default();
    let mut left_points: Vec<G1Affine> = Vec::with_capacity(pks.len());
    let mut right_points: Vec<G2Affine> = Vec::with_capacity(pks.len());
    let mut rng = OsRng;

    for i in 0..pks.len() {
        let pk = match pks[i].to_g1() {
            Ok(p) => p,
            Err(_) => return false,
        };
        let sig = match sigs[i].to_g2() {
            Ok(s) => s,
            Err(_) => return false,
        };
        let h = hash_to_g2(messages[i]);

        // Use a random scalar r_i for security against cancellation/rogue-key attacks
        let r = Fr::rand(&mut rng);

        combined_sig += sig * r;
        left_points.push((pk * r).into());
        right_points.push(h.into());
    }

    // Check e(G1, CombinedSig) == Product of e(PK_i*r_i, H(m_i))
    let p_left = Bls12_381::pairing(G1Projective::generator(), combined_sig);
    let p_right = Bls12_381::multi_pairing(left_points.iter(), right_points.iter());

    p_left == p_right
}

pub fn fuzz_target_bls_verification(public_key: &[u8], message: &[u8], signature: &[u8]) {
    let _ = bls_verify(
        &BlsPublicKey(public_key.to_vec()),
        message,
        &BlsSignature(signature.to_vec()),
    );
}

#[cfg(test)]
mod tests {
    use super::{
        aggregate_public_keys, aggregate_signatures, aggregate_votes, batch_signature_verification,
        bls_generate_keypair, bls_sign, bls_verify, consensus_message_hash, sign_vote,
        validator_vote_signature, verify_aggregate_signature, verify_quorum_certificate,
        verify_vote_signature,
    };
    use super::{BlsPublicKey, BlsSignature};
    use ark_bls12_381::{G1Affine, G2Affine};
    use ark_serialize::CanonicalSerialize;

    #[test]
    fn generated_bls_keypair_signs_and_verifies() {
        let (private_key, public_key) = bls_generate_keypair();
        let message = b"vage-bls";
        let signature = bls_sign(&private_key, message).expect("bls signing should succeed");

        assert!(bls_verify(&public_key, message, &signature));
    }

    #[test]
    fn aggregate_signature_and_public_key_verify() {
        let (sk1, pk1) = bls_generate_keypair();
        let (sk2, pk2) = bls_generate_keypair();
        let message = b"qc-message";

        let sig1 = bls_sign(&sk1, message).expect("signature one should succeed");
        let sig2 = bls_sign(&sk2, message).expect("signature two should succeed");
        let agg_sig = aggregate_signatures(&[sig1.clone(), sig2.clone()])
            .expect("signature aggregation should succeed");
        let agg_pk = aggregate_public_keys(&[pk1.clone(), pk2.clone()])
            .expect("public key aggregation should succeed");

        assert!(verify_aggregate_signature(&agg_pk, message, &agg_sig));
        assert!(verify_quorum_certificate(&agg_pk, message, &agg_sig));
        assert_eq!(
            aggregate_votes(&[sig1, sig2]).expect("vote aggregation should succeed"),
            agg_sig
        );
    }

    #[test]
    fn batch_verification_accepts_valid_signatures() {
        let (sk1, pk1) = bls_generate_keypair();
        let (sk2, pk2) = bls_generate_keypair();
        let message_one = b"vote-one";
        let message_two = b"vote-two";
        let sig1 = bls_sign(&sk1, message_one).expect("signature one should succeed");
        let sig2 = bls_sign(&sk2, message_two).expect("signature two should succeed");

        assert!(batch_signature_verification(
            &[pk1, pk2],
            &[message_one.as_slice(), message_two.as_slice()],
            &[sig1, sig2],
        ));
    }

    #[test]
    fn batch_verification_rejects_mismatched_message() {
        let (sk1, pk1) = bls_generate_keypair();
        let (sk2, pk2) = bls_generate_keypair();
        let message_one = b"vote-one";
        let message_two = b"vote-two";
        let sig1 = bls_sign(&sk1, message_one).expect("signature one should succeed");
        let sig2 = bls_sign(&sk2, message_two).expect("signature two should succeed");

        assert!(!batch_signature_verification(
            &[pk1, pk2],
            &[message_one.as_slice(), b"tampered".as_slice()],
            &[sig1, sig2],
        ));
    }

    #[test]
    fn vote_signature_helpers_and_consensus_hash_work() {
        let (private_key, public_key) = bls_generate_keypair();
        let block_hash = consensus_message_hash(b"block");
        let vote_signature = validator_vote_signature(&private_key, &block_hash)
            .expect("vote signing should succeed");

        assert!(verify_vote_signature(
            &public_key,
            &block_hash,
            &vote_signature
        ));
        assert_eq!(
            consensus_message_hash(b"block"),
            consensus_message_hash(b"block")
        );
    }

    #[test]
    fn direct_vote_helper_api_round_trips() {
        let (sk1, pk1) = bls_generate_keypair();
        let (sk2, pk2) = bls_generate_keypair();
        let message = consensus_message_hash(b"prepare-vote");
        let sig1 = sign_vote(&sk1, &message).expect("first vote signature should succeed");
        let sig2 = sign_vote(&sk2, &message).expect("second vote signature should succeed");
        let aggregate_public_key = aggregate_public_keys(&[pk1.clone(), pk2.clone()])
            .expect("public key aggregation should succeed");
        let aggregate_signature = aggregate_votes(&[sig1.clone(), sig2.clone()])
            .expect("vote aggregation should succeed");

        assert!(verify_vote_signature(&pk1, &message, &sig1));
        assert!(verify_vote_signature(&pk2, &message, &sig2));
        assert!(verify_quorum_certificate(
            &aggregate_public_key,
            &message,
            &aggregate_signature,
        ));
    }

    #[test]
    fn storage_serialization_round_trips() {
        let (private_key, public_key) = bls_generate_keypair();
        let signature = bls_sign(&private_key, b"storage").expect("signature should succeed");

        let decoded_public_key =
            bincode::deserialize::<super::BlsPublicKey>(&public_key.encode_storage())
                .expect("public key deserialization should succeed");
        let decoded_private_key =
            bincode::deserialize::<super::BlsPrivateKey>(&private_key.encode_storage())
                .expect("private key deserialization should succeed");
        let decoded_signature =
            bincode::deserialize::<super::BlsSignature>(&signature.encode_storage())
                .expect("signature deserialization should succeed");

        assert_eq!(decoded_public_key, public_key);
        assert_eq!(decoded_private_key, private_key);
        assert_eq!(decoded_signature, signature);
    }

    #[test]
    fn invalid_public_key_and_signature_points_are_rejected() {
        assert!(
            BlsPublicKey(vec![0u8; G1Affine::default().compressed_size()])
                .to_g1()
                .is_err()
        );
        assert!(
            BlsSignature(vec![0u8; G2Affine::default().compressed_size()])
                .to_g2()
                .is_err()
        );
        assert!(BlsPublicKey(vec![1u8; 7]).to_g1().is_err());
        assert!(BlsSignature(vec![1u8; 7]).to_g2().is_err());
    }
}
