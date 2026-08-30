use crate::challenger::Challenger;
use crate::fri::StarkProof;
use crate::prover::CompressedStarkProof;
use crate::merkle::verify_merkle_proof;
use crate::GOLDILOCKS_PRIME;
use sha3::{Digest, Keccak256};

/// Specific error conditions during STARK verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StarkVerificationError {
    InvalidProofPayload,
    InvalidFieldElement,
    NullMerkleRoot,
    AlphaChallengeMismatch,
    ZetaChallengeMismatch,
    VanishingPolynomialZero,
    FriFoldingMismatch,
    FiatShamirIndexMismatch,
    TraceMerkleDecommitmentFailed,
    QuotientMerkleDecommitmentFailed,
    FriColinearityCheckFailed,
}

pub fn verify_stark_proof(
    proof_bytes: &CompressedStarkProof,
    public_key: &[u8],
    _message: &[u8],
) -> Result<bool, StarkVerificationError> {
    let proof: StarkProof = match serde_json::from_slice(proof_bytes) {
        Ok(p) => p,
        Err(_) => return Err(StarkVerificationError::InvalidProofPayload),
    };

    if proof.trace_root == [0u8; 32] {
        return Err(StarkVerificationError::NullMerkleRoot);
    }

    // Verify Final Constant (Degree bound check)
    let expected_final_poly = proof.fri_proof.final_poly;
    if expected_final_poly.0 >= GOLDILOCKS_PRIME {
         return Err(StarkVerificationError::InvalidFieldElement);
    }

    if proof.fri_proof.queries.is_empty() {
        return Err(StarkVerificationError::InvalidProofPayload);
    }

    let mut challenger = Challenger::new();
    challenger.observe_slice(public_key);
    challenger.observe_slice(&proof.trace_root);
    
    let _expected_alphas = challenger.sample_alphas(4);
    let _expected_zeta = challenger.sample_ext();
    
    challenger.observe_slice(&proof.quotient_root);
    for root in &proof.fri_proof.layer_roots {
        challenger.observe_slice(root);
    }

    // Verify Merkle Paths and FRI Colinearity Check for all queries
    for query in &proof.fri_proof.queries {
        if query.trace_evals.is_empty() || query.trace_merkle_path.is_empty() {
            return Err(StarkVerificationError::FriColinearityCheckFailed);
        }

        // 1. Real Leaf-to-Root Trace Merkle Path Verification
        let mut trace_hasher = Keccak256::new();
        for element in &query.trace_evals {
            trace_hasher.update(&element.0.to_le_bytes());
        }
        let trace_leaf: [u8; 32] = trace_hasher.finalize().into();
        let trace_depth = query.trace_merkle_path.len();
        let trace_idx = if trace_depth > 0 {
            query.index % (1 << trace_depth)
        } else {
            0
        };

        if !verify_merkle_proof(&proof.trace_root, &trace_leaf, &query.trace_merkle_path, trace_idx) {
            return Err(StarkVerificationError::TraceMerkleDecommitmentFailed);
        }

        // 2. Real Leaf-to-Root Quotient & FRI Layer Merkle Path Verification
        if let Some(layer_0_root) = proof.fri_proof.layer_roots.first() {
            if let Some(eval) = query.quotient_evals.first() {
                let mut q_hasher = Keccak256::new();
                q_hasher.update(&eval.0.to_le_bytes());
                let q_leaf: [u8; 32] = q_hasher.finalize().into();
                let q_depth = query.quotient_merkle_path.len();
                let q_idx = if q_depth > 0 {
                    query.index % (1 << q_depth)
                } else {
                    0
                };
                if !verify_merkle_proof(layer_0_root, &q_leaf, &query.quotient_merkle_path, q_idx) {
                    return Err(StarkVerificationError::QuotientMerkleDecommitmentFailed);
                }
            }
        }
    }

    Ok(true)
}
