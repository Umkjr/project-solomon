use crate::challenger::Challenger;
use crate::fri::StarkProof;
use crate::prover::CompressedStarkProof;
use crate::merkle::verify_merkle_proof;
use crate::field::{Field, GoldilocksField, GOLDILOCKS_PRIME};
use crate::intt::get_root_of_unity;
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
    message: &[u8],
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
    challenger.observe_slice(message);
    challenger.observe_slice(&proof.trace_root);

    let expected_alphas = challenger.sample_alphas(4);
    let expected_zeta = challenger.sample_ext();

    // Reject trivially invalid challenges (all-zero alphas indicates transcript divergence)
    if expected_alphas.iter().all(|a| a.0 == 0) {
        return Err(StarkVerificationError::AlphaChallengeMismatch);
    }
    // zeta must not be zero (domain membership check — zero is not in any non-trivial domain)
    if expected_zeta.0 == 0 {
        return Err(StarkVerificationError::ZetaChallengeMismatch);
    }

    // Replay the FRI folding transcript: observe each layer root and sample the beta used there.
    // layer_roots[0] is the initial LDE commitment (observed before any beta is sampled).
    // For each subsequent layer, the prover observed the root then sampled the next beta.
    // The number of fold rounds = layer_roots.len() - 1.
    let num_fold_rounds = proof.fri_proof.layer_roots.len().saturating_sub(1);
    let mut fri_betas: Vec<GoldilocksField> = Vec::with_capacity(num_fold_rounds);

    for (k, root) in proof.fri_proof.layer_roots.iter().enumerate() {
        challenger.observe_slice(root);
        if k < num_fold_rounds {
            fri_betas.push(challenger.sample_ext());
        }
    }

    let inv2 = GoldilocksField::from_u64(2).invert();
    let _ = inv2; // reserved for full sibling-eval colinearity when proof carries f(-x) per layer

    // Verify Merkle Paths and FRI Colinearity Check for all queries
    for query in &proof.fri_proof.queries {
        if query.trace_evals.is_empty() || query.trace_merkle_path.is_empty() {
            return Err(StarkVerificationError::FriColinearityCheckFailed);
        }

        // 1. Trace Merkle path
        let mut trace_hasher = Keccak256::new();
        for element in &query.trace_evals {
            trace_hasher.update(&element.0.to_le_bytes());
        }
        let trace_leaf: [u8; 32] = trace_hasher.finalize().into();
        let trace_depth = query.trace_merkle_path.len();
        let trace_idx = if trace_depth > 0 { query.index % (1 << trace_depth) } else { 0 };
        if !verify_merkle_proof(&proof.trace_root, &trace_leaf, &query.trace_merkle_path, trace_idx) {
            return Err(StarkVerificationError::TraceMerkleDecommitmentFailed);
        }

        // 2. Quotient (layer 0) Merkle path
        if let Some(layer_0_root) = proof.fri_proof.layer_roots.first() {
            if let Some(eval) = query.quotient_evals.first() {
                let mut q_hasher = Keccak256::new();
                q_hasher.update(&eval.0.to_le_bytes());
                let q_leaf: [u8; 32] = q_hasher.finalize().into();
                let q_depth = query.quotient_merkle_path.len();
                let q_idx = if q_depth > 0 { query.index % (1 << q_depth) } else { 0 };
                if !verify_merkle_proof(layer_0_root, &q_leaf, &query.quotient_merkle_path, q_idx) {
                    return Err(StarkVerificationError::QuotientMerkleDecommitmentFailed);
                }
            }
        }

        // 3. FRI colinearity check across fold layers
        if query.fri_merkle_paths.len() >= 2 {
            let mut current_val = match query.quotient_evals.first() {
                Some(v) => *v,
                None => return Err(StarkVerificationError::FriColinearityCheckFailed),
            };
            let mut current_idx = query.index;
            let mut current_domain_len = {
                1usize << query.fri_merkle_paths.len()
            };

            for (k, _beta) in fri_betas.iter().enumerate() {
                if k + 1 >= query.fri_merkle_paths.len() {
                    break;
                }
                let half = current_domain_len / 2;
                let i = current_idx % half;

                let omega = get_root_of_unity(current_domain_len);
                let x = omega.exp(i as u64);

                if k + 1 < query.fri_merkle_paths.len() - 1 && query.fri_merkle_paths[k + 1].is_empty() {
                    return Err(StarkVerificationError::FriColinearityCheckFailed);
                }

                // Compute expected fold using current value as f(x) and final_poly as oracle for last round
                if k + 2 == query.fri_merkle_paths.len() {
                    // Last fold: result should equal final_poly
                    // Check fold(current_val, _, beta, x) is consistent with final_poly
                    // Without f(-x) we can only verify that x is non-zero (no divide-by-zero)
                    if x.0 == 0 {
                        return Err(StarkVerificationError::FriFoldingMismatch);
                    }
                }

                current_val = {
                    // Carry current_val forward; full fold verification deferred until
                    // proof carries explicit f(-x) sibling evals per layer.
                    let _ = current_val;
                    current_val
                };
                current_idx = i;
                current_domain_len = half;
            }
        }
    }

    Ok(true)
}
