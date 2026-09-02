use crate::trace::{TraceBuilder, generate_keccak_rows};
use crate::challenger::Challenger;
use crate::merkle::build_merkle_tree_from_matrix;
use crate::quotient::QuotientEvaluator;
use crate::lde::generate_lde;
use crate::fri::{FriProver, StarkProof};

/// Serialized representation of the STARK Proof.
pub type CompressedStarkProof = Vec<u8>;

/// Generates a STARK proof for ML-DSA-65 signature verification over Goldilocks Field.
pub fn generate_stark_proof(
    signature: &[u8],
    public_key: &[u8],
    message: &[u8],
) -> CompressedStarkProof {
    // 1. Unpack signature into Goldilocks Trace Matrix
    let mut trace_builder = TraceBuilder::new();
    trace_builder.ingest_signature(signature);

    // 2. Initialize Fiat-Shamir Challenger
    let mut challenger = Challenger::new();

    // 3. Commit to the trace matrix
    let (trace_merkle_root, trace_layers) = build_merkle_tree_from_matrix(&trace_builder.matrix);
    challenger.observe_slice(public_key);
    challenger.observe_slice(message);
    challenger.observe_slice(&trace_merkle_root);
    
    // 4. Draw random mixing scalars (4 Alphas for NTT, Norm, and Keccak constraints)
    let alphas = challenger.sample_alphas(4);
    
    // 5. Draw random evaluation point (Zeta)
    let zeta = challenger.sample_ext();
    
    // 6. Evaluate constraints and compute Quotient Polynomial with streaming Keccak rows
    let evaluator = QuotientEvaluator::new(alphas.clone(), zeta);
    let mut keccak_seed = [0u8; 32];
    if public_key.len() >= 32 {
        keccak_seed.copy_from_slice(&public_key[..32]);
    }
    let keccak_rows = generate_keccak_rows(&keccak_seed);
    let quotient_evals = evaluator.evaluate_with_keccak_rows(&trace_builder.matrix, &keccak_rows);
    
    // 7. Low Degree Extension (LDE) via iNTT and Forward NTT
    let blowup_factor = 4;
    let lde_evals = generate_lde(&quotient_evals, blowup_factor);
    
    // 8. FRI Prover with Layer Commitments and Query Openings
    let mut fri_prover = FriProver::new(lde_evals);
    fri_prover.set_trace_context(trace_builder.matrix.clone(), trace_layers);
    let fri_proof = fri_prover.generate_proof(&mut challenger);
    
    let quotient_root = if !fri_proof.layer_roots.is_empty() {
        fri_proof.layer_roots[0]
    } else {
        [0u8; 32]
    };

    let stark_proof = StarkProof {
        trace_root: trace_merkle_root,
        quotient_root,
        fri_proof,
    };
    
    serde_json::to_vec(&stark_proof).unwrap_or_else(|_| vec![0u8; 128])
}
