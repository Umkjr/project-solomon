//! Fast Reed-Solomon Interactive Oracle Proof (FRI) Prover over Goldilocks Field
//! 
//! Recursively folds LDE domain across coset pairs (x, -x), computes intermediate
//! Merkle layer commitments, and samples query openings for sound decommitment.

use crate::field::{Field, GoldilocksField};
use crate::challenger::Challenger;
use crate::merkle::{build_merkle_tree_from_leaves, generate_merkle_proof};
use crate::intt::get_root_of_unity;
use sha3::{Digest, Keccak256};

use serde::{Serialize, Deserialize};

pub const NUM_FRI_QUERIES: usize = 40;

#[derive(Clone, Serialize, Deserialize)]
pub struct FriQueryOpening {
    pub index: usize,
    pub trace_evals: Vec<GoldilocksField>,
    pub quotient_evals: Vec<GoldilocksField>,
    pub trace_merkle_path: Vec<[u8; 32]>,
    pub quotient_merkle_path: Vec<[u8; 32]>,
    pub fri_merkle_paths: Vec<Vec<[u8; 32]>>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct FriProof {
    pub layer_roots: Vec<[u8; 32]>,
    pub queries: Vec<FriQueryOpening>,
    pub final_poly: GoldilocksField,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct StarkProof {
    pub trace_root: [u8; 32],
    pub quotient_root: [u8; 32],
    pub fri_proof: FriProof,
}

pub struct FriProver {
    domain_evaluations: Vec<GoldilocksField>,
    trace_matrix: Option<Vec<Vec<GoldilocksField>>>,
    trace_layers: Option<Vec<Vec<[u8; 32]>>>,
}

impl FriProver {
    pub fn new(lde_evaluations: Vec<GoldilocksField>) -> Self {
        assert!(lde_evaluations.len() > 1, "LDE must have multiple evaluations for FRI folding");
        Self {
            domain_evaluations: lde_evaluations,
            trace_matrix: None,
            trace_layers: None,
        }
    }

    pub fn set_trace_context(&mut self, matrix: Vec<Vec<GoldilocksField>>, layers: Vec<Vec<[u8; 32]>>) {
        self.trace_matrix = Some(matrix);
        self.trace_layers = Some(layers);
    }

    /// Executes the complete FRI folding protocol and generates layer Merkle roots and query openings.
    pub fn generate_proof(&mut self, challenger: &mut Challenger) -> FriProof {
        let mut current_evals = self.domain_evaluations.clone();
        let mut layer_roots = Vec::new();
        let mut all_tree_layers = Vec::new();

        // 1. Commit to initial LDE domain
        let (initial_root, initial_layers) = Self::merkleize_evals(&current_evals);
        layer_roots.push(initial_root);
        all_tree_layers.push(initial_layers);
        challenger.observe_slice(&initial_root);

        // 2. Recursive Folding Loop
        let inv2 = GoldilocksField::from_u64(2).invert();
        let mut current_len = current_evals.len();
        while current_evals.len() > 1 {
            let beta = challenger.sample_ext();
            let next_len = current_evals.len() / 2;
            let mut next_evals = Vec::with_capacity(next_len);

            // Domain generator for the current layer: primitive current_len-th root of unity
            let omega = get_root_of_unity(current_len);

            for i in 0..next_len {
                let f_x = current_evals[i];
                let f_neg_x = current_evals[i + next_len];

                // x = omega^i (domain point for index i)
                let x = omega.exp(i as u64);

                // folded(x^2) = (f(x) + f(-x))/2 + beta * (f(x) - f(-x)) / (2*x)
                let sum = f_x.add(f_neg_x);
                let diff = f_x.sub(f_neg_x);
                let half_sum = sum.mul(inv2);
                let half_diff_over_x = diff.mul(inv2).mul(x.invert());
                let folded = half_sum.add(beta.mul(half_diff_over_x));

                next_evals.push(folded);
            }

            current_evals = next_evals;
            current_len /= 2;

            // Merkleize intermediate layer
            let (root, layers) = Self::merkleize_evals(&current_evals);
            layer_roots.push(root);
            all_tree_layers.push(layers);
            challenger.observe_slice(&root);
        }

        let final_constant = current_evals[0];
        challenger.observe(final_constant);

        // 3. Sample 40 Query Openings
        let mut queries = Vec::with_capacity(NUM_FRI_QUERIES);
        let domain_len = self.domain_evaluations.len();
        
        for _ in 0..NUM_FRI_QUERIES {
            let challenge = challenger.sample_ext();
            let query_index = (challenge.0 as usize) % domain_len;
            
            let (trace_evals, trace_merkle_path) = if let (Some(tm), Some(tl)) = (&self.trace_matrix, &self.trace_layers) {
                let trace_pow2 = if !tl.is_empty() { tl[0].len() } else { tm.len() };
                let trace_idx = query_index % trace_pow2;
                let evals = if trace_idx < tm.len() {
                    tm[trace_idx].clone()
                } else {
                    let width = if !tm.is_empty() { tm[0].len() } else { 8 };
                    vec![GoldilocksField::ZERO; width]
                };
                (evals, generate_merkle_proof(tl, trace_idx))
            } else {
                (vec![self.domain_evaluations[query_index]], generate_merkle_proof(&all_tree_layers[0], query_index))
            };

            let quotient_evals = vec![self.domain_evaluations[query_index]];
            let quotient_merkle_path = generate_merkle_proof(&all_tree_layers[0], query_index);
            
            let mut fri_merkle_paths = Vec::new();
            for (l, layer) in all_tree_layers.iter().enumerate() {
                let layer_idx = query_index >> l;
                fri_merkle_paths.push(generate_merkle_proof(layer, layer_idx % layer.len()));
            }

            queries.push(FriQueryOpening {
                index: query_index,
                trace_evals,
                quotient_evals,
                trace_merkle_path,
                quotient_merkle_path,
                fri_merkle_paths,
            });
        }

        FriProof {
            layer_roots,
            queries,
            final_poly: final_constant,
        }
    }

    fn merkleize_evals(evals: &[GoldilocksField]) -> ([u8; 32], Vec<Vec<[u8; 32]>>) {
        let mut leaves = Vec::with_capacity(evals.len());
        for &e in evals {
            let mut hasher = Keccak256::new();
            hasher.update(&e.0.to_le_bytes());
            let mut leaf = [0u8; 32];
            leaf.copy_from_slice(&hasher.finalize());
            leaves.push(leaf);
        }
        build_merkle_tree_from_leaves(leaves)
    }
}
