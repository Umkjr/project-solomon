//! Merkle Tree & Decommitment Engine over Goldilocks Field
//! 
//! Computes trace commitments and generates inclusion paths for FRI queries.

use sha3::{Digest, Keccak256};
use crate::field::GoldilocksField;

/// Computes the Merkle Root of the execution trace matrix.
pub fn compute_trace_merkle_root(matrix: &[Vec<GoldilocksField>]) -> [u8; 32] {
    let (root, _) = build_merkle_tree_from_matrix(matrix);
    root
}

/// Builds the Merkle Tree from trace matrix rows and returns (root, all_layers).
pub fn build_merkle_tree_from_matrix(matrix: &[Vec<GoldilocksField>]) -> ([u8; 32], Vec<Vec<[u8; 32]>>) {
    let mut leaves = Vec::with_capacity(matrix.len());

    for row in matrix {
        let mut hasher = Keccak256::new();
        for element in row {
            hasher.update(&element.0.to_le_bytes());
        }
        let mut leaf = [0u8; 32];
        leaf.copy_from_slice(&hasher.finalize());
        leaves.push(leaf);
    }

    build_merkle_tree_from_leaves(leaves)
}

/// Builds a Merkle Tree from a slice of leaf hashes.
pub fn build_merkle_tree_from_leaves(mut leaves: Vec<[u8; 32]>) -> ([u8; 32], Vec<Vec<[u8; 32]>>) {
    if leaves.is_empty() {
        return ([0u8; 32], vec![]);
    }

    let mut next_pow2 = 1;
    while next_pow2 < leaves.len() {
        next_pow2 *= 2;
    }
    while leaves.len() < next_pow2 {
        leaves.push([0u8; 32]);
    }

    let mut layers = vec![leaves.clone()];
    let mut current = leaves;

    while current.len() > 1 {
        let mut next = Vec::with_capacity(current.len() / 2);
        for chunk in current.chunks(2) {
            let mut hasher = Keccak256::new();
            hasher.update(&chunk[0]);
            if chunk.len() > 1 {
                hasher.update(&chunk[1]);
            } else {
                hasher.update(&[0u8; 32]);
            }
            let mut parent = [0u8; 32];
            parent.copy_from_slice(&hasher.finalize());
            next.push(parent);
        }
        layers.push(next.clone());
        current = next;
    }

    (current[0], layers)
}

/// Generates a Merkle inclusion proof for a given leaf index.
pub fn generate_merkle_proof(layers: &[Vec<[u8; 32]>], index: usize) -> Vec<[u8; 32]> {
    let mut proof = Vec::new();
    let mut idx = index;

    for layer in &layers[..layers.len() - 1] {
        let sibling_idx = if idx % 2 == 0 { idx + 1 } else { idx - 1 };
        if sibling_idx < layer.len() {
            proof.push(layer[sibling_idx]);
        }
        idx /= 2;
    }

    proof
}

/// Verifies a Merkle inclusion proof against a known root.
pub fn verify_merkle_proof(root: &[u8; 32], leaf: &[u8; 32], proof: &[[u8; 32]], index: usize) -> bool {
    let mut current = *leaf;
    let mut idx = index;

    for sibling in proof {
        let mut hasher = Keccak256::new();
        if idx % 2 == 0 {
            hasher.update(&current);
            hasher.update(sibling);
        } else {
            hasher.update(sibling);
            hasher.update(&current);
        }
        current.copy_from_slice(&hasher.finalize());
        idx /= 2;
    }

    &current == root
}
