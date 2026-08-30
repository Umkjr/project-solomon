//! Fiat-Shamir Challenger over Goldilocks Field
//! 
//! Cryptographic sponge used to sample non-interactive challenges for the STARK protocol.

use sha3::{Digest, Keccak256};
use crate::field::{GoldilocksField, GOLDILOCKS_PRIME};

pub struct Challenger {
    hasher: Keccak256,
}

impl Challenger {
    pub fn new() -> Self {
        Self {
            hasher: Keccak256::new(),
        }
    }

    /// Observes a Goldilocks field element
    pub fn observe(&mut self, element: GoldilocksField) {
        self.hasher.update(&element.0.to_le_bytes());
    }

    /// Observes a raw byte slice (e.g., public key or Merkle root)
    pub fn observe_slice(&mut self, data: &[u8]) {
        self.hasher.update(data);
    }

    /// Samples a pseudo-random Goldilocks field element from the sponge state.
    pub fn sample_ext(&mut self) -> GoldilocksField {
        let result = self.hasher.finalize_reset();
        
        // Re-absorb the hash to advance the sponge state (Duplex construction)
        self.hasher.update(&result);
        
        // Extract 8 bytes to form a u64 in Goldilocks field
        let raw_val = u64::from_le_bytes([
            result[0], result[1], result[2], result[3],
            result[4], result[5], result[6], result[7],
        ]);
        GoldilocksField::from_u64(raw_val % GOLDILOCKS_PRIME)
    }

    /// Samples an array of mixing coefficients for AIR constraints
    pub fn sample_alphas(&mut self, count: usize) -> Vec<GoldilocksField> {
        let mut alphas = Vec::with_capacity(count);
        for _ in 0..count {
            alphas.push(self.sample_ext());
        }
        alphas
    }
}
