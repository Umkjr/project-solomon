//! Execution Trace Generator over Goldilocks Field for ML-DSA-65
//! 
//! Real bit-level unpacking of signature polynomial z and construction
//! of the 7-column execution trace with integer quotient witnesses.

use crate::field::{GoldilocksField, DILITHIUM_Q};

pub const TRACE_DOMAIN_ORDER: usize = 262_144; // N = 2^18
pub const KECCAK_TRACE_WIDTH: usize = 400;

const KECCAK_RC: [u64; 24] = [
    0x0000000000000001, 0x0000000000008082, 0x800000000000808A, 0x8000000080008000,
    0x000000000000808B, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
    0x000000000000008A, 0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
    0x000000008000808B, 0x800000000000008B, 0x8000000000008089, 0x8000000000008003,
    0x8000000000008002, 0x8000000000000080, 0x000000000000800A, 0x800000008000000A,
    0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
];

fn keccak_f1600_round(state: &mut [u64; 25], round: usize) {
    // Theta
    let mut c = [0u64; 5];
    for x in 0..5 {
        c[x] = state[x] ^ state[x + 5] ^ state[x + 10] ^ state[x + 15] ^ state[x + 20];
    }
    let mut d = [0u64; 5];
    for x in 0..5 {
        d[x] = c[(x + 4) % 5] ^ c[(x + 1) % 5].rotate_left(1);
    }
    for x in 0..5 {
        for y in 0..5 {
            state[x + 5 * y] ^= d[x];
        }
    }

    // Rho and Pi
    const ROT_CONSTANTS: [[u32; 5]; 5] = [
        [0, 36, 3, 41, 18],
        [1, 44, 10, 45, 2],
        [62, 6, 43, 15, 61],
        [28, 55, 25, 21, 56],
        [27, 20, 39, 8, 14],
    ];

    let mut b = [0u64; 25];
    for x in 0..5 {
        for y in 0..5 {
            b[y + 5 * ((2 * x + 3 * y) % 5)] = state[x + 5 * y].rotate_left(ROT_CONSTANTS[x][y]);
        }
    }

    // Chi
    for x in 0..5 {
        for y in 0..5 {
            state[x + 5 * y] = b[x + 5 * y] ^ ((!b[(x + 1) % 5 + 5 * y]) & b[(x + 2) % 5 + 5 * y]);
        }
    }

    // Iota
    state[0] ^= KECCAK_RC[round % 24];
}

/// Generates the 24 Keccak-f[1600] state-transition rows for a 32-byte seed.
/// Each row = one round's Goldilocks-encoded 400-cell state snapshot.
/// Peak memory: 24 * 400 * 8 = 76,800 bytes (75 KB).
pub fn generate_keccak_rows(seed: &[u8; 32]) -> Vec<[GoldilocksField; 400]> {
    let mut state = [0u64; 25];
    for (i, chunk) in seed.chunks(8).enumerate() {
        let mut buf = [0u8; 8];
        buf[..chunk.len()].copy_from_slice(chunk);
        state[i % 25] ^= u64::from_le_bytes(buf);
    }

    let mut rows = Vec::with_capacity(24);
    for round in 0..24 {
        keccak_f1600_round(&mut state, round);
        let mut row = [GoldilocksField::ZERO; 400];
        for (lane_idx, &lane) in state.iter().enumerate() {
            for nibble_idx in 0..16 {
                let nibble = (lane >> (nibble_idx * 4)) & 0xF;
                row[lane_idx * 16 + nibble_idx] = GoldilocksField::from_u64(nibble);
            }
        }
        rows.push(row);
    }
    rows
}

pub fn generate_shake_trace(seed: &[u8; 32]) -> Vec<GoldilocksField> {
    let rows = generate_keccak_rows(seed);
    let mut trace = Vec::with_capacity(TRACE_DOMAIN_ORDER * KECCAK_TRACE_WIDTH);
    for row in &rows {
        trace.extend_from_slice(row);
    }
    // Pad to exact power-of-two domain
    trace.resize(TRACE_DOMAIN_ORDER * KECCAK_TRACE_WIDTH, GoldilocksField::ZERO);
    trace
}

pub struct TraceBuilder {
    pub matrix: Vec<Vec<GoldilocksField>>,
}

impl TraceBuilder {
    pub fn new() -> Self {
        Self {
            matrix: Vec::with_capacity(1024),
        }
    }

    /// Ingests a raw 3309-byte ML-DSA-65 signature and unpacks it into the Goldilocks trace.
    pub fn ingest_signature(&mut self, signature: &[u8]) {
        assert_eq!(signature.len(), 3309, "ML-DSA-65 signature must be exactly 3309 bytes");

        // 1. Extract 32-byte Challenge (c~)
        let c_tilde = &signature[0..32];

        // 2. Extract Polynomial Vector 'z' (3200 bytes, L=5 polynomials, 256 coeffs each, 20-bit packed)
        let z_bytes = &signature[32..3232];
        let mut z_coefficients = Vec::with_capacity(5 * 256);
        
        let mut bit_offset = 0;
        for _ in 0..(5 * 256) {
            let byte_idx = bit_offset / 8;
            let bit_shift = bit_offset % 8;
            
            let mut chunk = 0u32;
            if byte_idx + 3 < z_bytes.len() {
                chunk = u32::from_le_bytes([
                    z_bytes[byte_idx],
                    z_bytes[byte_idx + 1],
                    z_bytes[byte_idx + 2],
                    z_bytes[byte_idx + 3],
                ]);
            } else {
                for i in 0..4 {
                    if byte_idx + i < z_bytes.len() {
                        chunk |= (z_bytes[byte_idx + i] as u32) << (i * 8);
                    }
                }
            }
            
            let mut coeff = ((chunk >> bit_shift) & 0x000F_FFFF) as u64;
            
            let gamma1 = 1u64 << 19;
            if coeff >= gamma1 {
                coeff -= gamma1;
            } else {
                coeff = DILITHIUM_Q - (gamma1 - coeff);
            }
            
            z_coefficients.push(GoldilocksField::from_u64(coeff % DILITHIUM_Q));
            bit_offset += 20;
        }

        // 3. Map into the Goldilocks AIR Trace Matrix with quotient witnesses
        let base_zeta = GoldilocksField::from_u64(1753);
        let mut w_twiddle = GoldilocksField::ONE;

        for chunk in z_coefficients.chunks(2) {
            if chunk.len() == 2 {
                let a = chunk[0];
                let b = chunk[1];
                
                let b_w_val = (b.0 * w_twiddle.0) % DILITHIUM_Q;
                let b_w = GoldilocksField::from_u64(b_w_val);

                // Exact modular reduction for u and v in Dilithium ring
                let sum_raw = a.0 + b_w.0;
                let u_val = sum_raw % DILITHIUM_Q;
                let k_u_val = sum_raw / DILITHIUM_Q;

                let diff_raw = a.0 + DILITHIUM_Q - b_w.0;
                let v_val = diff_raw % DILITHIUM_Q;
                let k_v_val = diff_raw / DILITHIUM_Q;

                let row = vec![
                    a,
                    b,
                    w_twiddle,
                    GoldilocksField::from_u64(u_val),
                    GoldilocksField::from_u64(v_val),
                    GoldilocksField::from_u64(k_u_val),
                    GoldilocksField::from_u64(k_v_val),
                    GoldilocksField::from_u64(c_tilde[0] as u64),
                ];
                self.matrix.push(row);
                
                w_twiddle = GoldilocksField::from_u64((w_twiddle.0 * base_zeta.0) % DILITHIUM_Q);
            }
        }

        // Pad matrix to power of 2 for consistent Merkle tree depth
        let mut next_pow2 = 1;
        while next_pow2 < self.matrix.len().max(1024) {
            next_pow2 *= 2;
        }
        while self.matrix.len() < next_pow2 {
            self.matrix.push(vec![GoldilocksField::ZERO; 8]);
        }
    }
}
