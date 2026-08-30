//! Inverse Number Theoretic Transform (iNTT) over Goldilocks Field
//! 
//! Converts discrete evaluation points back into continuous polynomial coefficients
//! using Gentleman-Sande decimation-in-frequency with primitive 2-adic roots of unity.

use crate::field::{Field, GoldilocksField, GOLDILOCKS_PRIME};

/// Computes primitive N-th root of unity in Goldilocks field (N must be power of 2 <= 2^32)
pub fn get_root_of_unity(n: usize) -> GoldilocksField {
    assert!(n.is_power_of_two() && n <= (1 << 32));
    let g = GoldilocksField(7); // Standard Goldilocks multiplicative generator
    let exp = (GOLDILOCKS_PRIME - 1) / (n as u64);
    g.exp(exp)
}

/// Performs in-place Inverse Number Theoretic Transform.
pub fn compute_intt(evals: &mut [GoldilocksField]) {
    let n = evals.len();
    if n <= 1 {
        return;
    }

    let root = get_root_of_unity(n);
    let root_inv = root.invert();

    // Gentleman-Sande decimation-in-frequency iNTT
    let mut len = n;
    while len >= 2 {
        let half_len = len / 2;
        let w_step = root_inv.exp((n / len) as u64);
        let mut w_twiddle = GoldilocksField::ONE;

        for i in (0..n).step_by(len) {
            for j in 0..half_len {
                let u_idx = i + j;
                let v_idx = i + j + half_len;

                let u = evals[u_idx];
                let v = evals[v_idx];

                // Gentleman-Sande Butterfly: a = u + v, b = (u - v) * W
                evals[u_idx] = u.add(v);
                let diff = u.sub(v);
                evals[v_idx] = diff.mul(w_twiddle);

                w_twiddle = w_twiddle.mul(w_step);
            }
        }
        len = half_len;
    }

    // Scale by N^-1
    let n_field = GoldilocksField::from_u64(n as u64);
    let n_inv = n_field.invert();

    for i in 0..n {
        evals[i] = evals[i].mul(n_inv);
    }
}
