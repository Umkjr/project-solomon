//! Low Degree Extension (LDE) Engine over Goldilocks Field
//! 
//! Expands quotient polynomials using iNTT interpolation, zero padding,
//! and Cooley-Tukey forward NTT evaluation.

use crate::field::{Field, GoldilocksField};
use crate::intt::{compute_intt, get_root_of_unity};

/// Generates a Low Degree Extension of discrete evaluations.
pub fn generate_lde(discrete_evals: &[GoldilocksField], blowup_factor: usize) -> Vec<GoldilocksField> {
    let mut coefficients = discrete_evals.to_vec();
    
    // 1. iNTT: Interpolate back to polynomial coefficients
    compute_intt(&mut coefficients);
    
    // 2. Pad with zeroes to extend domain size
    let extended_len = coefficients.len() * blowup_factor;
    coefficients.resize(extended_len, GoldilocksField::ZERO);
    
    // 3. Forward NTT: Evaluate over extended domain
    compute_forward_ntt(&mut coefficients);
    
    coefficients
}

/// In-place Cooley-Tukey Forward NTT over Goldilocks Field
pub fn compute_forward_ntt(evals: &mut [GoldilocksField]) {
    let n = evals.len();
    if n <= 1 {
        return;
    }

    let root = get_root_of_unity(n);

    let mut len = 2;
    while len <= n {
        let half_len = len / 2;
        let w_step = root.exp((n / len) as u64);
        let mut w_twiddle = GoldilocksField::ONE;

        for i in (0..n).step_by(len) {
            for j in 0..half_len {
                let u_idx = i + j;
                let v_idx = i + j + half_len;

                let u = evals[u_idx];
                let v = evals[v_idx];

                // Cooley-Tukey Butterfly: a = u + v*W, b = u - v*W
                let b_w = v.mul(w_twiddle);
                evals[u_idx] = u.add(b_w);
                evals[v_idx] = u.sub(b_w);

                w_twiddle = w_twiddle.mul(w_step);
            }
        }
        len *= 2;
    }
}
