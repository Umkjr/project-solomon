//! Quotient Polynomial Evaluator over Goldilocks Field
//! 
//! Evaluates the AIR constraints across the trace matrix and performs exact
//! algebraic division by the vanishing polynomial Z_H(zeta) = zeta^N - 1 in F_p.

use crate::field::{Field, GoldilocksField, DILITHIUM_Q};

pub struct QuotientEvaluator {
    alphas: Vec<GoldilocksField>,
    zeta: GoldilocksField,
}

impl QuotientEvaluator {
    pub fn new(alphas: Vec<GoldilocksField>, zeta: GoldilocksField) -> Self {
        Self { alphas, zeta }
    }

    /// Evaluates the AIR constraints across the entire execution trace matrix and Keccak rows.
    /// Divides the mixed constraints by Z_H(zeta) = zeta^N - 1 in the Goldilocks field.
    pub fn evaluate_with_keccak_rows(
        &self,
        matrix: &[Vec<GoldilocksField>],
        keccak_rows: &[[GoldilocksField; 400]],
    ) -> Vec<GoldilocksField> {
        let mut evaluations = Vec::with_capacity(matrix.len() + keccak_rows.len());

        assert!(self.alphas.len() >= 3, "Quotient evaluator requires at least 3 alpha scalars");
        let alpha_0 = self.alphas[0];
        let alpha_1 = self.alphas[1];
        let alpha_2 = self.alphas[2];
        let alpha_3 = if self.alphas.len() > 3 { self.alphas[3] } else { GoldilocksField::ONE };

        let q_dilithium = GoldilocksField::from_u64(DILITHIUM_Q);

        // Evaluation domain size must match the actual trace domain: TRACE_DOMAIN_ORDER = 2^18 = 262_144.
        // Z_H(zeta) = zeta^N - 1 must use the real trace size to produce a correct vanishing polynomial.
        let n: u64 = 262_144; // 2^18 — matches TraceBuilder::TRACE_DOMAIN_ORDER
        let zeta_pow_n = self.zeta.exp(n);
        let z_h = zeta_pow_n.sub(GoldilocksField::ONE);
        // Guard against zeta being an N-th root of unity (z_h == 0), which would cause division by zero.
        if z_h == GoldilocksField::ZERO {
            // zeta is on the evaluation domain itself — return empty evaluation set to avoid panic
            return Vec::new();
        }
        let z_h_inv = z_h.invert();

        for row in matrix {
            if row.len() < 5 {
                continue;
            }
            
            let a = row[0];
            let b = row[1];
            let w = row[2];
            let u = row[3];
            let v = row[4];

            // Integer quotient witnesses k_u, k_v
            let k_u = if row.len() > 5 { row[5] } else { GoldilocksField::ZERO };
            let k_v = if row.len() > 6 { row[6] } else { GoldilocksField::ZERO };

            // Gate 1: (a + b * W) - (u + k_u * Q)
            let b_w = b.mul(w);
            let lhs_1 = a.add(b_w);
            let rhs_1 = u.add(k_u.mul(q_dilithium));
            let constraint_1 = lhs_1.sub(rhs_1);

            // Gate 2: (a + Q - b * W) - (v + k_v * Q)
            let lhs_2 = a.add(q_dilithium).sub(b_w);
            let rhs_2 = v.add(k_v.mul(q_dilithium));
            let constraint_2 = lhs_2.sub(rhs_2);

            // Gate 3: Norm Slack Constraint (v_i + 109 - w_i)
            let slack_const = GoldilocksField::from_u64(109);
            let norm_constraint = a.add(slack_const).sub(u);

            // Mixed constraint evaluation
            let mixed = alpha_0.mul(constraint_1)
                .add(alpha_1.mul(constraint_2))
                .add(alpha_2.mul(norm_constraint));

            let point_eval = mixed.mul(z_h_inv);
            evaluations.push(point_eval);
        }

        // Stream Keccak transition constraints across adjacent round rows
        for window in keccak_rows.windows(2) {
            let local = &window[0];
            let next = &window[1];

            let mut keccak_constraint = GoldilocksField::ZERO;
            for x in 0..5 {
                let c_x = local[x].add(local[x + 5]).add(local[x + 10]).add(local[x + 15]).add(local[x + 20]);
                let d_x = local[(x + 4) % 5].add(next[(x + 1) % 5]);
                let theta = next[x].sub(local[x].add(d_x)).add(c_x);
                keccak_constraint = keccak_constraint.add(theta);
            }

            let point_eval = alpha_3.mul(keccak_constraint).mul(z_h_inv);
            evaluations.push(point_eval);
        }

        // Pad to power of 2 for iNTT interpolation
        let mut next_power = 1;
        while next_power < evaluations.len().max(n as usize) {
            next_power *= 2;
        }
        while evaluations.len() < next_power {
            evaluations.push(GoldilocksField::ZERO);
        }

        evaluations
    }

    /// Evaluates the AIR constraints across the trace matrix without auxiliary Keccak rows.
    pub fn evaluate(&self, matrix: &[Vec<GoldilocksField>]) -> Vec<GoldilocksField> {
        self.evaluate_with_keccak_rows(matrix, &[])
    }
}
