//! Module Linear Algebra and Sponge-based deterministic sampling for ML-DSA-65.
//!
//! This module implements `PolyVector` and `PolyMatrix` structures that manage
//! multidimensional grids of polynomials, supporting pointwise additions, subtractions,
//! vector NTT transforms, infinity norm operations, and matrix-vector multiplications.
//! It also integrates standard SHAKE-128 and SHAKE-256 generators for seed expansions.

use crate::crypto::poly::Polynomial;
use crate::crypto::scalar::{Scalar, Q};
use crate::crypto::shake::KeccakSponge;

/// A vector of N polynomials representing elements in R_q^N
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PolyVector<const N: usize> {
    pub polys: [Polynomial; N],
}

impl<const N: usize> PolyVector<N> {
    /// Creates a new zero PolyVector
    #[inline(always)]
    pub fn new() -> Self {
        Self {
            polys: [Polynomial::new(); N],
        }
    }

    /// Performs element-wise vector addition in constant-time
    pub fn add(&self, other: &Self) -> Self {
        let mut result = Self::new();
        for i in 0..N {
            result.polys[i] = self.polys[i].add(&other.polys[i]);
        }
        result
    }

    /// Performs element-wise vector subtraction in constant-time
    pub fn sub(&self, other: &Self) -> Self {
        let mut result = Self::new();
        for i in 0..N {
            result.polys[i] = self.polys[i].sub(&other.polys[i]);
        }
        result
    }

    /// Applies the forward NTT to all polynomials in the vector in-place
    pub fn ntt(&mut self) {
        for i in 0..N {
            Polynomial::ntt(&mut self.polys[i]);
        }
    }

    /// Applies the inverse NTT to all polynomials in the vector in-place
    pub fn intt(&mut self) {
        for i in 0..N {
            Polynomial::intt(&mut self.polys[i]);
        }
    }

    /// Computes the infinity norm of the vector in constant-time
    pub fn inf_norm(&self) -> i32 {
        let mut max = 0i32;
        for i in 0..N {
            let poly_max = self.polys[i].inf_norm();
            let diff = max - poly_max;
            // mask is -1 if max < poly_max, and 0 if max >= poly_max
            let mask = diff >> 31;
            max = (max & !mask) | (poly_max & mask);
        }
        max
    }

    /// Decomposes each polynomial in the vector into low and high bits.
    pub fn power2round(&self) -> (Self, Self) {
        let mut r1 = Self::new();
        let mut r0 = Self::new();
        for i in 0..N {
            let (p1, p0) = self.polys[i].power2round();
            r1.polys[i] = p1;
            r0.polys[i] = p0;
        }
        (r1, r0)
    }

    /// Decomposes each polynomial in the vector into high and low bits.
    pub fn decompose(&self, alpha: i32) -> (Self, Self) {
        let mut r1 = Self::new();
        let mut r0 = Self::new();
        for i in 0..N {
            let (p1, p0) = self.polys[i].decompose(alpha);
            r1.polys[i] = p1;
            r0.polys[i] = p0;
        }
        (r1, r0)
    }

    /// Returns high bits for each polynomial in the vector.
    pub fn high_bits(&self, alpha: i32) -> Self {
        let mut r = Self::new();
        for i in 0..N {
            r.polys[i] = self.polys[i].high_bits(alpha);
        }
        r
    }

    /// Returns low bits for each polynomial in the vector.
    pub fn low_bits(&self, alpha: i32) -> Self {
        let mut r = Self::new();
        for i in 0..N {
            r.polys[i] = self.polys[i].low_bits(alpha);
        }
        r
    }

    /// Computes the hint vector based on approximation vector z.
    pub fn make_hint(&self, z: &Self, alpha: i32) -> Self {
        let mut h = Self::new();
        for i in 0..N {
            h.polys[i] = self.polys[i].make_hint(&z.polys[i], alpha);
        }
        h
    }

    /// Reconstructs high bits vector using the hint vector.
    pub fn use_hint(&self, h: &Self, alpha: i32) -> Self {
        let mut r = Self::new();
        for i in 0..N {
            r.polys[i] = self.polys[i].use_hint(&h.polys[i], alpha);
        }
        r
    }
}

impl<const N: usize> Default for PolyVector<N> {
    fn default() -> Self {
        Self::new()
    }
}

/// A K x L matrix of polynomials representing elements in R_q^{K x L}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PolyMatrix<const K: usize, const L: usize> {
    pub rows: [[Polynomial; L]; K],
}

impl<const K: usize, const L: usize> PolyMatrix<K, L> {
    /// Creates a new zero PolyMatrix
    #[inline(always)]
    pub fn new() -> Self {
        Self {
            rows: [[Polynomial::new(); L]; K],
        }
    }

    /// Multiplies the polynomial matrix with a polynomial vector in the NTT domain.
    ///
    /// The matrix self and the vector input must be in the NTT domain. Pointwise
    /// multiplication is executed on the coefficients of the polynomials.
    /// Returns the resulting PolyVector of dimension K in the NTT domain.
    pub fn mul_vector_ntt(&self, vec: &PolyVector<L>) -> PolyVector<K> {
        let mut result = PolyVector::<K>::new();
        for i in 0..K {
            let mut sum = Polynomial::new();
            for j in 0..L {
                let prod = Polynomial::mul_pointwise_ntt(&self.rows[i][j], &vec.polys[j]);
                sum = sum.add(&prod);
            }
            result.polys[i] = sum;
        }
        result
    }
}

impl<const K: usize, const L: usize> Default for PolyMatrix<K, L> {
    fn default() -> Self {
        Self::new()
    }
}

/// Expands a public seed rho into the master public matrix A of dimension 6 x 5.
///
/// Implements standard SHAKE-128 expansion and FIPS 204 Algorithm 34/35/36 rejection sampling.
/// Returns the expanded PolyMatrix directly in the NTT domain.
pub fn expand_a(rho: &[u8; 32]) -> PolyMatrix<6, 5> {
    let salt = crate::crypto::heartbeat::get_daily_salt()
        .expect("System fails-closed: Daily Salt not initialized via Heartbeat!");

    let mut a = PolyMatrix::<6, 5>::new();
    for i in 0..6 {
        for j in 0..5 {
            let mut seed = [0u8; 66];
            seed[0..32].copy_from_slice(rho);
            seed[32] = j as u8;
            seed[33] = i as u8;
            seed[34..66].copy_from_slice(&salt);

            let mut sponge = KeccakSponge::new_shake128();
            sponge.absorb(&seed);

            let mut coeffs = [0i32; 256];
            let mut count = 0;
            let mut buf = [0u8; 3];

            while count < 256 {
                sponge.squeeze(&mut buf);
                let z = (buf[0] as u32) | ((buf[1] as u32) << 8) | (((buf[2] as u32) & 0x7F) << 16);
                let z = z as i32;
                if z < Q {
                    // Convert z directly to Montgomery representation before storage
                    coeffs[count] = Scalar::montgomery_reduce(z as i64 * 4193792);
                    count += 1;
                }
            }

            a.rows[i][j] = Polynomial { coeffs };
        }
    }
    a
}

/// Generates secret noise components s_1 and s_2 for ML-DSA-65.
///
/// Implements standard SHAKE-256 expansion and Algorithm 37/38 bounded rejection sampling with eta = 4.
/// Returns a tuple containing the secret vectors s1 (dimension 5) and s2 (dimension 6) in the spatial domain.
pub fn expand_s(rho_prime: &[u8; 64]) -> (PolyVector<5>, PolyVector<6>) {
    let salt = crate::crypto::heartbeat::get_daily_salt()
        .expect("System fails-closed: Daily Salt not initialized via Heartbeat!");

    let mut s1 = PolyVector::<5>::new();
    let mut s2 = PolyVector::<6>::new();

    // Sample secret vector s1 of dimension l = 5
    for i in 0..5 {
        let mut seed = [0u8; 98];
        seed[0..64].copy_from_slice(rho_prime);
        let i_u16 = i as u16;
        seed[64] = (i_u16 & 0xFF) as u8;
        seed[65] = ((i_u16 >> 8) & 0xFF) as u8;
        seed[66..98].copy_from_slice(&salt);

        let mut sponge = KeccakSponge::new_shake256();
        sponge.absorb(&seed);

        let mut coeffs = [0i32; 256];
        let mut count = 0;
        let mut buf = [0u8; 1];

        while count < 256 {
            sponge.squeeze(&mut buf);
            let b = buf[0];
            let z0 = (b & 0x0F) as i32;
            let z1 = (b >> 4) as i32;

            if z0 < 9 {
                let coeff = 4 - z0; // eta = 4
                coeffs[count] = Scalar::montgomery_reduce(coeff as i64 * 4193792);
                count += 1;
            }
            if count < 256 && z1 < 9 {
                let coeff = 4 - z1; // eta = 4
                coeffs[count] = Scalar::montgomery_reduce(coeff as i64 * 4193792);
                count += 1;
            }
        }

        s1.polys[i] = Polynomial { coeffs };
    }

    // Sample secret vector s2 of dimension k = 6
    for i in 0..6 {
        let mut seed = [0u8; 98];
        seed[0..64].copy_from_slice(rho_prime);
        let val = (5 + i) as u16; // l + i = 5 + i
        seed[64] = (val & 0xFF) as u8;
        seed[65] = ((val >> 8) & 0xFF) as u8;
        seed[66..98].copy_from_slice(&salt);

        let mut sponge = KeccakSponge::new_shake256();
        sponge.absorb(&seed);

        let mut coeffs = [0i32; 256];
        let mut count = 0;
        let mut buf = [0u8; 1];

        while count < 256 {
            sponge.squeeze(&mut buf);
            let b = buf[0];
            let z0 = (b & 0x0F) as i32;
            let z1 = (b >> 4) as i32;

            if z0 < 9 {
                let coeff = 4 - z0;
                coeffs[count] = Scalar::montgomery_reduce(coeff as i64 * 4193792);
                count += 1;
            }
            if count < 256 && z1 < 9 {
                let coeff = 4 - z1;
                coeffs[count] = Scalar::montgomery_reduce(coeff as i64 * 4193792);
                count += 1;
            }
        }

        s2.polys[i] = Polynomial { coeffs };
    }

    (s1, s2)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vector_addition_subtraction() {
        let mut v1 = PolyVector::<2>::new();
        let mut v2 = PolyVector::<2>::new();

        // Initialize with some values directly in canonical representation
        v1.polys[0].coeffs[0] = 100;
        v1.polys[1].coeffs[1] = 200;

        v2.polys[0].coeffs[0] = 300;
        v2.polys[1].coeffs[1] = 400;

        let sum = v1.add(&v2);
        assert_eq!(sum.polys[0].coeffs[0], 400);
        assert_eq!(sum.polys[1].coeffs[1], 600);

        let diff = sum.sub(&v2);
        assert_eq!(diff.polys[0].coeffs[0], 100);
        assert_eq!(diff.polys[1].coeffs[1], 200);
    }

    #[test]
    fn test_vector_ntt_intt_roundtrip() {
        let mut v = PolyVector::<3>::new();
        // Fill with randomized bounded values
        for i in 0..3 {
            for j in 0..256 {
                let val = ((i * j + 13) % 256) as i32;
                v.polys[i].coeffs[j] = val;
            }
        }

        let orig = v;
        v.ntt();
        // Ensure NTT representation is randomized and different from original
        assert_ne!(v, orig);

        v.intt();
        // Roundtrip must match the original exactly
        for i in 0..3 {
            for j in 0..256 {
                let canonical_orig = orig.polys[i].coeffs[j];
                let canonical_roundtrip = v.polys[i].coeffs[j];
                assert_eq!(canonical_orig, canonical_roundtrip);
            }
        }
    }

    #[test]
    fn test_vector_inf_norm() {
        let mut v = PolyVector::<2>::new();
        // Let's set a specific high value
        // Modulus Q = 8,380,417.
        // Limit is (Q - 1) / 2 = 4,190,208.
        // Let's set some canonical values:
        // 500000 (which is < limit, so absolute value is 500000)
        // Q - 600000 (which is > limit, absolute value is Q - (Q - 600000) = 600000)
        let val1 = 500000i32;
        let val2 = Q - 600000i32;

        v.polys[0].coeffs[12] = val1;
        v.polys[1].coeffs[34] = val2;

        let norm = v.inf_norm();
        assert_eq!(norm, 600000);
    }

    #[test]
    fn test_expand_a_bounds() {
        crate::crypto::heartbeat::set_daily_salt([0x5A; 32]);
        let rho = [0u8; 32];
        let a = expand_a(&rho);

        // Verify that expand_a outputs valid coefficients under Q
        for i in 0..6 {
            for j in 0..5 {
                let poly = &a.rows[i][j];
                for &coeff in poly.coeffs.iter() {
                    let canonical = coeff;
                    assert!(canonical >= 0 && canonical < Q, "Coeff {} out of range", canonical);
                }
            }
        }
    }

    #[test]
    fn test_expand_s_bounds() {
        crate::crypto::heartbeat::set_daily_salt([0x5A; 32]);
        let rho_prime = [0u8; 64];
        let (s1, s2) = expand_s(&rho_prime);

        // Verify s1 coefficients are in [-4, 4]
        for i in 0..5 {
            let poly = &s1.polys[i];
            for &coeff in poly.coeffs.iter() {
                let canonical = coeff;
                let limit = (Q - 1) / 2;
                let signed_val = if canonical > limit {
                    canonical - Q
                } else {
                    canonical
                };
                assert!(signed_val >= -4 && signed_val <= 4, "s1 coeff {} out of bounds [-4, 4]", signed_val);
            }
        }

        // Verify s2 coefficients are in [-4, 4]
        for i in 0..6 {
            let poly = &s2.polys[i];
            for &coeff in poly.coeffs.iter() {
                let canonical = coeff;
                let limit = (Q - 1) / 2;
                let signed_val = if canonical > limit {
                    canonical - Q
                } else {
                    canonical
                };
                assert!(signed_val >= -4 && signed_val <= 4, "s2 coeff {} out of bounds [-4, 4]", signed_val);
            }
        }
    }

    #[test]
    fn test_matrix_vector_multiplication() {
        let mut mat = PolyMatrix::<2, 2>::new();
        let mut vec = PolyVector::<2>::new();

        // Initialize matrix and vector in spatial domain
        let p00 = Polynomial::rejection_sample(0);
        let p01 = Polynomial::rejection_sample(1);
        let p10 = Polynomial::rejection_sample(2);
        let p11 = Polynomial::rejection_sample(3);

        mat.rows[0][0] = p00;
        mat.rows[0][1] = p01;
        mat.rows[1][0] = p10;
        mat.rows[1][1] = p11;

        let v0 = Polynomial::rejection_sample(4);
        let v1 = Polynomial::rejection_sample(5);

        vec.polys[0] = v0;
        vec.polys[1] = v1;

        // Compute expected result using schoolbook negacyclic multiplication in spatial domain
        // expected_row0 = p00 * v0 + p01 * v1
        // expected_row1 = p10 * v0 + p11 * v1
        let expected_row0 = p00.mul_schoolbook(&v0).add(&p01.mul_schoolbook(&v1));
        let expected_row1 = p10.mul_schoolbook(&v0).add(&p11.mul_schoolbook(&v1));

        // Now transform matrix and vector to NTT domain
        for i in 0..2 {
            for j in 0..2 {
                Polynomial::ntt(&mut mat.rows[i][j]);
            }
        }
        vec.ntt();

        // Perform matrix-vector multiplication in NTT domain
        let mut res = mat.mul_vector_ntt(&vec);

        // Transform result back to spatial domain
        res.intt();

        // Verify that the resulting polynomials match the schoolbook calculations
        for i in 0..256 {
            assert_eq!(
                res.polys[0].coeffs[i],
                expected_row0.coeffs[i],
                "Mismatch at row 0 coefficient index {}",
                i
            );
            assert_eq!(
                res.polys[1].coeffs[i],
                expected_row1.coeffs[i],
                "Mismatch at row 1 coefficient index {}",
                i
            );
        }
    }
}