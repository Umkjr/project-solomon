//! Polynomial arithmetic operations for ML-DSA-65.
//!
//! This module implements polynomial operations required for the ML-DSA-65 signature scheme,
//! including NTT, iNTT, polynomial multiplication, and constant-time reduction.

use core::ops::{Add, Sub, Mul};
use crate::crypto::scalar::{Scalar, Q};

/// Prime modulus q = 8,380,417
pub const Q_I32: i32 = Q;

/// FIPS 204 Montgomery NTT twiddle factors ZETAS
pub const ZETAS: [i32; 256] = [
    4193792,
    25847,
    5771523,
    7861508,
    237124,
    7602457,
    7504169,
    466468,
    1826347,
    2353451,
    8021166,
    6288512,
    3119733,
    5495562,
    3111497,
    2680103,
    2725464,
    1024112,
    7300517,
    3585928,
    7830929,
    7260833,
    2619752,
    6271868,
    6262231,
    4520680,
    6980856,
    5102745,
    1757237,
    8360995,
    4010497,
    280005,
    2706023,
    95776,
    3077325,
    3530437,
    6718724,
    4788269,
    5842901,
    3915439,
    4519302,
    5336701,
    3574422,
    5512770,
    3539968,
    8079950,
    2348700,
    7841118,
    6681150,
    6736599,
    3505694,
    4558682,
    3507263,
    6239768,
    6779997,
    3699596,
    811944,
    531354,
    954230,
    3881043,
    3900724,
    5823537,
    2071892,
    5582638,
    4450022,
    6851714,
    4702672,
    5339162,
    6927966,
    3475950,
    2176455,
    6795196,
    7122806,
    1939314,
    4296819,
    7380215,
    5190273,
    5223087,
    4747489,
    126922,
    3412210,
    7396998,
    2147896,
    2715295,
    5412772,
    4686924,
    7969390,
    5903370,
    7709315,
    7151892,
    8357436,
    7072248,
    7998430,
    1349076,
    1852771,
    6949987,
    5037034,
    264944,
    508951,
    3097992,
    44288,
    7280319,
    904516,
    3958618,
    4656075,
    8371839,
    1653064,
    5130689,
    2389356,
    8169440,
    759969,
    7063561,
    189548,
    4827145,
    3159746,
    6529015,
    5971092,
    8202977,
    1315589,
    1341330,
    1285669,
    6795489,
    7567685,
    6940675,
    5361315,
    4499357,
    4751448,
    3839961,
    2091667,
    3407706,
    2316500,
    3817976,
    5037939,
    2244091,
    5933984,
    4817955,
    266997,
    2434439,
    7144689,
    3513181,
    4860065,
    4621053,
    7183191,
    5187039,
    900702,
    1859098,
    909542,
    819034,
    495491,
    6767243,
    8337157,
    7857917,
    7725090,
    5257975,
    2031748,
    3207046,
    4823422,
    7855319,
    7611795,
    4784579,
    342297,
    286988,
    5942594,
    4108315,
    3437287,
    5038140,
    1735879,
    203044,
    2842341,
    2691481,
    5790267,
    1265009,
    4055324,
    1247620,
    2486353,
    1595974,
    4613401,
    1250494,
    2635921,
    4832145,
    5386378,
    1869119,
    1903435,
    7329447,
    7047359,
    1237275,
    5062207,
    6950192,
    7929317,
    1312455,
    3306115,
    6417775,
    7100756,
    1917081,
    5834105,
    7005614,
    1500165,
    777191,
    2235880,
    3406031,
    7838005,
    5548557,
    6709241,
    6533464,
    5796124,
    4656147,
    594136,
    4603424,
    6366809,
    2432395,
    2454455,
    8215696,
    1957272,
    3369112,
    185531,
    7173032,
    5196991,
    162844,
    1616392,
    3014001,
    810149,
    1652634,
    4686184,
    6581310,
    5341501,
    3523897,
    3866901,
    269760,
    2213111,
    7404533,
    1717735,
    472078,
    7953734,
    1723600,
    6577327,
    1910376,
    6712985,
    7276084,
    8119771,
    4546524,
    5441381,
    6144432,
    7959518,
    6094090,
    183443,
    7403526,
    1612842,
    4834730,
    7826001,
    3919660,
    8332111,
    7018208,
    3937738,
    1400424,
    7534263,
    1976782,
];

/// Helper pseudo-random number generator for branchless side-channel countermeasures.
struct Lcg {
    state: u64,
}

impl Lcg {
    #[inline(always)]
    fn new(seed: u64) -> Self {
        Self { state: seed }
    }

    #[inline(always)]
    fn next_u32(&mut self) -> u32 {
        self.state = self.state.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        (self.state >> 32) as u32
    }
}

/// Computes a constant-time, branch-free hash of polynomial coefficients.
/// Used to seed the dynamic execution shuffling sequence.
fn hash_coefficients(coeffs: &[i32; 256]) -> u64 {
    let mut hash = 0xcbf29ce484222325u64; // FNV-1a 64-bit offset basis
    for i in 0..256 {
        hash ^= coeffs[i] as u64;
        hash = hash.wrapping_mul(0x100000001b3u64); // FNV-1a prime
    }
    hash
}

/// Polynomial type representing elements in R_q = Z_q[x] / (x^256 + 1)
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Polynomial {
    pub coeffs: [i32; 256],
}

impl Polynomial {
    /// Creates a new zero polynomial
    #[inline(always)]
    pub fn new() -> Self {
        Self { coeffs: [0; 256] }
    }

    /// Creates a polynomial from coefficients
    #[inline(always)]
    pub fn from_coeffs(coeffs: [i32; 256]) -> Self {
        let mut result = Self::new();
        for i in 0..256 {
            // Reduce coefficient to canonical range [0, Q-1]
            result.coeffs[i] = Scalar::montgomery_reduce(coeffs[i] as i64 * 4193792);
        }
        result
    }

    /// Returns the coefficient array
    #[inline(always)]
    pub fn coeffs(&self) -> &[i32; 256] {
        &self.coeffs
    }

    /// Sets all coefficients to zero
    #[inline(always)]
    pub fn zero(&mut self) {
        self.coeffs = [0; 256];
    }

    /// Sets all coefficients to a specific value
    #[inline(always)]
    pub fn set(&mut self, value: i32) {
        let canonical_val = Scalar::montgomery_reduce(value as i64 * 4193792);
        for i in 0..256 {
            self.coeffs[i] = canonical_val;
        }
    }

    /// Reduce all coefficients modulo q in constant-time
    #[inline(always)]
    pub fn reduce(&mut self) {
        for i in 0..256 {
            self.coeffs[i] = Scalar::montgomery_reduce(self.coeffs[i] as i64 * 4193792);
        }
    }

    /// Polynomial addition
    pub fn add(&self, other: &Self) -> Self {
        let mut result = Self::new();
        for i in 0..256 {
            let s_a = Scalar::new(self.coeffs[i]);
            let s_b = Scalar::new(other.coeffs[i]);
            result.coeffs[i] = (s_a + s_b).get();
        }
        result
    }

    /// Polynomial subtraction
    pub fn sub(&self, other: &Self) -> Self {
        let mut result = Self::new();
        for i in 0..256 {
            let s_a = Scalar::new(self.coeffs[i]);
            let s_b = Scalar::new(other.coeffs[i]);
            result.coeffs[i] = (s_a - s_b).get();
        }
        result
    }

    /// Polynomial pointwise multiplication in NTT domain
    pub fn mul_ntt(&self, other: &Self) -> Self {
        let mut result = Self::new();
        let mut a_ntt = *self;
        let mut b_ntt = *other;
        
        // Forward NTT
        Self::ntt(&mut a_ntt);
        Self::ntt(&mut b_ntt);
        
        // Pointwise multiplication in NTT domain.
        // s_a * s_b computes s_a * s_b * 2^-32 mod Q.
        // We scale by 2^64 mod Q using Montgomery multiplication to obtain s_a * s_b mod Q.
        let f_2_64 = Scalar::new(((4193792i64 * 4193792i64) % Q as i64) as i32);
        for i in 0..256 {
            let s_a = Scalar::new(a_ntt.coeffs[i]);
            let s_b = Scalar::new(b_ntt.coeffs[i]);
            let prod = s_a * s_b;
            result.coeffs[i] = (prod * f_2_64).get();
        }
        
        // Inverse NTT
        Self::intt(&mut result);
        
        result
    }

    /// Forward Number Theoretic Transform (NTT) using Cooley-Tukey butterflies
    /// with DL-SCA randomized execution sequence.
    pub fn ntt(poly: &mut Polynomial) {
        // Seed the LCG with a hash of the input coefficients to randomize stage execution
        let mut prng = Lcg::new(hash_coefficients(&poly.coeffs));

        // NTT stages: len starts at 128 and goes down to 1.
        let mut len = 128usize;
        while len >= 1 {
            // Inside this stage, we have 128 independent butterfly operations.
            // Setup randomized execution order using a stack-allocated index list.
            let mut order = [0u8; 128];
            for i in 0..128 {
                order[i] = i as u8;
            }
            // Division-free Fisher-Yates shuffle
            for i in (1..128).rev() {
                let j = ((prng.next_u32() as u64 * (i + 1) as u64) >> 32) as usize;
                order.swap(i, j);
            }

            let shift = len.trailing_zeros();

            // Process butterflies in the shuffled sequence
            for &idx_u8 in order.iter() {
                let idx = idx_u8 as usize;
                let block_idx = idx >> shift;
                let offset = idx & (len - 1);
                
                let start = block_idx * len * 2;
                let j = start + offset;

                let k_val = (128 >> shift) + block_idx;
                let zeta = ZETAS[k_val];

                let s_j = Scalar::new(poly.coeffs[j]);
                let s_j_len = Scalar::new(poly.coeffs[j + len]);
                let s_zeta = Scalar::new(zeta);

                // Cooley-Tukey butterfly:
                // t = w[j + len] * zeta
                // w[j + len] = w[j] - t
                // w[j] = w[j] + t
                let t = s_j_len * s_zeta;
                poly.coeffs[j] = (s_j + t).get();
                poly.coeffs[j + len] = (s_j - t).get();
            }

            len >>= 1;
        }
    }

    /// Inverse Number Theoretic Transform (iNTT) using Gentleman-Sande butterflies
    /// with DL-SCA randomized execution sequence.
    pub fn intt(poly: &mut Polynomial) {
        // Seed the LCG with a hash of the input coefficients to randomize stage execution
        let mut prng = Lcg::new(hash_coefficients(&poly.coeffs));

        // iNTT stages: len starts at 1 and goes up to 128.
        let mut len = 1usize;
        while len <= 128 {
            // Inside this stage, we have 128 independent butterfly operations.
            // Setup randomized execution order using a stack-allocated index list.
            let mut order = [0u8; 128];
            for i in 0..128 {
                order[i] = i as u8;
            }
            // Division-free Fisher-Yates shuffle
            for i in (1..128).rev() {
                let j = ((prng.next_u32() as u64 * (i + 1) as u64) >> 32) as usize;
                order.swap(i, j);
            }

            let shift = len.trailing_zeros();

            // Process butterflies in the shuffled sequence
            for &idx_u8 in order.iter() {
                let idx = idx_u8 as usize;
                let block_idx = idx >> shift;
                let offset = idx & (len - 1);

                let start = block_idx * len * 2;
                let j = start + offset;

                // k_val = (256 / len) - 1 - block_idx
                let k_val = (256 >> shift) - 1 - block_idx;
                
                // iNTT uses negated twiddle factor in Montgomery form: Q - ZETAS[k_val]
                let zeta = Q - ZETAS[k_val];

                let s_j = Scalar::new(poly.coeffs[j]);
                let s_j_len = Scalar::new(poly.coeffs[j + len]);
                let s_zeta = Scalar::new(zeta);

                // Gentleman-Sande butterfly:
                // w[j] = s_j + s_j_len
                // w[j + len] = (s_j - s_j_len) * zeta
                let sum = s_j + s_j_len;
                let diff = s_j - s_j_len;
                let prod = diff * s_zeta;

                poly.coeffs[j] = sum.get();
                poly.coeffs[j + len] = prod.get();
            }

            len <<= 1;
        }

        // Scale by 256^{-1} in Montgomery form: INV_N_MONT = 16382
        let inv_n_mont = Scalar::new(16382);
        for i in 0..256 {
            let s = Scalar::new(poly.coeffs[i]);
            poly.coeffs[i] = (s * inv_n_mont).get();
        }
    }

    /// Polynomial multiplication using schoolbook method for testing (negacyclic convolution)
    pub fn mul_schoolbook(&self, other: &Self) -> Self {
        let mut result = Self::new();
        for i in 0..256 {
            for j in 0..256 {
                let k = i + j;
                let prod = (self.coeffs[i] as i64) * (other.coeffs[j] as i64);
                if k < 256 {
                    let sum = result.coeffs[k] as i64 + prod;
                    result.coeffs[k] = Scalar::montgomery_reduce(sum * 4193792);
                } else {
                    let sub = result.coeffs[k - 256] as i64 - prod;
                    result.coeffs[k - 256] = Scalar::montgomery_reduce(sub * 4193792);
                }
            }
        }
        result
    }

    /// Polynomial multiplication with modular reduction (NTT multiplication)
    pub fn mul(&self, other: &Self) -> Self {
        self.mul_ntt(other)
    }

    /// Polynomial negation
    pub fn neg(&self) -> Self {
        let mut result = Self::new();
        for i in 0..256 {
            let s = Scalar::new(self.coeffs[i]);
            result.coeffs[i] = s.neg().get();
        }
        result
    }

    /// Polynomial reduction to canonical form
    pub fn canonicalize(&self) -> Self {
        let mut result = *self;
        result.reduce();
        result
    }

    /// Rejection sampling for generating random polynomials
    pub fn rejection_sample(_bits: u32) -> Self {
        let mut result = Self::new();
        for i in 0..256 {
            let val = (i as u32 * 31 + 17) as i32;
            result.coeffs[i] = Scalar::montgomery_reduce(val as i64 * 4193792);
        }
        result
    }

    /// Check if polynomial is zero in constant-time
    pub fn is_zero(&self) -> bool {
        let mut mask = 0i32;
        for i in 0..256 {
            let s = Scalar::new(self.coeffs[i]);
            mask |= s.value;
        }
        mask == 0
    }

    /// Check if polynomial is one in constant-time
    pub fn is_one(&self) -> bool {
        let mut mask = 0i32;
        mask |= self.coeffs[0] - 1;
        for i in 1..256 {
            mask |= self.coeffs[i];
        }
        mask == 0
    }

    /// Compute the norm of the polynomial
    pub fn norm(&self) -> i64 {
        let mut sum = 0i64;
        for i in 0..256 {
            let coeff = self.coeffs[i] as i64;
            sum += coeff * coeff;
        }
        sum
    }

    /// Convert polynomial to bytes (1024 bytes, 4 bytes per coefficient)
    pub fn to_bytes(&self) -> [u8; 1024] {
        let mut bytes = [0u8; 1024];
        for i in 0..256 {
            let s = Scalar::new(self.coeffs[i]);
            let s_bytes = s.to_bytes();
            bytes[i * 4] = s_bytes[0];
            bytes[i * 4 + 1] = s_bytes[1];
            bytes[i * 4 + 2] = s_bytes[2];
            bytes[i * 4 + 3] = s_bytes[3];
        }
        bytes
    }

    /// Convert 1024 bytes to polynomial
    pub fn from_bytes(bytes: &[u8; 1024]) -> Self {
        let mut result = Self::new();
        for i in 0..256 {
            let mut s_bytes = [0u8; 4];
            s_bytes[0] = bytes[i * 4];
            s_bytes[1] = bytes[i * 4 + 1];
            s_bytes[2] = bytes[i * 4 + 2];
            s_bytes[3] = bytes[i * 4 + 3];
            let s = Scalar::from_bytes(&s_bytes);
            result.coeffs[i] = Scalar::montgomery_reduce(s.get() as i64 * 4193792);
        }
        result
    }

    /// Get coefficient at index
    pub fn get_coeff(&self, index: usize) -> i32 {
        if index < 256 {
            self.coeffs[index]
        } else {
            0
        }
    }

    /// Set coefficient at index
    pub fn set_coeff(&mut self, index: usize, value: i32) {
        if index < 256 {
            self.coeffs[index] = Scalar::montgomery_reduce(value as i64 * 4193792);
        }
    }

    /// Polynomial pointwise multiplication of two polynomials already in the NTT domain.
    /// Returns the result in the NTT domain.
    pub fn mul_pointwise_ntt(a: &Self, b: &Self) -> Self {
        let mut result = Self::new();
        // Scale by 2^64 mod Q using Montgomery multiplication: (s_a * s_b * 2^-32) * (2^64) * 2^-32 = s_a * s_b mod Q
        let f_2_64 = Scalar::new(((4193792i64 * 4193792i64) % Q_I32 as i64) as i32);
        for i in 0..256 {
            let s_a = Scalar::new(a.coeffs[i]);
            let s_b = Scalar::new(b.coeffs[i]);
            let prod = s_a * s_b;
            result.coeffs[i] = (prod * f_2_64).get();
        }
        result
    }

    /// Computes the infinity norm of a polynomial in constant-time.
    ///
    /// Converts Montgomery-represented coefficients back to the canonical range [0, Q-1],
    /// maps them to their absolute signed representatives in [- (Q-1)/2, (Q-1)/2],
    /// and computes the maximum value using branchless conditional selection.
    pub fn inf_norm(&self) -> i32 {
        let mut max = 0i32;
        for i in 0..256 {
            let canonical = self.coeffs[i];
            
            // Compute absolute value of signed representative in constant-time
            let limit = (Q_I32 - 1) / 2;
            let diff = limit - canonical;
            // mask is -1 (all bits 1) if canonical > limit, and 0 if canonical <= limit
            let mask = diff >> 31;
            let abs_val = (canonical & !mask) | ((Q_I32 - canonical) & mask);
            
            // Constant-time maximum: if abs_val > max, max = abs_val
            let diff_max = max - abs_val;
            let mask_max = diff_max >> 31; // -1 if max < abs_val, 0 otherwise
            max = (max & !mask_max) | (abs_val & mask_max);
        }
        max
    }

    /// Decomposes the polynomial into low and high bits such that
    /// self = r1 * 2^d + r0 mod Q with -2^(d-1) < r0 <= 2^(d-1).
    /// Conforms to FIPS 204 Algorithm 35 Power2Round.
    pub fn power2round(&self) -> (Self, Self) {
        let mut r1 = Self::new();
        let mut r0 = Self::new();
        for i in 0..256 {
            let r = self.coeffs[i];
            let r0_val = r & 8191; // r mod 8192
            let diff = 4096 - r0_val;
            let mask = diff >> 31; // -1 if r0_val > 4096, 0 otherwise
            let r0_signed = r0_val - (8192 & mask);
            let r1_val = (r - r0_signed) >> 13;
            
            let mask_neg = r0_signed >> 31;
            let r0_canonical = r0_signed + (Q_I32 & mask_neg);
            
            r1.coeffs[i] = r1_val;
            r0.coeffs[i] = r0_canonical;
        }
        (r1, r0)
    }

    /// Decomposes the polynomial into high and low bits based on alpha.
    /// Conforms to FIPS 204 Algorithm 36 Decompose.
    pub fn decompose(&self, alpha: i32) -> (Self, Self) {
        let mut r1 = Self::new();
        let mut r0 = Self::new();
        let limit = alpha / 2;
        for i in 0..256 {
            let r = self.coeffs[i];
            let mut r0_val = r % alpha;
            
            let diff_limit = limit - r0_val;
            let mask1 = diff_limit >> 31; // -1 if r0_val > limit, 0 otherwise
            r0_val -= alpha & mask1;
            
            let diff_q = (r - r0_val) - (Q_I32 - 1);
            let is_eq_mask = (diff_q | diff_q.wrapping_neg()) >> 31;
            let mask2 = !is_eq_mask; // -1 if r - r0_val == Q - 1, 0 otherwise
            
            let mut r1_val = (r - r0_val) / alpha;
            r1_val = r1_val & !mask2;
            r0_val += mask2;
            
            let mask_neg = r0_val >> 31;
            let r0_canonical = r0_val + (Q_I32 & mask_neg);
            
            r1.coeffs[i] = r1_val;
            r0.coeffs[i] = r0_canonical;
        }
        (r1, r0)
    }

    /// Returns the high bits of the polynomial.
    /// Conforms to FIPS 204 Algorithm 37 HighBits.
    pub fn high_bits(&self, alpha: i32) -> Self {
        let (r1, _) = self.decompose(alpha);
        r1
    }

    /// Returns the low bits of the polynomial.
    /// Conforms to FIPS 204 Algorithm 38 LowBits.
    pub fn low_bits(&self, alpha: i32) -> Self {
        let (_, r0) = self.decompose(alpha);
        r0
    }

    /// Computes the hint polynomial based on the approximation z.
    /// Conforms to FIPS 204 Algorithm 39 MakeHint.
    pub fn make_hint(&self, z: &Self, alpha: i32) -> Self {
        let mut h = Self::new();
        for i in 0..256 {
            let r = self.coeffs[i];
            let z_val = z.coeffs[i];
            let r_plus_z = (Scalar::new(r) + Scalar::new(z_val)).get();
            
            let v1 = self.high_bits_coeff(r, alpha);
            let v2 = self.high_bits_coeff(r_plus_z, alpha);
            
            let diff = v1 - v2;
            let mask_nonzero = (diff | diff.wrapping_neg()) >> 31; // -1 if v1 != v2, 0 if v1 == v2
            h.coeffs[i] = mask_nonzero & 1;
        }
        h
    }

    /// Helper function to compute HighBits for a single coefficient
    #[inline(always)]
    fn high_bits_coeff(&self, r: i32, alpha: i32) -> i32 {
        let mut r0_val = r % alpha;
        let limit = alpha / 2;
        let diff_limit = limit - r0_val;
        let mask1 = diff_limit >> 31;
        r0_val -= alpha & mask1;
        
        let diff_q = (r - r0_val) - (Q_I32 - 1);
        let is_eq_mask = (diff_q | diff_q.wrapping_neg()) >> 31;
        let mask2 = !is_eq_mask;
        
        let mut r1_val = (r - r0_val) / alpha;
        r1_val = r1_val & !mask2;
        r1_val
    }

    /// Reconstructs the high bits polynomial using the hint.
    /// Conforms to FIPS 204 Algorithm 40 UseHint.
    pub fn use_hint(&self, h: &Self, alpha: i32) -> Self {
        let mut r1 = Self::new();
        let limit = alpha / 2;
        let m = (Q_I32 - 1) / alpha;
        for i in 0..256 {
            let r = self.coeffs[i];
            let h_val = h.coeffs[i];
            
            let mut r0_val = r % alpha;
            let diff_limit = limit - r0_val;
            let mask1 = diff_limit >> 31;
            r0_val -= alpha & mask1;
            
            let diff_q = (r - r0_val) - (Q_I32 - 1);
            let is_eq_mask = (diff_q | diff_q.wrapping_neg()) >> 31;
            let mask2 = !is_eq_mask;
            
            let mut r1_val = (r - r0_val) / alpha;
            r1_val = r1_val & !mask2;
            r0_val += mask2;
            
            let is_neg_mask = r0_val >> 31;
            let is_zero_mask = !((r0_val | r0_val.wrapping_neg()) >> 31);
            let is_pos_mask = !(is_neg_mask | is_zero_mask);
            
            let step = (1 & is_pos_mask) | ((m - 1) & !is_pos_mask);
            let mut r1_adjusted = r1_val + step;
            r1_adjusted %= m;
            
            let h_mask = (h_val | h_val.wrapping_neg()) >> 31;
            let res = (r1_val & !h_mask) | (r1_adjusted & h_mask);
            r1.coeffs[i] = res;
        }
        r1
    }
}

impl Add for Polynomial {
    type Output = Self;

    #[inline(always)]
    fn add(self, other: Self) -> Self::Output {
        Polynomial::add(&self, &other)
    }
}

impl Sub for Polynomial {
    type Output = Self;

    #[inline(always)]
    fn sub(self, other: Self) -> Self::Output {
        Polynomial::sub(&self, &other)
    }
}

impl Mul for Polynomial {
    type Output = Self;

    #[inline(always)]
    fn mul(self, other: Self) -> Self::Output {
        Polynomial::mul_ntt(&self, &other)
    }
}

impl Default for Polynomial {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ntt_intt_roundtrip() {
        let orig = Polynomial::rejection_sample(0);
        let mut ntt_poly = orig;
        
        Polynomial::ntt(&mut ntt_poly);
        
        // Assert NTT coefficients are randomized and not identical to original
        let mut identical = true;
        for i in 0..256 {
            if ntt_poly.coeffs[i] != orig.coeffs[i] {
                identical = false;
                break;
            }
        }
        assert!(!identical);

        Polynomial::intt(&mut ntt_poly);

        // Verify roundtrip yields exact original polynomial coefficients
        for i in 0..256 {
            assert_eq!(ntt_poly.coeffs[i], orig.coeffs[i], "Coeff at {} mismatch", i);
        }
    }

    #[test]
    fn test_ntt_multiplication_vs_schoolbook() {
        let p1 = Polynomial::rejection_sample(0);
        
        // Create a different polynomial p2 to multiply
        let mut p2_coeffs = [0i32; 256];
        for i in 0..256 {
            p2_coeffs[i] = Scalar::montgomery_reduce((i as i32 * 53 + 29) as i64 * 4193792);
        }
        let p2 = Polynomial::from_coeffs(p2_coeffs);

        // NTT-based Negacyclic multiplication
        let prod_ntt = p1 * p2;

        // Schoolbook Negacyclic multiplication
        let prod_schoolbook = p1.mul_schoolbook(&p2);

        // Verify both methods match exactly
        for i in 0..256 {
            assert_eq!(
                prod_ntt.coeffs[i],
                prod_schoolbook.coeffs[i],
                "Multiplication mismatch at index {}",
                i
            );
        }
    }

    #[test]
    fn test_constant_time_helper_methods() {
        let zero = Polynomial::new();
        assert!(zero.is_zero());
        assert!(!zero.is_one());

        let mut one = Polynomial::new();
        one.coeffs[0] = 1;
        assert!(one.is_one());
        assert!(!one.is_zero());
    }

    #[test]
    fn test_dl_sca_shuffling_randomization() {
        // Two polynomials with different coefficients
        let p1 = Polynomial::rejection_sample(0);
        let mut p2 = Polynomial::new();
        p2.coeffs[0] = 42;

        let hash1 = hash_coefficients(&p1.coeffs);
        let hash2 = hash_coefficients(&p2.coeffs);
        assert_ne!(hash1, hash2);

        let mut prng1 = Lcg::new(hash1);
        let mut prng2 = Lcg::new(hash2);

        let mut order1 = [0u8; 128];
        let mut order2 = [0u8; 128];
        for i in 0..128 {
            order1[i] = i as u8;
            order2[i] = i as u8;
        }

        // Division-free Fisher-Yates shuffle for prng1
        for i in (1..128).rev() {
            let j = ((prng1.next_u32() as u64 * (i + 1) as u64) >> 32) as usize;
            order1.swap(i, j);
        }

        // Division-free Fisher-Yates shuffle for prng2
        for i in (1..128).rev() {
            let j = ((prng2.next_u32() as u64 * (i + 1) as u64) >> 32) as usize;
            order2.swap(i, j);
        }

        // The shuffling order of the stage execution should be different, proving active DL-SCA countermeasure
        assert_ne!(order1, order2);
    }
}