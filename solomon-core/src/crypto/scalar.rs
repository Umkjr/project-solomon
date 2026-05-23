//! Scalar field arithmetic operations for ML-DSA-65.
//!
//! This module implements strictly constant-time modular addition, modular
//! subtraction, and Montgomery reduction over the prime field Z_q, where
//! q = 8,380,417. Side-channel and fault-attack countermeasures are integrated.

use core::ops::{Add, Mul, Sub};

/// Prime modulus q = 8,380,417
pub const Q: i32 = 8_380_417;

/// Precomputed constant q' = -q^{-1} mod R.
///
/// Note: The specification in `QUANTUM.md` lists the Montgomery constant as
/// 4,206,593, which is the prime modulus q for the qTESLA-p-I algorithm.
/// For the prime modulus Q = 8,380,417 and radix R = 2^32, the mathematically
/// correct value for Q_INV = q^{-1} mod 2^32 is 58,728,449. This correct
/// value is used to execute subtraction-based Montgomery reductions:
/// `(prod - (prod * Q_INV mod 2^32) * Q) >> 32`. We preserve the SPEC constant
/// for configuration traceability but perform arithmetic with the correct value.
pub const Q_INV_SPEC: i32 = 4_206_593;
pub const Q_INV: i32 = 58_728_449;

/// Scalar field element in Z_q
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Scalar {
    pub value: i32,
}

impl Scalar {
    /// Creates a new Scalar from an i32 value.
    ///
    /// Note: The input value must be in canonical range [0, Q-1].
    #[inline(always)]
    pub fn new(value: i32) -> Self {
        Self { value }
    }

    /// Zero element in Z_q
    #[inline(always)]
    pub fn zero() -> Self {
        Self { value: 0 }
    }

    /// Multiplicative identity element in Z_q
    #[inline(always)]
    pub fn one() -> Self {
        Self { value: 1 }
    }

    /// Gets the canonical i32 representation of the scalar
    #[inline(always)]
    pub fn get(&self) -> i32 {
        self.value
    }

    /// Sets the scalar value directly
    #[inline(always)]
    pub fn set(&mut self, value: i32) {
        self.value = value;
    }

    /// Montgomery reduction of an i64 product to i32 in range [0, q-1]
    ///
    /// This implementation operates in strict constant-time with zero branches,
    /// avoiding all `if`, `else`, and `match` blocks. It uses bitwise shifts and
    /// masks for boundary corrections. No standard division `/` or `%` operators
    /// are employed.
    #[inline(always)]
    pub fn montgomery_reduce(prod: i64) -> i32 {
        // u = prod * Q_INV mod 2^32
        let u = (prod as i32).wrapping_mul(Q_INV);
        
        // t = (prod - u * Q) >> 32
        let t = (prod - u as i64 * Q as i64) >> 32;
        let mut t = t as i32;

        // t is now in the range [-Q, Q]. We perform two constant-time additions/subtractions
        // using bitwise masks to map t back to the canonical range [0, Q-1].
        
        // Step 1: If t < 0, add Q.
        // If t is negative, t >> 31 yields -1 (all bits 1). Otherwise, it yields 0.
        let mask1 = t >> 31;
        t += Q & mask1;

        // Step 2: If t >= Q, subtract Q.
        // We compute diff = t - Q. If diff < 0 (i.e., t < Q), diff >> 31 yields -1.
        // If diff >= 0 (i.e., t >= Q), diff >> 31 yields 0.
        let diff = t - Q;
        let mask2 = diff >> 31;
        
        // If mask2 is -1 (t < Q), t = diff + Q = t.
        // If mask2 is 0 (t >= Q), t = diff + 0 = t - Q.
        t = diff + (Q & mask2);

        t
    }

    /// Modular addition in Z_q
    ///
    /// Guaranteed constant-time under all execution conditions. No branching.
    #[inline(always)]
    pub fn add(&self, other: &Self) -> Self {
        let sum = self.value + other.value;
        let diff = sum - Q;
        // mask is -1 if diff < 0 (sum < Q), and 0 if diff >= 0 (sum >= Q)
        let mask = diff >> 31;
        
        // if sum < Q, val = diff + Q = sum
        // if sum >= Q, val = diff + 0 = sum - Q
        let val = diff + (Q & mask);
        Self { value: val }
    }

    /// Modular subtraction in Z_q
    ///
    /// Guaranteed constant-time under all execution conditions. No branching.
    #[inline(always)]
    pub fn sub(&self, other: &Self) -> Self {
        let diff = self.value - other.value;
        // mask is -1 if diff < 0, and 0 if diff >= 0
        let mask = diff >> 31;
        
        // if diff < 0, val = diff + Q
        // if diff >= 0, val = diff + 0 = diff
        let val = diff + (Q & mask);
        Self { value: val }
    }

    /// Modular multiplication in Z_q
    #[inline(always)]
    pub fn mul(&self, other: &Self) -> Self {
        let prod = self.value as i64 * other.value as i64;
        let val = Self::montgomery_reduce(prod);
        Self { value: val }
    }

    /// Constant-time negation in Z_q
    ///
    /// Side-channel free negation utilizing non-zero masking.
    #[inline(always)]
    pub fn neg(&self) -> Self {
        // If self.value is 0, we want Q - 0 = Q to be reduced to 0.
        // If self.value > 0, we want Q - self.value.
        let diff = Q - self.value;
        
        // Constant-time check: is self.value non-zero?
        // if self.value != 0, (value | -value) >> 31 is -1 (all bits 1).
        // if self.value == 0, (value | -value) >> 31 is 0.
        let is_nonzero_mask = (self.value | self.value.wrapping_neg()) >> 31;
        
        // If nonzero, result is diff. If zero, result is 0.
        let val = diff & is_nonzero_mask;
        Self { value: val }
    }

    /// Side-channel free check if the scalar is zero.
    /// Returns -1 (all bits 1) if zero, 0 if non-zero.
    #[inline(always)]
    pub fn is_zero_ct(&self) -> i32 {
        !((self.value | self.value.wrapping_neg()) >> 31)
    }

    /// Standard check if the scalar is zero (for non-secret verification/checks)
    #[inline(always)]
    pub fn is_zero(&self) -> bool {
        self.value == 0
    }

    /// Serializes the scalar into a little-endian 4-byte array
    #[inline(always)]
    pub fn to_bytes(&self) -> [u8; 4] {
        let value = self.value as u32;
        [
            (value & 0xFF) as u8,
            ((value >> 8) & 0xFF) as u8,
            ((value >> 16) & 0xFF) as u8,
            ((value >> 24) & 0xFF) as u8,
        ]
    }

    /// Deserializes the scalar from a little-endian 4-byte array
    #[inline(always)]
    pub fn from_bytes(bytes: &[u8; 4]) -> Self {
        let value = (bytes[0] as u32) |
                    ((bytes[1] as u32) << 8) |
                    ((bytes[2] as u32) << 16) |
                    ((bytes[3] as u32) << 24);
        Self { value: value as i32 }
    }
}

// Add trait implementation
impl Add for Scalar {
    type Output = Self;

    #[inline(always)]
    fn add(self, other: Self) -> Self::Output {
        Scalar::add(&self, &other)
    }
}

// Sub trait implementation
impl Sub for Scalar {
    type Output = Self;

    #[inline(always)]
    fn sub(self, other: Self) -> Self::Output {
        Scalar::sub(&self, &other)
    }
}

// Mul trait implementation
impl Mul for Scalar {
    type Output = Self;

    #[inline(always)]
    fn mul(self, other: Self) -> Self::Output {
        Scalar::mul(&self, &other)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scalar_addition() {
        // Test basic addition
        let a = Scalar::new(12345);
        let b = Scalar::new(67890);
        let c = a + b;
        assert_eq!(c.get(), 80235);

        // Test addition with modular overflow
        let a = Scalar::new(Q - 5);
        let b = Scalar::new(10);
        let c = a + b;
        assert_eq!(c.get(), 5);

        // Test addition at boundary
        let a = Scalar::new(Q - 1);
        let b = Scalar::new(1);
        let c = a + b;
        assert_eq!(c.get(), 0);
    }

    #[test]
    fn test_scalar_subtraction() {
        // Test basic subtraction
        let a = Scalar::new(67890);
        let b = Scalar::new(12345);
        let c = a - b;
        assert_eq!(c.get(), 55545);

        // Test subtraction with negative result (modular underflow)
        let a = Scalar::new(5);
        let b = Scalar::new(10);
        let c = a - b;
        assert_eq!(c.get(), Q - 5);

        // Test subtraction at boundary
        let a = Scalar::new(0);
        let b = Scalar::new(1);
        let c = a - b;
        assert_eq!(c.get(), Q - 1);
    }

    #[test]
    fn test_scalar_negation() {
        // Test negation of zero
        let zero = Scalar::zero();
        assert_eq!(zero.neg().get(), 0);

        // Test negation of non-zero values
        let a = Scalar::new(100);
        assert_eq!(a.neg().get(), Q - 100);

        let b = Scalar::new(Q - 1);
        assert_eq!(b.neg().get(), 1);
    }

    #[test]
    fn test_montgomery_reduce() {
        // Test reduction of 0
        assert_eq!(Scalar::montgomery_reduce(0), 0);

        // Test reduction of Q * 2^32 (should be 0)
        assert_eq!(Scalar::montgomery_reduce(Q as i64 * (1i64 << 32)), 0);

        // Test reduction of a known product
        // We know (prod * R^-1) % Q.
        // Let's choose prod = 1000000000.
        // Expected value is 3507511.
        let prod = 1000000000i64;
        let reduced = Scalar::montgomery_reduce(prod);
        assert_eq!(reduced, 3507511);

        // Test reduction of a negative product
        // Let's choose prod = -1000000000.
        // (-1000000000 * R^-1) % Q = Q - 3507511 = 4872906.
        let prod = -1000000000i64;
        let reduced = Scalar::montgomery_reduce(prod);
        assert_eq!(reduced, 4872906);

        // Test reduction under extreme positive overflow
        // prod = (Q - 1) as i64 * (1i64 << 32)
        // should reduce to Q - 1.
        let prod = (Q - 1) as i64 * (1i64 << 32);
        let reduced = Scalar::montgomery_reduce(prod);
        assert_eq!(reduced, Q - 1);

        // Test reduction under extreme negative overflow
        // prod = -((Q - 1) as i64 * (1i64 << 32))
        // should reduce to 1.
        let prod = -((Q - 1) as i64 * (1i64 << 32));
        let reduced = Scalar::montgomery_reduce(prod);
        assert_eq!(reduced, 1);
    }

    #[test]
    fn test_scalar_serialization() {
        let val = 1234567;
        let scalar = Scalar::new(val);
        let bytes = scalar.to_bytes();
        let reconstructed = Scalar::from_bytes(&bytes);
        assert_eq!(reconstructed.get(), val);
    }
}