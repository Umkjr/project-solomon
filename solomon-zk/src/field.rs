//! Goldilocks Prime Field (q = 2^64 - 2^32 + 1)
//!
//! Provides 2-adicity of 32 for large STARK execution traces (up to 2^32 rows).
//! Supports native 64-bit word storage for Dilithium ring elements (Z_8380417).

pub const GOLDILOCKS_PRIME: u64 = 0xFFFF_FFFF_0000_0001; // 2^64 - 2^32 + 1
pub const DILITHIUM_Q: u64 = 8_380_417;

/// Trait representing field arithmetic operations.
pub trait Field: Copy + Clone + PartialEq + Eq + std::fmt::Debug {
    fn zero() -> Self;
    fn one() -> Self;
    fn add(self, other: Self) -> Self;
    fn sub(self, other: Self) -> Self;
    fn mul(self, other: Self) -> Self;
    fn invert(self) -> Self;
    fn exp(self, power: u64) -> Self;
}

use serde::{Serialize, Deserialize};

/// Goldilocks Field Element (Z_p where p = 2^64 - 2^32 + 1)
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct GoldilocksField(pub u64);

impl GoldilocksField {
    pub const ZERO: Self = GoldilocksField(0);
    pub const ONE: Self = GoldilocksField(1);

    /// Constructs a Goldilocks field element from a raw u64 (reducing if >= p).
    pub fn from_u64(val: u64) -> Self {
        if val >= GOLDILOCKS_PRIME {
            GoldilocksField(val - GOLDILOCKS_PRIME)
        } else {
            GoldilocksField(val)
        }
    }

    /// Embeds a Dilithium-65 polynomial coefficient into a single Goldilocks register.
    pub fn from_dilithium(val: u32) -> Self {
        GoldilocksField((val as u64) % DILITHIUM_Q)
    }

    /// Fast Goldilocks reduction for 128-bit values
    #[inline(always)]
    pub fn reduce_u128(x: u128) -> Self {
        let x_lo = x as u64;
        let x_hi = (x >> 64) as u64;

        let x_hi_hi = x_hi >> 32;
        let x_hi_lo = x_hi & 0xFFFF_FFFF;

        // x = x_lo + (x_hi_lo << 32) - x_hi + x_hi_hi * (2^32 - 1) (mod p)
        let t0 = (x_lo as i128) + ((x_hi_lo as i128) << 32) - (x_hi as i128) + (x_hi_hi as i128) * (0xFFFF_FFFF as i128);
        let p = GOLDILOCKS_PRIME as i128;
        let mut res = t0 % p;
        if res < 0 {
            res += p;
        }
        GoldilocksField(res as u64)
    }
}

impl Field for GoldilocksField {
    fn zero() -> Self {
        Self::ZERO
    }

    fn one() -> Self {
        Self::ONE
    }

    #[inline(always)]
    fn add(self, other: Self) -> Self {
        let (res, carry) = self.0.overflowing_add(other.0);
        if carry || res >= GOLDILOCKS_PRIME {
            GoldilocksField(res.wrapping_sub(GOLDILOCKS_PRIME))
        } else {
            GoldilocksField(res)
        }
    }

    #[inline(always)]
    fn sub(self, other: Self) -> Self {
        if self.0 >= other.0 {
            GoldilocksField(self.0 - other.0)
        } else {
            GoldilocksField(GOLDILOCKS_PRIME - (other.0 - self.0))
        }
    }

    #[inline(always)]
    fn mul(self, other: Self) -> Self {
        let prod = (self.0 as u128) * (other.0 as u128);
        Self::reduce_u128(prod)
    }

    fn exp(self, mut power: u64) -> Self {
        let mut base = self;
        let mut res = Self::ONE;
        while power > 0 {
            if power & 1 == 1 {
                res = res.mul(base);
            }
            base = base.mul(base);
            power >>= 1;
        }
        res
    }

    fn invert(self) -> Self {
        assert_ne!(self.0, 0, "Cannot invert zero in GoldilocksField");
        // By Fermat's Little Theorem: a^(p-2) = a^(-1) mod p
        self.exp(GOLDILOCKS_PRIME - 2)
    }
}
