//! Portable 8-Lane SIMD Vectorized Goldilocks Arithmetic Engine
//!
//! Provides deterministic 8-lane parallel Goldilocks field arithmetic (Z_p where p = 2^64 - 2^32 + 1).
//! Operates with 64-byte alignment matching the AVX-512 ZMM register footprint.

use crate::field::{GoldilocksField, GOLDILOCKS_PRIME};

pub const LANES: usize = 8;

#[repr(C, align(64))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PackedGoldilocks8(pub [u64; LANES]);

impl Default for PackedGoldilocks8 {
    fn default() -> Self {
        Self::ZERO
    }
}

impl PackedGoldilocks8 {
    pub const ZERO: Self = PackedGoldilocks8([0; LANES]);
    pub const ONE: Self = PackedGoldilocks8([1; LANES]);

    #[inline(always)]
    pub fn broadcast(val: GoldilocksField) -> Self {
        PackedGoldilocks8([val.0; LANES])
    }

    #[inline(always)]
    pub fn from_slice(slice: &[GoldilocksField]) -> Self {
        assert_eq!(slice.len(), LANES);
        let mut arr = [0u64; LANES];
        for i in 0..LANES {
            arr[i] = slice[i].0;
        }
        PackedGoldilocks8(arr)
    }

    #[inline(always)]
    pub fn to_array(&self) -> [GoldilocksField; LANES] {
        let mut arr = [GoldilocksField::ZERO; LANES];
        for i in 0..LANES {
            arr[i] = GoldilocksField(self.0[i]);
        }
        arr
    }

    #[inline(always)]
    pub fn store_to_slice(&self, slice: &mut [GoldilocksField]) {
        assert_eq!(slice.len(), LANES);
        for i in 0..LANES {
            slice[i] = GoldilocksField(self.0[i]);
        }
    }

    #[inline(always)]
    pub fn add(&self, other: &Self) -> Self {
        let mut res = [0u64; LANES];
        for i in 0..LANES {
            let (sum, carry) = self.0[i].overflowing_add(other.0[i]);
            if carry || sum >= GOLDILOCKS_PRIME {
                res[i] = sum.wrapping_sub(GOLDILOCKS_PRIME);
            } else {
                res[i] = sum;
            }
        }
        PackedGoldilocks8(res)
    }

    #[inline(always)]
    pub fn sub(&self, other: &Self) -> Self {
        let mut res = [0u64; LANES];
        for i in 0..LANES {
            if self.0[i] >= other.0[i] {
                res[i] = self.0[i] - other.0[i];
            } else {
                res[i] = GOLDILOCKS_PRIME - (other.0[i] - self.0[i]);
            }
        }
        PackedGoldilocks8(res)
    }

    #[inline(always)]
    pub fn mul(&self, other: &Self) -> Self {
        let mut res = [0u64; LANES];
        for i in 0..LANES {
            let prod = (self.0[i] as u128) * (other.0[i] as u128);
            res[i] = GoldilocksField::reduce_u128(prod).0;
        }
        PackedGoldilocks8(res)
    }

    /// Fast Goldilocks reduction on packed 64-bit high and low parts:
    /// x = x_hi * 2^64 + x_lo = x_lo + x_hi * (2^32 - 1) mod p
    #[inline(always)]
    pub fn reduce_hi_lo(x_hi: &Self, x_lo: &Self) -> Self {
        let mut res = [0u64; LANES];
        for i in 0..LANES {
            let full = ((x_hi.0[i] as u128) << 64) | (x_lo.0[i] as u128);
            res[i] = GoldilocksField::reduce_u128(full).0;
        }
        PackedGoldilocks8(res)
    }
}
