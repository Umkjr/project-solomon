//! AVX-512 Vectorized Goldilocks Arithmetic Engine (x86_64)
//!
//! Packs eight 64-bit field elements into 512-bit ZMM vector registers (__m512i).
//! Implements vectorized additions, subtractions, and Goldilocks modular reduction.

#[cfg(target_arch = "x86_64")]
use core::arch::x86_64::*;
use crate::field::{GoldilocksField, GOLDILOCKS_PRIME};
use super::portable::PackedGoldilocks8;

#[cfg(target_arch = "x86_64")]
#[derive(Clone, Copy)]
pub struct GoldilocksAVX512(pub __m512i);

#[cfg(target_arch = "x86_64")]
impl GoldilocksAVX512 {
    pub const GOLDILOCKS_P: u64 = GOLDILOCKS_PRIME;
    pub const EPSILON: u64 = 0xFFFF_FFFF; // 2^32 - 1

    #[inline(always)]
    pub unsafe fn set1(val: u64) -> Self {
        GoldilocksAVX512(_mm512_set1_epi64(val as i64))
    }

    #[inline(always)]
    pub unsafe fn load(ptr: *const u64) -> Self {
        GoldilocksAVX512(_mm512_loadu_si512(ptr as *const _))
    }

    #[inline(always)]
    pub unsafe fn store(&self, ptr: *mut u64) {
        _mm512_storeu_si512(ptr as *mut _, self.0);
    }

    #[inline(always)]
    pub unsafe fn from_packed(packed: &PackedGoldilocks8) -> Self {
        Self::load(packed.0.as_ptr())
    }

    #[inline(always)]
    pub unsafe fn to_packed(&self) -> PackedGoldilocks8 {
        let mut out = [0u64; 8];
        self.store(out.as_mut_ptr());
        PackedGoldilocks8(out)
    }

    /// Vectorized modular addition over Goldilocks prime (8 lanes in parallel)
    #[inline(always)]
    pub unsafe fn add(&self, other: &Self) -> Self {
        let sum = _mm512_add_epi64(self.0, other.0);
        let p_vec = _mm512_set1_epi64(GOLDILOCKS_PRIME as i64);
        
        // Carry occurs if sum < self (unsigned compare)
        let mask_carry = _mm512_cmplt_epu64_mask(sum, self.0);
        let mask_ge_p = _mm512_cmpge_epu64_mask(sum, p_vec);
        let mask_reduce = mask_carry | mask_ge_p;

        let reduced = _mm512_mask_sub_epi64(sum, mask_reduce, sum, p_vec);
        GoldilocksAVX512(reduced)
    }

    /// Vectorized modular subtraction over Goldilocks prime (8 lanes in parallel)
    #[inline(always)]
    pub unsafe fn sub(&self, other: &Self) -> Self {
        let diff = _mm512_sub_epi64(self.0, other.0);
        let p_vec = _mm512_set1_epi64(GOLDILOCKS_PRIME as i64);

        // Borrow occurs if self < other (unsigned compare)
        let mask_borrow = _mm512_cmplt_epu64_mask(self.0, other.0);
        let corrected = _mm512_mask_add_epi64(diff, mask_borrow, diff, p_vec);
        GoldilocksAVX512(corrected)
    }

    /// Vectorized 64-bit Goldilocks multiplication using 32-bit lane decomposition
    #[inline(always)]
    pub unsafe fn mul(&self, other: &Self) -> Self {
        let a = self.0;
        let b = other.0;

        let mask_32 = _mm512_set1_epi64(0xFFFF_FFFF);
        
        let a_lo = _mm512_and_si512(a, mask_32);
        let a_hi = _mm512_srli_epi64(a, 32);
        let b_lo = _mm512_and_si512(b, mask_32);
        let b_hi = _mm512_srli_epi64(b, 32);

        // Compute partial products:
        // c0 = a_lo * b_lo
        let c0 = _mm512_mul_epu32(a_lo, b_lo);
        // c1_0 = a_lo * b_hi
        let c1_0 = _mm512_mul_epu32(a_lo, b_hi);
        // c1_1 = a_hi * b_lo
        let c1_1 = _mm512_mul_epu32(a_hi, b_lo);
        // c2 = a_hi * b_hi
        let c2 = _mm512_mul_epu32(a_hi, b_hi);

        let c1 = _mm512_add_epi64(c1_0, c1_1);
        let c1_lo = _mm512_slli_epi64(_mm512_and_si512(c1, mask_32), 32);
        let c1_hi = _mm512_srli_epi64(c1, 32);

        // Combine lower product x_lo = c0 + (c1_lo << 32)
        let x_lo = _mm512_add_epi64(c0, c1_lo);
        // Combine upper product x_hi = c2 + c1_hi
        let x_hi = _mm512_add_epi64(c2, c1_hi);

        // Reduce x_lo + x_hi * (2^32 - 1) mod p:
        // x_hi * 2^32 - x_hi
        let x_hi_lo = _mm512_and_si512(x_hi, mask_32);
        let x_hi_hi = _mm512_srli_epi64(x_hi, 32);
        let x_hi_shift32 = _mm512_slli_epi64(x_hi_lo, 32);

        let t0 = _mm512_sub_epi64(x_lo, x_hi);
        let t1 = _mm512_add_epi64(t0, x_hi_shift32);
        let t2 = _mm512_sub_epi64(t1, x_hi_hi);

        // Final canonical reduction into [0, p-1]
        let p_vec = _mm512_set1_epi64(GOLDILOCKS_PRIME as i64);
        let mask_ge = _mm512_cmpge_epu64_mask(t2, p_vec);
        let res = _mm512_mask_sub_epi64(t2, mask_ge, t2, p_vec);

        // Fallback check ensuring exact canonical bounds
        let mut tmp = [0u64; 8];
        _mm512_storeu_si512(tmp.as_mut_ptr() as *mut _, res);
        for i in 0..8 {
            if tmp[i] >= GOLDILOCKS_PRIME {
                tmp[i] = (GoldilocksField(tmp[i])).0;
            }
        }
        Self::load(tmp.as_ptr())
    }
}
