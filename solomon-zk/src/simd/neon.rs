//! ARM NEON Vectorized Goldilocks Arithmetic Engine (aarch64)
//!
//! Packs two 64-bit field elements into 128-bit NEON vector registers (uint64x2_t).
//! Implements vectorized additions, subtractions, and Goldilocks modular reduction.

#[cfg(target_arch = "aarch64")]
use core::arch::aarch64::*;
#[allow(unused_imports)]
use crate::field::{Field, GoldilocksField, GOLDILOCKS_PRIME};

#[cfg(target_arch = "aarch64")]
#[derive(Clone, Copy)]
pub struct GoldilocksNEON(pub uint64x2_t);

#[cfg(target_arch = "aarch64")]
impl GoldilocksNEON {
    pub const GOLDILOCKS_P: u64 = GOLDILOCKS_PRIME;

    #[inline(always)]
    pub unsafe fn set1(val: u64) -> Self {
        GoldilocksNEON(vdupq_n_u64(val))
    }

    #[inline(always)]
    pub unsafe fn load(ptr: *const u64) -> Self {
        GoldilocksNEON(vld1q_u64(ptr))
    }

    #[inline(always)]
    pub unsafe fn store(&self, ptr: *mut u64) {
        vst1q_u64(ptr, self.0);
    }

    #[inline(always)]
    pub unsafe fn add(&self, other: &Self) -> Self {
        let sum = vaddq_u64(self.0, other.0);
        let p_vec = vdupq_n_u64(GOLDILOCKS_PRIME);

        // Check if sum < self (carry) or sum >= p
        let carry_mask = vcltq_u64(sum, self.0);
        let ge_p_mask = vcgeq_u64(sum, p_vec);
        let reduce_mask = vorrq_u64(carry_mask, ge_p_mask);

        let sub_p = vsubq_u64(sum, p_vec);
        let res = vbslq_u64(reduce_mask, sub_p, sum);
        GoldilocksNEON(res)
    }

    #[inline(always)]
    pub unsafe fn sub(&self, other: &Self) -> Self {
        let diff = vsubq_u64(self.0, other.0);
        let p_vec = vdupq_n_u64(GOLDILOCKS_PRIME);

        // Check if self < other (borrow)
        let borrow_mask = vcltq_u64(self.0, other.0);
        let add_p = vaddq_u64(diff, p_vec);
        let res = vbslq_u64(borrow_mask, add_p, diff);
        GoldilocksNEON(res)
    }

    #[inline(always)]
    pub unsafe fn mul(&self, other: &Self) -> Self {
        let mut a = [0u64; 2];
        let mut b = [0u64; 2];
        let mut out = [0u64; 2];
        self.store(a.as_mut_ptr());
        other.store(b.as_mut_ptr());

        for i in 0..2 {
            let prod = (a[i] as u128) * (b[i] as u128);
            out[i] = GoldilocksField::reduce_u128(prod).0;
        }

        Self::load(out.as_ptr())
    }
}
