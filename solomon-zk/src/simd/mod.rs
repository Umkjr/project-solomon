//! SIMD Vectorized Goldilocks Arithmetic and NTT Acceleration
//!
//! Provides unified vectorization abstractions over AVX-512 (x86_64), ARM NEON (aarch64),
//! and portable 8-lane 64-byte aligned SIMD primitives.

pub mod portable;
pub mod avx512;
pub mod neon;

pub use portable::PackedGoldilocks8;
use crate::field::{Field, GoldilocksField};

/// Trait defining vectorized field operations over packed lanes.
pub trait VectorizedField<F: Field>: Sized + Copy + Clone {
    const LANES: usize;

    fn zero() -> Self;
    fn one() -> Self;
    fn broadcast(val: F) -> Self;
    fn add_lanes(&self, other: &Self) -> Self;
    fn sub_lanes(&self, other: &Self) -> Self;
    fn mul_lanes(&self, other: &Self) -> Self;
}

impl VectorizedField<GoldilocksField> for PackedGoldilocks8 {
    const LANES: usize = 8;

    #[inline(always)]
    fn zero() -> Self {
        Self::ZERO
    }

    #[inline(always)]
    fn one() -> Self {
        Self::ONE
    }

    #[inline(always)]
    fn broadcast(val: GoldilocksField) -> Self {
        Self::broadcast(val)
    }

    #[inline(always)]
    fn add_lanes(&self, other: &Self) -> Self {
        self.add(other)
    }

    #[inline(always)]
    fn sub_lanes(&self, other: &Self) -> Self {
        self.sub(other)
    }

    #[inline(always)]
    fn mul_lanes(&self, other: &Self) -> Self {
        self.mul(other)
    }
}

/// Runtime CPU architecture feature detection
pub fn has_avx512() -> bool {
    #[cfg(target_arch = "x86_64")]
    {
        is_x86_feature_detected!("avx512f") && is_x86_feature_detected!("avx512dq")
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        false
    }
}

pub fn has_neon() -> bool {
    #[cfg(target_arch = "aarch64")]
    {
        true
    }
    #[cfg(not(target_arch = "aarch64"))]
    {
        false
    }
}

/// In-place vectorized element-wise addition: a[i] = a[i] + b[i]
pub fn vector_add_slice(a: &mut [GoldilocksField], b: &[GoldilocksField]) {
    assert_eq!(a.len(), b.len());
    let mut i = 0;
    while i + 8 <= a.len() {
        let va = PackedGoldilocks8::from_slice(&a[i..i + 8]);
        let vb = PackedGoldilocks8::from_slice(&b[i..i + 8]);
        let vres = va.add(&vb);
        vres.store_to_slice(&mut a[i..i + 8]);
        i += 8;
    }
    while i < a.len() {
        a[i] = a[i].add(b[i]);
        i += 1;
    }
}

/// In-place vectorized element-wise subtraction: a[i] = a[i] - b[i]
pub fn vector_sub_slice(a: &mut [GoldilocksField], b: &[GoldilocksField]) {
    assert_eq!(a.len(), b.len());
    let mut i = 0;
    while i + 8 <= a.len() {
        let va = PackedGoldilocks8::from_slice(&a[i..i + 8]);
        let vb = PackedGoldilocks8::from_slice(&b[i..i + 8]);
        let vres = va.sub(&vb);
        vres.store_to_slice(&mut a[i..i + 8]);
        i += 8;
    }
    while i < a.len() {
        a[i] = a[i].sub(b[i]);
        i += 1;
    }
}

/// In-place vectorized element-wise multiplication: a[i] = a[i] * b[i]
pub fn vector_mul_slice(a: &mut [GoldilocksField], b: &[GoldilocksField]) {
    assert_eq!(a.len(), b.len());
    let mut i = 0;
    while i + 8 <= a.len() {
        let va = PackedGoldilocks8::from_slice(&a[i..i + 8]);
        let vb = PackedGoldilocks8::from_slice(&b[i..i + 8]);
        let vres = va.mul(&vb);
        vres.store_to_slice(&mut a[i..i + 8]);
        i += 8;
    }
    while i < a.len() {
        a[i] = a[i].mul(b[i]);
        i += 1;
    }
}

/// In-place vectorized scalar multiplication: a[i] = a[i] * scalar
pub fn vector_mul_scalar(a: &mut [GoldilocksField], scalar: GoldilocksField) {
    let vscalar = PackedGoldilocks8::broadcast(scalar);
    let mut i = 0;
    while i + 8 <= a.len() {
        let va = PackedGoldilocks8::from_slice(&a[i..i + 8]);
        let vres = va.mul(&vscalar);
        vres.store_to_slice(&mut a[i..i + 8]);
        i += 8;
    }
    while i < a.len() {
        a[i] = a[i].mul(scalar);
        i += 1;
    }
}

/// Cache-line block matrix transpose (8x8 blocks of 64-bit Goldilocks field elements)
pub fn transpose_8x8_block(
    src: &[GoldilocksField],
    src_stride: usize,
    dst: &mut [GoldilocksField],
    dst_stride: usize,
) {
    for r in 0..8 {
        for c in 0..8 {
            dst[c * dst_stride + r] = src[r * src_stride + c];
        }
    }
}
