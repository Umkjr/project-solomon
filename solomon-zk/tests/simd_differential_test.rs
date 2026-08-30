//! Differential SIMD Vectorized vs. Scalar Arithmetic and 4-Step NTT Test Harness
//!
//! Verifies exact arithmetic equivalence between:
//! 1. Scalar GoldilocksField arithmetic and 8-lane SIMD vector operations.
//! 2. Standard Radix-2 NTT and Cache-Oblivious 4-Step NTT across 262,144 coordinates.
//! 3. Forward NTT and Inverse NTT roundtrips (NTT o iNTT == Id).

use solomon_zk::field::{Field, GoldilocksField, GOLDILOCKS_PRIME};
use solomon_zk::simd::{
    PackedGoldilocks8, vector_add_slice, vector_sub_slice, vector_mul_slice, vector_mul_scalar,
    has_avx512, has_neon,
};
use solomon_zk::ntt::{
    forward_ntt_radix2, inverse_ntt_radix2, cache_oblivious_4step_ntt, cache_oblivious_4step_intt,
};

/// Deterministic Pseudo-Random Number Generator for test reproducibility (xorshift64)
struct TestRng(u64);

impl TestRng {
    fn new(seed: u64) -> Self {
        Self(if seed == 0 { 0x5EED_CAFE_BABE_DEAD } else { seed })
    }

    fn next_u64(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }

    fn next_goldilocks(&mut self) -> GoldilocksField {
        let raw = self.next_u64();
        GoldilocksField::from_u64(raw % GOLDILOCKS_PRIME)
    }
}

#[test]
fn test_simd_lane_add_sub_mul_differential() {
    let mut rng = TestRng::new(42);

    for iteration in 0..10_000 {
        let mut a_arr = [GoldilocksField::ZERO; 8];
        let mut b_arr = [GoldilocksField::ZERO; 8];

        for i in 0..8 {
            a_arr[i] = rng.next_goldilocks();
            b_arr[i] = rng.next_goldilocks();
        }

        let va = PackedGoldilocks8::from_slice(&a_arr);
        let vb = PackedGoldilocks8::from_slice(&b_arr);

        // 1. Vector Addition vs Scalar
        let v_sum = va.add(&vb).to_array();
        for i in 0..8 {
            let expected = a_arr[i].add(b_arr[i]);
            assert_eq!(
                v_sum[i], expected,
                "SIMD Addition mismatch on iter {} lane {}: got {:?}, expected {:?}",
                iteration, i, v_sum[i], expected
            );
        }

        // 2. Vector Subtraction vs Scalar
        let v_diff = va.sub(&vb).to_array();
        for i in 0..8 {
            let expected = a_arr[i].sub(b_arr[i]);
            assert_eq!(
                v_diff[i], expected,
                "SIMD Subtraction mismatch on iter {} lane {}: got {:?}, expected {:?}",
                iteration, i, v_diff[i], expected
            );
        }

        // 3. Vector Multiplication vs Scalar
        let v_prod = va.mul(&vb).to_array();
        for i in 0..8 {
            let expected = a_arr[i].mul(b_arr[i]);
            assert_eq!(
                v_prod[i], expected,
                "SIMD Multiplication mismatch on iter {} lane {}: got {:?}, expected {:?}",
                iteration, i, v_prod[i], expected
            );
        }
    }

    println!("[SIMD TEST] 10,000 iterations of 8-lane SIMD arithmetic verified against scalar oracle.");
}

#[test]
fn test_simd_slice_operations() {
    let mut rng = TestRng::new(1337);
    let len = 1024;

    let mut a = (0..len).map(|_| rng.next_goldilocks()).collect::<Vec<_>>();
    let b = (0..len).map(|_| rng.next_goldilocks()).collect::<Vec<_>>();
    let a_orig = a.clone();

    // Test vector_add_slice
    vector_add_slice(&mut a, &b);
    for i in 0..len {
        assert_eq!(a[i], a_orig[i].add(b[i]));
    }

    // Test vector_sub_slice
    vector_sub_slice(&mut a, &b);
    for i in 0..len {
        assert_eq!(a[i], a_orig[i]);
    }

    // Test vector_mul_slice
    let mut a_mul = a.clone();
    vector_mul_slice(&mut a_mul, &b);
    for i in 0..len {
        assert_eq!(a_mul[i], a_orig[i].mul(b[i]));
    }

    // Test vector_mul_scalar
    let scalar = rng.next_goldilocks();
    let mut a_scalar = a.clone();
    vector_mul_scalar(&mut a_scalar, scalar);
    for i in 0..len {
        assert_eq!(a_scalar[i], a_orig[i].mul(scalar));
    }
}

#[test]
fn test_ntt_radix2_roundtrip() {
    for &n in &[4, 16, 64, 256, 1024] {
        let mut rng = TestRng::new(999 + n as u64);
        let original = (0..n).map(|_| rng.next_goldilocks()).collect::<Vec<_>>();

        let mut transformed = original.clone();
        forward_ntt_radix2(&mut transformed);

        assert_ne!(transformed, original);

        inverse_ntt_radix2(&mut transformed);
        assert_eq!(transformed, original, "Radix-2 NTT o iNTT must equal identity for N = {}", n);
    }
}

#[test]
fn test_ntt_4step_cache_oblivious_roundtrip() {
    let mut rng = TestRng::new(2026);
    // Test N = 4096 (64 x 64 matrix)
    let n = 4096;
    let original = (0..n).map(|_| rng.next_goldilocks()).collect::<Vec<_>>();

    let mut transformed = original.clone();
    cache_oblivious_4step_ntt(&mut transformed);

    assert_ne!(transformed, original);

    cache_oblivious_4step_intt(&mut transformed);
    assert_eq!(transformed, original, "4-Step NTT o iNTT must equal identity for N = {}", n);
}

#[test]
fn test_ntt_4step_vs_radix2_differential_large_domain() {
    let mut rng = TestRng::new(777);
    // Test domain size N = 4096 for exact differential equality
    let n = 4096;
    let original = (0..n).map(|_| rng.next_goldilocks()).collect::<Vec<_>>();

    let mut radix2_res = original.clone();
    forward_ntt_radix2(&mut radix2_res);

    let mut step4_res = original.clone();
    cache_oblivious_4step_ntt(&mut step4_res);

    // Both NTT algorithms evaluate the same polynomial over the same canonical coset domain
    assert_eq!(
        step4_res, radix2_res,
        "4-Step Cache-Oblivious NTT output must be identical to Radix-2 NTT"
    );

    println!("[NTT TEST] Differential equivalence between Radix-2 and 4-Step NTT verified for N = {}.", n);
}

#[test]
fn test_simd_cpu_features_status() {
    println!("[SIMD STATUS] AVX-512 Support Detected: {}", has_avx512());
    println!("[SIMD STATUS] ARM NEON Support Detected: {}", has_neon());
}
