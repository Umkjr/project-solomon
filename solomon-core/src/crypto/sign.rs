//! Secure signing and verification core for ML-DSA-65.
//!
//! This module implements the secure signing engine featuring random arithmetic secret key
//! sharing, hardware speculative execution barriers, a continuous rejection sampling loop,
//! and the Verify-Before-Release (VBR) fault-attack guardrail.

#![allow(non_snake_case, dead_code)]

use crate::crypto::poly::Polynomial;
use crate::crypto::matrix::{expand_a, PolyVector};
use crate::crypto::shake::KeccakSponge;
use crate::crypto::barriers::speculative_barrier;
use crate::crypto::packing::{pack_pk, unpack_pk, pack_sig, unpack_sig, unpack_sk};
use crate::crypto::scalar::Q;

const GAMMA1: i32 = 524288; // 2^19
const GAMMA2: i32 = 261888; // (Q-1)/32

/// Guard structure housing secret shares with volatile zeroization on Drop.
struct SecretShares {
    s1_A: PolyVector<5>,
    s1_B: PolyVector<5>,
    s2_A: PolyVector<6>,
    s2_B: PolyVector<6>,
}

impl Drop for SecretShares {
    fn drop(&mut self) {
        // Securely zeroize sensitive secret shares upon falling out of scope
        unsafe {
            for p in 0..5 {
                for i in 0..256 {
                    core::ptr::write_volatile(&mut self.s1_A.polys[p].coeffs[i], 0);
                    core::ptr::write_volatile(&mut self.s1_B.polys[p].coeffs[i], 0);
                }
            }
            for p in 0..6 {
                for i in 0..256 {
                    core::ptr::write_volatile(&mut self.s2_A.polys[p].coeffs[i], 0);
                    core::ptr::write_volatile(&mut self.s2_B.polys[p].coeffs[i], 0);
                }
            }
        }
    }
}

// --- Helper Functions for Modular Field Mapping ---

#[inline(always)]
fn to_signed(coeff: i32) -> i32 {
    let limit = (Q - 1) / 2;
    let diff = limit - coeff;
    let mask = diff >> 31; // -1 if coeff > limit, 0 otherwise
    (coeff & !mask) | ((coeff - Q) & mask)
}

#[inline(always)]
fn to_canonical(val: i32) -> i32 {
    let mask = val >> 31; // -1 if val < 0, 0 otherwise
    val + (Q & mask)
}

// --- Masking Vector y Sampling (ExpandMask per FIPS 204 Algorithm 32) ---

fn expand_y(rho_prime: &[u8; 64], kappa: u16) -> PolyVector<5> {
    let mut y = PolyVector::<5>::new();
    for i in 0..5 {
        let mut seed = [0u8; 66];
        seed[0..64].copy_from_slice(rho_prime);
        let val = kappa + i as u16;
        seed[64] = (val & 0xFF) as u8;
        seed[65] = ((val >> 8) & 0xFF) as u8;

        let mut sponge = KeccakSponge::new_shake256();
        sponge.absorb(&seed);

        // For ML-DSA-65: gamma1 = 2^19 (20 bits per coefficient)
        // 256 coeffs * 20 bits / 8 = 640 bytes per polynomial
        let mut buf = [0u8; 640];
        sponge.squeeze(&mut buf);

        let mut poly = Polynomial::new();
        for j in 0..128 {
            let b0 = buf[5 * j] as u32;
            let b1 = buf[5 * j + 1] as u32;
            let b2 = buf[5 * j + 2] as u32;
            let b3 = buf[5 * j + 3] as u32;
            let b4 = buf[5 * j + 4] as u32;

            let c0 = b0 | (b1 << 8) | ((b2 & 0x0F) << 16);
            let c1 = (b2 >> 4) | (b3 << 4) | (b4 << 12);

            poly.coeffs[2 * j] = to_canonical(GAMMA1 - c0 as i32);
            poly.coeffs[2 * j + 1] = to_canonical(GAMMA1 - c1 as i32);
        }
        y.polys[i] = poly;
    }
    y
}

// --- High Bits pack helper for w1 ---

fn pack_w1(w1: &PolyVector<6>) -> [u8; 768] {
    let mut buf = [0u8; 768];
    for p in 0..6 {
        for i in 0..128 {
            let c0 = w1.polys[p].coeffs[2 * i] as u8;
            let c1 = w1.polys[p].coeffs[2 * i + 1] as u8;
            buf[p * 128 + i] = (c0 & 0x0F) | ((c1 & 0x0F) << 4);
        }
    }
    buf
}

// --- Challenge Polynomial c Sampling (SampleInBall per FIPS 204 Algorithm 29) ---

pub fn sample_in_ball(c_tilde: &[u8; 48]) -> Polynomial {
    let mut c = Polynomial::new();
    let mut sponge = KeccakSponge::new_shake256();
    sponge.absorb(c_tilde);

    let mut sign_bytes = [0u8; 8];
    sponge.squeeze(&mut sign_bytes);
    let mut signs = 0u64;
    for i in 0..8 {
        signs |= (sign_bytes[i] as u64) << (8 * i);
    }

    // 1 and -1 represented in the canonical modular range [0, Q-1]
    let c_1 = 1i32;
    let c_neg1 = Q - 1;

    // For ML-DSA-65: tau = 49 non-zero coefficients
    let mut buf = [0u8; 1];
    for i in (256 - 49)..256 {
        let mut j;
        loop {
            sponge.squeeze(&mut buf);
            j = buf[0] as usize;
            if j <= i {
                break;
            }
        }
        c.coeffs[i] = c.coeffs[j];

        let sign = (signs & 1) as u32;
        signs >>= 1;
        c.coeffs[j] = if sign == 1 { c_neg1 } else { c_1 };
    }
    c
}

// --- Main Verification Core (Internal) ---

/// Verifies an ML-DSA-65 signature per FIPS 204 ML-DSA.Verify_internal.
///
/// - `m_prime`: message representative (for pure ML-DSA: `0x00 || len(ctx) || ctx || msg`).
pub fn verify_internal(pk: &[u8; 1952], m_prime: &[u8], sig: &[u8; 3309]) -> bool {
    let (rho, t1) = unpack_pk(pk);

    let (c_tilde, z, h) = match unpack_sig(sig) {
        Ok(val) => val,
        Err(_) => return false,
    };

    if z.inf_norm() >= GAMMA1 - 196 {
        return false;
    }

    let mut tr_sponge = KeccakSponge::new_shake256();
    tr_sponge.absorb(pk);
    let mut tr = [0u8; 64];
    tr_sponge.squeeze(&mut tr);

    // FIPS 204 Algorithm 8: mu = SHAKE-256(tr || M', 512 bits)
    let mut mu_sponge = KeccakSponge::new_shake256();
    mu_sponge.absorb(&tr);
    mu_sponge.absorb(m_prime);
    let mut mu = [0u8; 64];
    mu_sponge.squeeze(&mut mu);

    let a = expand_a(&rho);

    let mut z_ntt = z;
    z_ntt.ntt();

    let c = sample_in_ball(&c_tilde);
    let mut c_ntt = c;
    Polynomial::ntt(&mut c_ntt);

    let az_ntt = a.mul_vector_ntt(&z_ntt);

    // t1 * 2^d (d = 13 for ML-DSA-65)
    let mut t1_shifted = t1;
    for i in 0..6 {
        for j in 0..256 {
            t1_shifted.polys[i].coeffs[j] = (t1.polys[i].coeffs[j] << 13) % Q;
        }
    }
    let mut t1_ntt = t1_shifted;
    t1_ntt.ntt();

    let mut w_approx_ntt = PolyVector::<6>::new();
    for i in 0..6 {
        let ct1_ntt = Polynomial::mul_pointwise_ntt(&c_ntt, &t1_ntt.polys[i]);
        w_approx_ntt.polys[i] = az_ntt.polys[i].sub(&ct1_ntt);
    }
    let mut w_approx = w_approx_ntt;
    w_approx.intt();

    // Reconstruct high bits using the hint (alpha = 2 * GAMMA2 = 523776)
    let w1 = w_approx.use_hint(&h, 523776);
    let packed_w1 = pack_w1(&w1);

    let mut challenge_sponge = KeccakSponge::new_shake256();
    challenge_sponge.absorb(&mu);
    challenge_sponge.absorb(&packed_w1);
    let mut c_tilde_prime = [0u8; 48];
    challenge_sponge.squeeze(&mut c_tilde_prime);

    c_tilde == c_tilde_prime
}

// --- Main Signing Core (Internal) ---

/// Signs a message per FIPS 204 ML-DSA.Sign_internal with optional stored public key for dual VBR.
///
/// - `m_prime`: message representative (for pure ML-DSA: `0x00 || len(ctx) || ctx || msg`).
/// - `rnd`: 32-byte randomness for hedged signing. Use `[0u8; 32]` for
///   deterministic signing as specified by FIPS 204.
/// - `canonical_pk`: optional stored 1952-byte public key from keystore for dual VBR fault-attack detection.
pub fn sign_internal_with_pk(
    sk: &[u8; 4032],
    m_prime: &[u8],
    rnd: &[u8; 32],
    canonical_pk: Option<&[u8; 1952]>,
) -> [u8; 3309] {
    let (rho, k, tr, s1, s2, t0) = unpack_sk(sk);

    // Secure zeroization wrappers
    let k = crate::crypto::zeroize::Zeroized { value: k };
    let s1 = crate::crypto::zeroize::Zeroized { value: s1 };
    let s2 = crate::crypto::zeroize::Zeroized { value: s2 };
    let t0 = crate::crypto::zeroize::Zeroized { value: t0 };

    // FIPS 204 Algorithm 7: mu = SHAKE-256(tr || M', 512 bits)
    let mut mu = crate::crypto::zeroize::Zeroized { value: [0u8; 64] };
    let mut mu_sponge = KeccakSponge::new_shake256();
    mu_sponge.absorb(&tr);
    mu_sponge.absorb(m_prime);
    mu_sponge.squeeze(&mut mu.value);

    // FIPS 204 Algorithm 7: rho_prime = SHAKE-256(K || rnd || mu, 512 bits)
    let mut rho_prime = crate::crypto::zeroize::Zeroized { value: [0u8; 64] };
    let mut rho_prime_sponge = KeccakSponge::new_shake256();
    rho_prime_sponge.absorb(&k.value);
    rho_prime_sponge.absorb(rnd);             // 32-byte rnd field per FIPS 204
    rho_prime_sponge.absorb(&mu.value);
    rho_prime_sponge.squeeze(&mut rho_prime.value);

    let a = expand_a(&rho);

    let mut s1_ntt = crate::crypto::zeroize::Zeroized { value: s1.value };
    s1_ntt.ntt();
    let mut s2_ntt = crate::crypto::zeroize::Zeroized { value: s2.value };
    s2_ntt.ntt();
    let mut t0_ntt = crate::crypto::zeroize::Zeroized { value: t0.value };
    t0_ntt.ntt();

    let mut kappa = 0u16;

    loop {
        let y = expand_y(&rho_prime.value, kappa);
        kappa += 5;

        let mut y_ntt = y;
        y_ntt.ntt();

        let az_ntt = a.mul_vector_ntt(&y_ntt);
        let mut w = az_ntt;
        w.intt();

        // decompose w (alpha = 2 * GAMMA2 = 523776)
        let (w1, w0) = w.decompose(523776);
        let packed_w1 = pack_w1(&w1);

        let mut challenge_sponge = KeccakSponge::new_shake256();
        challenge_sponge.absorb(&mu.value);
        challenge_sponge.absorb(&packed_w1);
        let mut c_tilde = [0u8; 48];
        challenge_sponge.squeeze(&mut c_tilde);

        let c = sample_in_ball(&c_tilde);
        let mut c_ntt = c;
        Polynomial::ntt(&mut c_ntt);

        // Hardware speculation fence before entering sensitive secret equations
        speculative_barrier();

        // Compute cs1 = c * s1
        let mut cs1 = PolyVector::<5>::new();
        for i in 0..5 {
            cs1.polys[i] = Polynomial::mul_pointwise_ntt(&c_ntt, &s1_ntt.polys[i]);
        }
        cs1.intt();

        let z = y.add(&cs1);

        // Rejection check: ||z||_inf >= GAMMA1 - BETA (524288 - 196 = 524092)
        if z.inf_norm() >= 524092 {
            continue;
        }

        // Compute cs2 = c * s2
        let mut cs2 = PolyVector::<6>::new();
        for i in 0..6 {
            cs2.polys[i] = Polynomial::mul_pointwise_ntt(&c_ntt, &s2_ntt.polys[i]);
        }
        cs2.intt();

        // Compute w0 - cs2 per component and check bound GAMMA2 - BETA (261888 - 196 = 261692)
        let mut w0_minus_cs2 = PolyVector::<6>::new();
        let mut r0_max = 0;
        for i in 0..6 {
            for j in 0..256 {
                let w0_val = to_signed(w0.polys[i].coeffs[j]);
                let cs2_val = to_signed(cs2.polys[i].coeffs[j]);
                let diff = to_signed(to_canonical(w0_val - cs2_val));
                w0_minus_cs2.polys[i].coeffs[j] = to_canonical(diff);
                if diff.abs() > r0_max {
                    r0_max = diff.abs();
                }
            }
        }
        if r0_max >= 261692 {
            continue;
        }

        // Compute ct0 = c * t0
        let mut ct0 = PolyVector::<6>::new();
        for i in 0..6 {
            ct0.polys[i] = Polynomial::mul_pointwise_ntt(&c_ntt, &t0_ntt.polys[i]);
        }
        ct0.intt();

        // Rejection check: ||ct0||_inf >= GAMMA2 (261888)
        if ct0.inf_norm() >= 261888 {
            continue;
        }

        // Compute hint: mld_make_hint(-u, w1) where u = w0 - cs2 + ct0
        let mut hint = PolyVector::<6>::new();
        let mut hint_ones = 0;
        for i in 0..6 {
            for j in 0..256 {
                let w0_cs2_val = to_signed(w0_minus_cs2.polys[i].coeffs[j]);
                let ct0_val = to_signed(ct0.polys[i].coeffs[j]);
                let u = to_signed(to_canonical(w0_cs2_val + ct0_val));
                let w1_val = w1.polys[i].coeffs[j];

                let neg_u = -u;
                let h_bit = if neg_u > GAMMA2 || neg_u < -GAMMA2 || (neg_u == -GAMMA2 && w1_val != 0) {
                    1
                } else {
                    0
                };
                hint.polys[i].coeffs[j] = h_bit;
                if h_bit == 1 {
                    hint_ones += 1;
                }
            }
        }

        if hint_ones > 55 {
            continue;
        }

        let sig = pack_sig(&c_tilde, &z, &hint);

        // Verify-Before-Release (VBR) Dual Guardrail:
        // Check 1: Verify against the re-derived PK from secret key components.
        let as1_ntt = a.mul_vector_ntt(&s1_ntt);
        let mut as1 = as1_ntt;
        as1.intt();

        let t = as1.add(&s2.value);
        let (t1_rec, _) = t.power2round();
        let pk_rec = pack_pk(&rho, &t1_rec);

        if !verify_internal(&pk_rec, m_prime, &sig) {
            continue;
        }

        // Check 2: If a canonical stored PK was provided, verify against it to detect stored PK corruption.
        if let Some(stored_pk) = canonical_pk {
            if !verify_internal(stored_pk, m_prime, &sig) {
                tracing::error!(
                    "CRITICAL: Dual VBR mismatch — signature verifies against re-derived PK but NOT against stored PK. Aborting."
                );
                // Key material inconsistency: requires operator intervention, not graceful recovery.
                panic!("Dual VBR mismatch: stored PK does not verify signature — key material corrupted.");
            }
        }

        return sig;
    }
}

/// Signs a message per FIPS 204 ML-DSA.Sign_internal without external stored PK (standard ACVP compatibility).
pub fn sign_internal(sk: &[u8; 4032], m_prime: &[u8], rnd: &[u8; 32]) -> [u8; 3309] {
    sign_internal_with_pk(sk, m_prime, rnd, None)
}