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

// --- Masking Vector y Sampling ---

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

        let mut coeffs = [0i32; 256];
        let mut buf = [0u8; 3];
        for j in 0..256 {
            sponge.squeeze(&mut buf);
            let z = (buf[0] as u32) | ((buf[1] as u32) << 8) | (((buf[2] as u32) & 0x0F) << 16);
            let val = GAMMA1 - z as i32;
            coeffs[j] = to_canonical(val);
        }
        y.polys[i] = Polynomial { coeffs };
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

// --- Challenge Polynomial c Sampling (SampleInBall) ---

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

    let mut buf = [0u8; 1];
    for i in (256 - 39)..256 {
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

pub fn verify_internal(pk: &[u8; 1952], msg: &[u8], sig: &[u8; 3309]) -> bool {
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

    let mut mu_sponge = KeccakSponge::new_shake256();
    mu_sponge.absorb(&tr);
    mu_sponge.absorb(msg);
    let mut mu = [0u8; 64];
    mu_sponge.squeeze(&mut mu);

    let a = expand_a(&rho);

    let mut z_ntt = z;
    z_ntt.ntt();

    let c = sample_in_ball(&c_tilde);
    let mut c_ntt = c;
    Polynomial::ntt(&mut c_ntt);

    let az_ntt = a.mul_vector_ntt(&z_ntt);
    let mut az = az_ntt;
    az.intt();

    let mut t1_ntt = t1;
    t1_ntt.ntt();

    let mut ct1 = PolyVector::<6>::new();
    for i in 0..6 {
        let prod_ntt = Polynomial::mul_pointwise_ntt(&c_ntt, &t1_ntt.polys[i]);
        let mut scaled_prod = prod_ntt;
        for j in 0..256 {
            let scaled_val = (scaled_prod.coeffs[j] as i64 * 8192) % Q as i64;
            scaled_prod.coeffs[j] = scaled_val as i32;
        }
        ct1.polys[i] = scaled_prod;
    }
    ct1.intt();

    let w_approx = az.sub(&ct1);

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

pub fn sign_internal(sk: &[u8; 4032], msg: &[u8]) -> [u8; 3309] {
    let (rho, k, tr, s1, s2, t0) = unpack_sk(sk);

    // Secure zeroization wrappers
    let k = crate::crypto::zeroize::Zeroized { value: k };
    let s1 = crate::crypto::zeroize::Zeroized { value: s1 };
    let s2 = crate::crypto::zeroize::Zeroized { value: s2 };
    let t0 = crate::crypto::zeroize::Zeroized { value: t0 };

    let mut mu = crate::crypto::zeroize::Zeroized { value: [0u8; 64] };
    let mut mu_sponge = KeccakSponge::new_shake256();
    mu_sponge.absorb(&tr);
    mu_sponge.absorb(msg);
    mu_sponge.squeeze(&mut mu.value);

    let mut rho_prime = crate::crypto::zeroize::Zeroized { value: [0u8; 64] };
    let mut rho_prime_sponge = KeccakSponge::new_shake256();
    rho_prime_sponge.absorb(&k.value);
    rho_prime_sponge.absorb(&mu.value);
    rho_prime_sponge.squeeze(&mut rho_prime.value);

    // Arithmetic Secret Masking (s_x = s_x_A + s_x_B mod Q)
    let mut s1_B = PolyVector::<5>::new();
    let mut s2_B = PolyVector::<6>::new();

    let mut share_sponge = KeccakSponge::new_shake256();
    share_sponge.absorb(&rho_prime.value);
    share_sponge.absorb(b"Project Solomon Share B Seed Prefix");

    for p in 0..5 {
        for i in 0..256 {
            let mut buf = [0u8; 4];
            share_sponge.squeeze(&mut buf);
            let val = (buf[0] as u32) | ((buf[1] as u32) << 8) | ((buf[2] as u32) << 16) | ((buf[3] as u32) << 24);
            s1_B.polys[p].coeffs[i] = (val as i64 % Q as i64) as i32;
        }
    }
    for p in 0..6 {
        for i in 0..256 {
            let mut buf = [0u8; 4];
            share_sponge.squeeze(&mut buf);
            let val = (buf[0] as u32) | ((buf[1] as u32) << 8) | ((buf[2] as u32) << 16) | ((buf[3] as u32) << 24);
            s2_B.polys[p].coeffs[i] = (val as i64 % Q as i64) as i32;
        }
    }

    let s1_A = s1.sub(&s1_B);
    let s2_A = s2.sub(&s2_B);

    let mut shares = SecretShares {
        s1_A,
        s1_B,
        s2_A,
        s2_B,
    };

    shares.s1_A.ntt();
    shares.s1_B.ntt();
    shares.s2_A.ntt();
    shares.s2_B.ntt();

    let a = expand_a(&rho);

    let mut t0_ntt = crate::crypto::zeroize::Zeroized { value: t0.value };
    t0_ntt.ntt();

    let mut kappa = 0u16;

    loop {
        let y = expand_y(&rho_prime.value, kappa);

        let mut y_ntt = y;
        y_ntt.ntt();

        let az_ntt = a.mul_vector_ntt(&y_ntt);
        let mut w = az_ntt;
        w.intt();

        // decompose w (alpha = 2 * GAMMA2 = 523776)
        let (w1, _w0) = w.decompose(523776);
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

        // Compute z = y + c * s1 using secret shares
        let mut cs1_A = PolyVector::<5>::new();
        let mut cs1_B = PolyVector::<5>::new();
        for i in 0..5 {
            cs1_A.polys[i] = Polynomial::mul_pointwise_ntt(&c_ntt, &shares.s1_A.polys[i]);
            cs1_B.polys[i] = Polynomial::mul_pointwise_ntt(&c_ntt, &shares.s1_B.polys[i]);
        }
        cs1_A.intt();
        cs1_B.intt();

        let cs1 = cs1_A.add(&cs1_B);
        let z = y.add(&cs1);

        // Compute cs2 using secret shares
        let mut cs2_A = PolyVector::<6>::new();
        let mut cs2_B = PolyVector::<6>::new();
        for i in 0..6 {
            cs2_A.polys[i] = Polynomial::mul_pointwise_ntt(&c_ntt, &shares.s2_A.polys[i]);
            cs2_B.polys[i] = Polynomial::mul_pointwise_ntt(&c_ntt, &shares.s2_B.polys[i]);
        }
        cs2_A.intt();
        cs2_B.intt();
        let cs2 = cs2_A.add(&cs2_B);

        // Compute ct0
        let mut ct0 = PolyVector::<6>::new();
        for i in 0..6 {
            ct0.polys[i] = Polynomial::mul_pointwise_ntt(&c_ntt, &t0_ntt.polys[i]);
        }
        ct0.intt();

        // Compute approximation: r = w - cs2 + ct0
        let w_minus_cs2 = w.sub(&cs2);
        let r = w_minus_cs2.add(&ct0);

        // Decompose r (alpha = 2 * GAMMA2 = 523776)
        let (_r1, r0) = r.decompose(523776);

        let mut loop_state = 0;
        let mut rejected = false;
        let mut hint = PolyVector::<6>::new();

        // Control flow flattening state machine for decompiler obfuscation
        while loop_state < 4 {
            match loop_state {
                0 => {
                    // Rejection bounds check (GAMMA1 - BETA = 524288 - 196 = 524092)
                    if z.inf_norm() >= 524092 {
                        rejected = true;
                        loop_state = 99; // abort
                    } else {
                        loop_state = 1;
                    }
                }
                1 => {
                    // Rejection bounds check (GAMMA2 - BETA = 261888 - 196 = 261692)
                    if r0.inf_norm() >= 261692 {
                        rejected = true;
                        loop_state = 99; // abort
                    } else {
                        loop_state = 2;
                    }
                }
                2 => {
                    // Compute hint difference: z_diff = cs2 - ct0
                    let z_diff = cs2.sub(&ct0);
                    hint = r.make_hint(&z_diff, 523776);
                    loop_state = 3;
                }
                3 => {
                    let mut hint_ones = 0;
                    for p in 0..6 {
                        for i in 0..256 {
                            if hint.polys[p].coeffs[i] == 1 {
                                hint_ones += 1;
                            }
                        }
                    }
                    if hint_ones > 55 {
                        rejected = true;
                    }
                    loop_state = 4; // terminate machine
                }
                _ => {
                    break;
                }
            }
        }

        if rejected {
            kappa += 5;
            continue;
        }

        let sig = pack_sig(&c_tilde, &z, &hint);

        // Verify-Before-Release fault-attack guardrail
        let s1_ntt = shares.s1_A.add(&shares.s1_B);
        let as1_ntt = a.mul_vector_ntt(&s1_ntt);
        let mut as1 = as1_ntt;
        as1.intt();

        let mut s2_spatial = shares.s2_A.add(&shares.s2_B);
        s2_spatial.intt();

        let t = as1.add(&s2_spatial);
        let (t1_rec, _) = t.power2round();
        let pk_rec = pack_pk(&rho, &t1_rec);

        if !verify_internal(&pk_rec, msg, &sig) {
            core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
            panic!("Verify-Before-Release fault guard triggered: internal verification failed!");
        }

        return sig;
    }
}