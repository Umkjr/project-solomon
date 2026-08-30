//! Public NIST FIPS 204 ML-DSA-65 standard API.
//!
//! This module exposes standard key generation, signing, and verification routines
//! mapped to our constant-time mathematical core and bit-packing serializer.

use crate::crypto::shake::KeccakSponge;
use crate::crypto::matrix::{expand_a, expand_s};
use crate::crypto::packing::{pack_pk, pack_sk};
pub use crate::crypto::sign::{sign_internal, sign_internal_with_pk, verify_internal};

pub const MLDSA_SEED_BYTES: usize = 32;
pub const MLDSA_SK_BYTES: usize = 4032;
pub const MLDSA_PK_BYTES: usize = 1952;
pub const MLDSA_SIG_BYTES: usize = 3309;

/// Generates a post-quantum ML-DSA-65 key pair from a 32-byte seed.
///
/// Returns a tuple containing:
/// - The private key `sk` (4032 bytes)
/// - The public key `pk` (1952 bytes)
pub fn keygen(seed: &[u8; 32]) -> ([u8; 4032], [u8; 1952]) {
    // 1. Expand seed using SHAKE-256 to obtain key generation seeds.
    //    FIPS 204 Algorithm 1: (rho, rho', K) = SHAKE-256(xi || k || l, 1024 bits)
    //    For ML-DSA-65: k = 6, l = 5.
    let mut sponge = KeccakSponge::new_shake256();
    sponge.absorb(seed);
    sponge.absorb(&[6u8, 5u8]); // k || l parameter binding per FIPS 204
    let mut expanded = crate::crypto::zeroize::Zeroized { value: [0u8; 128] };
    sponge.squeeze(&mut expanded.value);


    let mut rho = [0u8; 32];
    let mut rho_prime = crate::crypto::zeroize::Zeroized { value: [0u8; 64] };
    let mut k = crate::crypto::zeroize::Zeroized { value: [0u8; 32] };

    rho.copy_from_slice(&expanded.value[0..32]);
    rho_prime.value.copy_from_slice(&expanded.value[32..96]);
    k.value.copy_from_slice(&expanded.value[96..128]);

    // 2. Expand master matrix A
    let a = expand_a(&rho);

    // 3. Sample secret vectors s1 and s2
    let (s1, s2) = expand_s(&rho_prime.value);
    let s1 = crate::crypto::zeroize::Zeroized { value: s1 };
    let s2 = crate::crypto::zeroize::Zeroized { value: s2 };

    // 4. Compute t = A * s1 + s2
    let mut s1_ntt = crate::crypto::zeroize::Zeroized { value: s1.value };
    s1_ntt.ntt();
    let as1_ntt = a.mul_vector_ntt(&s1_ntt);
    let mut as1 = as1_ntt;
    as1.intt();
    let t = as1.add(&s2);

    // 5. Decompose t into high and low bits
    let (t1, t0) = t.power2round();
    let t0 = crate::crypto::zeroize::Zeroized { value: t0 };

    // 6. Pack public key and compute hash tr
    let pk = pack_pk(&rho, &t1);
    
    let mut tr_sponge = KeccakSponge::new_shake256();
    tr_sponge.absorb(&pk);
    let mut tr = crate::crypto::zeroize::Zeroized { value: [0u8; 64] };
    tr_sponge.squeeze(&mut tr.value);

    // 7. Pack private key
    let sk = pack_sk(&rho, &k.value, &tr.value, &s1.value, &s2.value, &t0.value);

    (sk, pk)
}

/// Formats the message representative M' per FIPS 204:
/// M' = 0x00 || len(ctx) as u8 || ctx || msg
pub fn format_m_prime_pub(msg: &[u8], ctx: &[u8]) -> Vec<u8> {
    assert!(ctx.len() <= 255, "Context string must not exceed 255 bytes per FIPS 204");
    let mut m_prime = Vec::with_capacity(2 + ctx.len() + msg.len());
    m_prime.push(0x00);
    m_prime.push(ctx.len() as u8);
    m_prime.extend_from_slice(ctx);
    m_prime.extend_from_slice(msg);
    m_prime
}

fn format_m_prime(msg: &[u8], ctx: &[u8]) -> Vec<u8> {
    format_m_prime_pub(msg, ctx)
}

/// Generates an ML-DSA-65 signature on a message using the private key.
///
/// Uses deterministic signing (rnd = 0x00...00) per FIPS 204 §5.2 for
/// testability and reproducibility. For production use with a live RNG,
/// call `sign_hedged()` instead.
///
/// Returns the packed signature (3309 bytes).
pub fn sign(sk: &[u8; 4032], msg: &[u8]) -> [u8; 3309] {
    let rnd = [0u8; 32]; // deterministic: rnd = 0
    let m_prime = format_m_prime(msg, &[]);
    sign_internal(sk, &m_prime, &rnd)
}

/// Generates an ML-DSA-65 signature using hedged (randomized) signing with optional context.
///
/// Accepts an externally supplied 32-byte `rnd` value for hedged signing
/// per FIPS 204 §5.2. Callers should supply 32 cryptographically random bytes.
/// Optionally binds a `ctx` context string (up to 255 bytes, empty for standard signing).
pub fn sign_hedged(sk: &[u8; 4032], msg: &[u8], rnd: &[u8; 32], ctx: &[u8]) -> [u8; 3309] {
    let m_prime = format_m_prime(msg, ctx);
    sign_internal(sk, &m_prime, rnd)
}

/// Verifies an ML-DSA-65 signature on a message using the public key.
///
/// Uses an empty context string (standard signing). For context-bound
/// verification call `verify_ctx()`.
///
/// Returns `true` if the signature is valid, `false` otherwise.
pub fn verify(pk: &[u8; 1952], msg: &[u8], sig: &[u8; 3309]) -> bool {
    verify_ctx(pk, msg, sig, &[])
}

/// Verifies an ML-DSA-65 signature with an explicit context string.
///
/// The `ctx` must match exactly what was used during signing.
pub fn verify_ctx(pk: &[u8; 1952], msg: &[u8], sig: &[u8; 3309], ctx: &[u8]) -> bool {
    if ctx.len() > 255 {
        return false;
    }
    let m_prime = format_m_prime(msg, ctx);
    verify_internal(pk, &m_prime, sig)
}

/// Signs a message using deterministic random seed injection per FIPS 204 Section 5.3.
///
/// Directly feeds the supplied 32-byte `deterministic_rnd` seed into SHAKE-256 expansion
/// for exact byte-for-byte reproducibility against official NIST ACVP vectors.
pub fn sign_internal_deterministic(
    sk: &[u8; MLDSA_SK_BYTES],
    message: &[u8],
    deterministic_rnd: &[u8; MLDSA_SEED_BYTES],
) -> Result<[u8; MLDSA_SIG_BYTES], &'static str> {
    let m_prime = format_m_prime(message, &[]);
    Ok(sign_internal(sk, &m_prime, deterministic_rnd))
}

/// Signs a raw message representative M' directly with deterministic seed injection (for internal ACVP testing).
pub fn sign_raw_m_prime_deterministic(
    sk: &[u8; MLDSA_SK_BYTES],
    m_prime: &[u8],
    deterministic_rnd: &[u8; MLDSA_SEED_BYTES],
) -> Result<[u8; MLDSA_SIG_BYTES], &'static str> {
    Ok(sign_internal(sk, m_prime, deterministic_rnd))
}