//! Public NIST FIPS 204 ML-DSA-65 standard API.
//!
//! This module exposes standard key generation, signing, and verification routines
//! mapped to our constant-time mathematical core and bit-packing serializer.

use crate::crypto::shake::KeccakSponge;
use crate::crypto::matrix::{expand_a, expand_s};
use crate::crypto::packing::{pack_pk, pack_sk};
use crate::crypto::sign::{sign_internal, verify_internal};

/// Generates a post-quantum ML-DSA-65 key pair from a 32-byte seed.
///
/// Returns a tuple containing:
/// - The private key `sk` (4032 bytes)
/// - The public key `pk` (1952 bytes)
pub fn keygen(seed: &[u8; 32]) -> ([u8; 4032], [u8; 1952]) {
    // 1. Expand seed using SHAKE-256 to obtain key generation seeds
    let mut sponge = KeccakSponge::new_shake256();
    sponge.absorb(seed);
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

/// Generates an ML-DSA-65 signature on a message using the private key.
///
/// Returns the packed signature (3309 bytes).
pub fn sign(sk: &[u8; 4032], msg: &[u8]) -> [u8; 3309] {
    sign_internal(sk, msg)
}

/// Verifies an ML-DSA-65 signature on a message using the public key.
///
/// Returns `true` if the signature is valid, `false` otherwise.
pub fn verify(pk: &[u8; 1952], msg: &[u8], sig: &[u8; 3309]) -> bool {
    verify_internal(pk, msg, sig)
}