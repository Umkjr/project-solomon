//! Audited FIPS 204 ML-DSA-65 implementation using RustCrypto's `ml-dsa` crate.
//!
//! Provides an audited, drop-in replacement for key generation, signing, and verification
//! adhering strictly to NIST FIPS 204 parameter set ML-DSA-65.

use ml_dsa::{
    MlDsa65, ExpandedSigningKey, VerifyingKey, Signature,
    EncodedVerifyingKey, EncodedSignature, ExpandedSigningKeyBytes,
    Seed, B32, Keypair,
};

pub const PK_SIZE: usize = 1952;
pub const SK_SIZE: usize = 4032;
pub const SIG_SIZE: usize = 3309;
pub const SEED_SIZE: usize = 32;

/// Audited ML-DSA-65 Engine wrapping RustCrypto primitives.
pub struct AuditedMlDsa65;

impl AuditedMlDsa65 {
    /// Deterministically generates an expanded keypair (sk: 4032 bytes, pk: 1952 bytes) from a 32-byte seed.
    /// Follows FIPS 204 Algorithm 6: `ML-DSA.KeyGen_internal`.
    pub fn keygen(seed: &[u8; 32]) -> ([u8; SK_SIZE], [u8; PK_SIZE]) {
        let mut seed_arr = Seed::default();
        seed_arr.copy_from_slice(seed);
        let expanded_sk = ExpandedSigningKey::<MlDsa65>::from_seed(&seed_arr);
        
        let vk = Keypair::verifying_key(&expanded_sk);
        let enc_vk = vk.encode();

        let mut pk = [0u8; PK_SIZE];
        pk.copy_from_slice(enc_vk.as_slice());

        #[allow(deprecated)]
        let enc_sk = expanded_sk.to_expanded();
        let mut sk = [0u8; SK_SIZE];
        sk.copy_from_slice(enc_sk.as_slice());

        (sk, pk)
    }

    /// Signs an arbitrary message using a 32-byte seed directly (FIPS 204 Algorithm 2).
    pub fn sign_with_seed(seed: &[u8; 32], message: &[u8], rnd: &[u8; 32]) -> [u8; SIG_SIZE] {
        let mut seed_arr = Seed::default();
        seed_arr.copy_from_slice(seed);
        let expanded_sk = ExpandedSigningKey::<MlDsa65>::from_seed(&seed_arr);
        
        let mut rnd_arr = B32::default();
        rnd_arr.copy_from_slice(rnd);

        let m_prime = format_m_prime(message, &[]);
        let sig = expanded_sk.sign_internal(&[&m_prime], &rnd_arr);
        let enc_sig = sig.encode();

        let mut out = [0u8; SIG_SIZE];
        out.copy_from_slice(enc_sig.as_slice());
        out
    }

    /// Signs an internal formatted message buffer `m_prime` (FIPS 204 Algorithm 7: `ML-DSA.Sign_internal`).
    pub fn sign_internal_with_seed(seed: &[u8; 32], m_prime: &[u8], rnd: &[u8; 32]) -> [u8; SIG_SIZE] {
        let mut seed_arr = Seed::default();
        seed_arr.copy_from_slice(seed);
        let expanded_sk = ExpandedSigningKey::<MlDsa65>::from_seed(&seed_arr);
        
        let mut rnd_arr = B32::default();
        rnd_arr.copy_from_slice(rnd);

        let sig = expanded_sk.sign_internal(&[m_prime], &rnd_arr);
        let enc_sig = sig.encode();

        let mut out = [0u8; SIG_SIZE];
        out.copy_from_slice(enc_sig.as_slice());
        out
    }

    /// Signs an internal formatted message buffer `m_prime` from an expanded secret key buffer.
    pub fn sign_internal_with_sk(sk_bytes: &[u8; SK_SIZE], m_prime: &[u8], rnd: &[u8; 32]) -> [u8; SIG_SIZE] {
        let mut sk_arr = ExpandedSigningKeyBytes::<MlDsa65>::default();
        sk_arr.copy_from_slice(sk_bytes);
        #[allow(deprecated)]
        let expanded_sk = ExpandedSigningKey::<MlDsa65>::from_expanded(&sk_arr);
        
        let mut rnd_arr = B32::default();
        rnd_arr.copy_from_slice(rnd);

        let sig = expanded_sk.sign_internal(&[m_prime], &rnd_arr);
        let enc_sig = sig.encode();

        let mut out = [0u8; SIG_SIZE];
        out.copy_from_slice(enc_sig.as_slice());
        out
    }

    /// Verifies a signature against a public key and raw message with optional context (FIPS 204 Algorithm 3).
    pub fn verify(pk_bytes: &[u8; PK_SIZE], message: &[u8], sig_bytes: &[u8; SIG_SIZE]) -> bool {
        Self::verify_with_context(pk_bytes, message, &[], sig_bytes)
    }

    /// Verifies a signature against a public key, raw message, and context string.
    pub fn verify_with_context(
        pk_bytes: &[u8; PK_SIZE],
        message: &[u8],
        ctx: &[u8],
        sig_bytes: &[u8; SIG_SIZE],
    ) -> bool {
        let mut pk_arr = EncodedVerifyingKey::<MlDsa65>::default();
        pk_arr.copy_from_slice(pk_bytes);
        let vk = VerifyingKey::<MlDsa65>::decode(&pk_arr);

        let mut sig_arr = EncodedSignature::<MlDsa65>::default();
        sig_arr.copy_from_slice(sig_bytes);
        let Some(sig) = Signature::<MlDsa65>::decode(&sig_arr) else {
            return false;
        };

        vk.verify_with_context(message, ctx, &sig)
    }

    /// Verifies an internal pre-formatted buffer `m_prime` (FIPS 204 Algorithm 8: `ML-DSA.Verify_internal`).
    pub fn verify_internal(pk_bytes: &[u8; PK_SIZE], m_prime: &[u8], sig_bytes: &[u8; SIG_SIZE]) -> bool {
        let mut pk_arr = EncodedVerifyingKey::<MlDsa65>::default();
        pk_arr.copy_from_slice(pk_bytes);
        let vk = VerifyingKey::<MlDsa65>::decode(&pk_arr);

        let mut sig_arr = EncodedSignature::<MlDsa65>::default();
        sig_arr.copy_from_slice(sig_bytes);
        let Some(sig) = Signature::<MlDsa65>::decode(&sig_arr) else {
            return false;
        };

        vk.verify_internal(m_prime, &sig)
    }
}

/// Helper function to format M' = 0x00 || len(ctx) || ctx || msg per FIPS 204 Section 5.2.
pub fn format_m_prime(message: &[u8], ctx: &[u8]) -> Vec<u8> {
    let mut m_prime = Vec::with_capacity(2 + ctx.len() + message.len());
    m_prime.push(0x00);
    m_prime.push(ctx.len() as u8);
    m_prime.extend_from_slice(ctx);
    m_prime.extend_from_slice(message);
    m_prime
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_audited_mldsa_keygen_sign_verify_roundtrip() {
        let seed = [0x42u8; 32];
        let (sk, pk) = AuditedMlDsa65::keygen(&seed);
        assert_eq!(pk.len(), PK_SIZE);
        assert_eq!(sk.len(), SK_SIZE);

        let msg = b"Project Solomon Audited Post-Quantum Payment Payload";
        let rnd = [0x00u8; 32]; // deterministic mode

        let sig = AuditedMlDsa65::sign_with_seed(&seed, msg, &rnd);
        assert_eq!(sig.len(), SIG_SIZE);

        let valid = AuditedMlDsa65::verify(&pk, msg, &sig);
        assert!(valid, "Valid signature must verify with audited engine");

        let mut tampered_sig = sig;
        tampered_sig[0] ^= 0xFF;
        assert!(!AuditedMlDsa65::verify(&pk, msg, &tampered_sig), "Tampered signature must fail");

        let mut tampered_pk = pk;
        tampered_pk[0] ^= 0xFF;
        assert!(!AuditedMlDsa65::verify(&tampered_pk, msg, &sig), "Tampered public key must fail");
    }

    #[test]
    fn test_audited_mldsa_internal_roundtrip() {
        let seed = [0x99u8; 32];
        let (sk, pk) = AuditedMlDsa65::keygen(&seed);
        let m_prime = b"\x00\x00Payment transaction internal buffer";
        let rnd = [0x11u8; 32];

        let sig = AuditedMlDsa65::sign_internal_with_sk(&sk, m_prime, &rnd);
        let valid = AuditedMlDsa65::verify_internal(&pk, m_prime, &sig);
        assert!(valid, "Internal signature must verify with verify_internal");
    }
}
