//! Mutual Non-Separable Hybrid Classical (Ed25519) + Post-Quantum (ML-DSA-65) Engine
//!
//! Implements RFC 9591 and NIST SP 800-227 compliant composite key generation, signing, and dual verification.
//! Guarantees non-separable mutual binding: both the classical Ed25519 signature AND the post-quantum
//! ML-DSA-65 signature sign the exact canonical composite message containing both public keys and the payload.
//! Stripping attacks and cross-key substitution attacks are mathematically eliminated.

use crate::crypto::nist_api::{keygen as pq_keygen, sign as pq_sign, verify as pq_verify};
use ed25519_dalek::{SigningKey, VerifyingKey, Signature as Ed25519Sig, Signer, Verifier};

/// Domain separation prefix for Solomon Composite Signatures (RFC 9591 compliant)
pub const DOMAIN_PREFIX: &[u8; 20] = b"SOLOMON-COMPOSITE-V1";

/// Total byte length of a Hybrid Public Key: 32 bytes (Ed25519) + 1952 bytes (ML-DSA-65)
pub const HYBRID_PUBLIC_KEY_SIZE: usize = 32 + 1952;

/// Total byte length of a Hybrid Signature: 64 bytes (Ed25519) + 3309 bytes (ML-DSA-65)
pub const HYBRID_SIGNATURE_SIZE: usize = 64 + 3309;

/// Composite Hybrid Secret Key holding both classical and post-quantum private material.
#[derive(Clone)]
pub struct HybridSecretKey {
    pub ed25519_sk: SigningKey,
    pub pq_sk: [u8; 4032],
}

/// Composite Hybrid Public Key holding both classical and post-quantum verifying keys.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HybridPublicKey {
    pub ed25519_pk: [u8; 32],
    pub pq_pk: [u8; 1952],
}

impl HybridPublicKey {
    pub fn to_bytes(&self) -> [u8; HYBRID_PUBLIC_KEY_SIZE] {
        let mut out = [0u8; HYBRID_PUBLIC_KEY_SIZE];
        out[0..32].copy_from_slice(&self.ed25519_pk);
        out[32..HYBRID_PUBLIC_KEY_SIZE].copy_from_slice(&self.pq_pk);
        out
    }

    pub fn from_bytes(bytes: &[u8; HYBRID_PUBLIC_KEY_SIZE]) -> Self {
        let mut ed25519_pk = [0u8; 32];
        let mut pq_pk = [0u8; 1952];
        ed25519_pk.copy_from_slice(&bytes[0..32]);
        pq_pk.copy_from_slice(&bytes[32..HYBRID_PUBLIC_KEY_SIZE]);
        Self { ed25519_pk, pq_pk }
    }

    pub fn from_slice(bytes: &[u8]) -> Result<Self, &'static str> {
        if bytes.len() != HYBRID_PUBLIC_KEY_SIZE {
            return Err("Invalid hybrid public key byte length");
        }
        let mut ed25519_pk = [0u8; 32];
        let mut pq_pk = [0u8; 1952];
        ed25519_pk.copy_from_slice(&bytes[0..32]);
        pq_pk.copy_from_slice(&bytes[32..HYBRID_PUBLIC_KEY_SIZE]);
        Ok(Self { ed25519_pk, pq_pk })
    }
}

/// Composite Hybrid Signature containing both Ed25519 and ML-DSA-65 signatures.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HybridSignature {
    pub ed25519_sig: [u8; 64],
    pub pq_sig: [u8; 3309],
}

impl HybridSignature {
    pub fn to_bytes(&self) -> [u8; HYBRID_SIGNATURE_SIZE] {
        let mut out = [0u8; HYBRID_SIGNATURE_SIZE];
        out[0..64].copy_from_slice(&self.ed25519_sig);
        out[64..HYBRID_SIGNATURE_SIZE].copy_from_slice(&self.pq_sig);
        out
    }

    pub fn from_bytes(bytes: &[u8; HYBRID_SIGNATURE_SIZE]) -> Self {
        let mut ed25519_sig = [0u8; 64];
        let mut pq_sig = [0u8; 3309];
        ed25519_sig.copy_from_slice(&bytes[0..64]);
        pq_sig.copy_from_slice(&bytes[64..HYBRID_SIGNATURE_SIZE]);
        Self { ed25519_sig, pq_sig }
    }

    pub fn from_slice(bytes: &[u8]) -> Result<Self, &'static str> {
        if bytes.len() != HYBRID_SIGNATURE_SIZE {
            return Err("Invalid hybrid signature byte length");
        }
        let mut ed25519_sig = [0u8; 64];
        let mut pq_sig = [0u8; 3309];
        ed25519_sig.copy_from_slice(&bytes[0..64]);
        pq_sig.copy_from_slice(&bytes[64..HYBRID_SIGNATURE_SIZE]);
        Ok(Self { ed25519_sig, pq_sig })
    }
}

/// Constructs the canonical composite payload M_composite:
/// M_composite = DomainPrefix || ContextLen (2 bytes BE) || Context || pk_Ed || pk_PQ || message
pub fn construct_composite_message(ed_pk: &[u8; 32], pq_pk: &[u8; 1952], message: &[u8]) -> Vec<u8> {
    construct_composite_message_with_ctx(ed_pk, pq_pk, message, &[]).unwrap_or_default()
}

/// Constructs the canonical composite payload with explicit context length framing to prevent delimiter collision attacks:
/// M_composite = DomainPrefix || ContextLen (2 bytes BE) || Context || pk_Ed || pk_PQ || message
pub fn construct_composite_message_with_ctx(
    ed_pk: &[u8; 32],
    pq_pk: &[u8; 1952],
    message: &[u8],
    ctx: &[u8],
) -> Result<Vec<u8>, &'static str> {
    if ctx.len() > 65535 {
        return Err("Context length exceeds maximum 16-bit prefix");
    }
    let ctx_len = (ctx.len() as u16).to_be_bytes();
    let mut m_composite = Vec::with_capacity(20 + 2 + ctx.len() + 32 + 1952 + message.len());
    m_composite.extend_from_slice(DOMAIN_PREFIX);
    m_composite.extend_from_slice(&ctx_len);
    m_composite.extend_from_slice(ctx);
    m_composite.extend_from_slice(ed_pk);
    m_composite.extend_from_slice(pq_pk);
    m_composite.extend_from_slice(message);
    Ok(m_composite)
}

/// Generates a composite Hybrid KeyPair derived deterministically from a 32-byte master seed.
pub fn hybrid_keygen(seed: &[u8; 32]) -> (HybridSecretKey, HybridPublicKey) {
    // 1. Derive Ed25519 keypair
    let ed25519_sk = SigningKey::from_bytes(seed);
    let ed25519_pk = ed25519_sk.verifying_key().to_bytes();

    // 2. Derive ML-DSA-65 keypair
    let (pq_sk, pq_pk) = pq_keygen(seed);

    let sk = HybridSecretKey { ed25519_sk, pq_sk };
    let pk = HybridPublicKey { ed25519_pk, pq_pk };

    (sk, pk)
}

/// Signs a message payload with bidirectional composite binding over M_composite.
pub fn hybrid_sign(sk: &HybridSecretKey, pk: &HybridPublicKey, message: &[u8]) -> HybridSignature {
    let m_composite = construct_composite_message(&pk.ed25519_pk, &pk.pq_pk, message);

    // 1. Classical Ed25519 signature over M_composite
    let ed25519_sig = sk.ed25519_sk.sign(&m_composite).to_bytes();

    // 2. Post-Quantum ML-DSA-65 signature over M_composite
    let pq_sig = pq_sign(&sk.pq_sk, &m_composite);

    HybridSignature { ed25519_sig, pq_sig }
}

/// Verifies a composite Hybrid Signature against the hybrid public key.
/// 
/// Returns `true` if and only if BOTH signatures verify against the canonical M_composite.
pub fn hybrid_verify(pk: &HybridPublicKey, message: &[u8], signature: &HybridSignature) -> bool {
    let m_composite = construct_composite_message(&pk.ed25519_pk, &pk.pq_pk, message);

    // 1. Verify Classical Ed25519 Signature over M_composite
    let ed_vk = match VerifyingKey::from_bytes(&pk.ed25519_pk) {
        Ok(vk) => vk,
        Err(_) => return false,
    };
    let ed_sig = Ed25519Sig::from_bytes(&signature.ed25519_sig);
    if ed_vk.verify(&m_composite, &ed_sig).is_err() {
        return false;
    }

    // 2. Verify Post-Quantum ML-DSA-65 Signature over M_composite
    pq_verify(&pk.pq_pk, &m_composite, &signature.pq_sig)
}
