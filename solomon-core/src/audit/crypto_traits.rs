//! Crypto-agnostic trait abstractions for the RBI audit subsystem.
//! Decouples the audit chain, segment sealing, and SAR signing from
//! any concrete algorithm so that SHA-256, SHAKE-256, or any future
//! NIST-approved primitive can be swapped by changing one config line.

use std::sync::Arc;
use sha2::{Sha256, Digest};
use ed25519_dalek::Signer as DalekSigner;
use crate::crypto::shake::KeccakSponge;

/// A pluggable hash function for the audit chain.
/// Implementors must produce a fixed-length, deterministic digest.
pub trait AuditHasher: Send + Sync {
    /// Returns the human-readable algorithm name recorded in every audit record
    /// (e.g. "SHA-256", "SHAKE-256").
    fn algorithm_id(&self) -> &'static str;

    /// Computes a hex-encoded digest over the concatenation of all `inputs` slices.
    fn hex_digest(&self, inputs: &[&[u8]]) -> String;
}

/// A pluggable signing algorithm for segment seals and SAR reports.
/// Implementors must produce a deterministic, verifiable byte-level signature.
pub trait AuditSigner: Send + Sync {
    /// Returns the human-readable algorithm name (e.g. "Ed25519", "ML-DSA-65").
    fn algorithm_id(&self) -> &'static str;

    /// Signs `payload` and returns the raw signature bytes.
    fn sign_bytes(&self, payload: &[u8]) -> Vec<u8>;
}

// ──────────────────────────────────────────────────────────────────────────────
// CONCRETE IMPLEMENTATION A: SHA-256 hasher (current default)
// ──────────────────────────────────────────────────────────────────────────────

#[derive(Default, Clone, Copy, Debug)]
pub struct Sha256AuditHasher;

impl AuditHasher for Sha256AuditHasher {
    fn algorithm_id(&self) -> &'static str {
        "SHA-256"
    }

    fn hex_digest(&self, inputs: &[&[u8]]) -> String {
        let mut h = Sha256::new();
        for chunk in inputs {
            h.update(chunk);
        }
        format!("{:x}", h.finalize())
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// CONCRETE IMPLEMENTATION B: SHAKE-256 (256-bit output) hasher
// ──────────────────────────────────────────────────────────────────────────────

#[derive(Default, Clone, Copy, Debug)]
pub struct Shake256AuditHasher;

impl AuditHasher for Shake256AuditHasher {
    fn algorithm_id(&self) -> &'static str {
        "SHAKE-256"
    }

    fn hex_digest(&self, inputs: &[&[u8]]) -> String {
        let mut sponge = KeccakSponge::new_shake256();
        for chunk in inputs {
            sponge.absorb(chunk);
        }
        let mut out = [0u8; 32];
        sponge.squeeze(&mut out);
        hex::encode(out)
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// CONCRETE IMPLEMENTATION C: Ed25519 signer (current default)
// ──────────────────────────────────────────────────────────────────────────────

pub struct Ed25519AuditSigner {
    pub key: Arc<ed25519_dalek::SigningKey>,
}

impl Ed25519AuditSigner {
    pub fn new(key: ed25519_dalek::SigningKey) -> Self {
        Self {
            key: Arc::new(key),
        }
    }

    pub fn from_arc(key: Arc<ed25519_dalek::SigningKey>) -> Self {
        Self { key }
    }
}

impl AuditSigner for Ed25519AuditSigner {
    fn algorithm_id(&self) -> &'static str {
        "Ed25519"
    }

    fn sign_bytes(&self, payload: &[u8]) -> Vec<u8> {
        self.key.sign(payload).to_bytes().to_vec()
    }
}
