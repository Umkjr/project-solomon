// solomon-core/src/hsm.rs
//! Hardware Security Module (HSM) and Key Storage Abstraction for Enterprise Key Management.

use crate::crypto::nist_api::keygen;
use crate::crypto::zeroize::Zeroized;

/// Pluggable Key Storage Backend trait for Enterprise Financial Networks.
pub trait KeyStorageBackend: Send + Sync {
    /// Return the human-readable identifier of the key storage provider.
    fn backend_name(&self) -> &'static str;

    /// Retrieve the public key associated with this key slot.
    fn get_public_key(&self) -> Result<[u8; 1952], String>;

    /// Sign an arbitrary payload message.
    fn sign_payload(&self, message: &[u8]) -> Result<[u8; 3309], String>;

    /// Sign an arbitrary payload message with injected hedging entropy.
    fn sign_hedged_payload(&self, message: &[u8], rnd: &[u8; 32]) -> Result<[u8; 3309], String>;

    /// Explicitly zeroize and wipe secret key material from memory.
    fn zeroize_keys(&mut self);
}

/// In-memory pinned, zeroize-protected software keystore.
pub struct SoftwarePinnedMemoryBackend {
    pk: [u8; 1952],
    sk: Zeroized<[u8; 4032]>,
}

impl SoftwarePinnedMemoryBackend {
    pub fn generate_new(seed: &[u8; 32]) -> Self {
        let (sk, pk) = keygen(seed);
        Self {
            pk,
            sk: Zeroized { value: sk },
        }
    }

    pub fn from_existing(pk: [u8; 1952], sk: [u8; 4032]) -> Self {
        Self {
            pk,
            sk: Zeroized { value: sk },
        }
    }
}

impl KeyStorageBackend for SoftwarePinnedMemoryBackend {
    fn backend_name(&self) -> &'static str {
        "SoftwarePinnedMemory (RAM-Locked with Zeroization)"
    }

    fn get_public_key(&self) -> Result<[u8; 1952], String> {
        Ok(self.pk)
    }

    fn sign_payload(&self, message: &[u8]) -> Result<[u8; 3309], String> {
        let rnd = [0u8; 32];
        let m_prime = crate::crypto::nist_api::format_m_prime_pub(message, &[]);
        Ok(crate::crypto::sign::sign_internal_with_pk(&self.sk.value, &m_prime, &rnd, Some(&self.pk)))
    }

    fn sign_hedged_payload(&self, message: &[u8], rnd: &[u8; 32]) -> Result<[u8; 3309], String> {
        let m_prime = crate::crypto::nist_api::format_m_prime_pub(message, b"");
        Ok(crate::crypto::sign::sign_internal_with_pk(&self.sk.value, &m_prime, rnd, Some(&self.pk)))
    }

    fn zeroize_keys(&mut self) {
        let empty = [0u8; 4032];
        self.sk = Zeroized { value: empty };
    }
}

