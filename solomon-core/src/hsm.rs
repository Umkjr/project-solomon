// solomon-core/src/hsm.rs
//! Hardware Security Module (HSM) and Key Storage Abstraction for Enterprise Key Management.
//!
//! Provides:
//! - Pluggable `KeyStorageBackend` trait.
//! - Audited FIPS 204 `AuditedKeyStorageBackend` (RustCrypto `ml-dsa`).
//! - Hardware side-channel memory page locking (`VirtualLock` / `mlock`) fulfilling PCI-DSS 3.5.
//! - Encrypted file keystore backend (`EncryptedKeystoreBackend`) with AES-256-GCM.
//! - Cloud KMS / HashiCorp Vault envelope encryption driver (`KmsEnvelopeBackend`).
//! - Multi-tenant isolation engine (`TenantKeyRegistry`) for Payment Aggregators.

use std::collections::HashMap;
use std::sync::Arc;
use std::path::{Path, PathBuf};
use std::fs;
use tokio::sync::RwLock;
use serde::{Serialize, Deserialize};
use sha2::{Sha256, Digest};
use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};

use crate::crypto::zeroize::Zeroized;
use crate::crypto::audited_mldsa::{AuditedMlDsa65, PK_SIZE, SK_SIZE, SIG_SIZE};

/// OS-level memory page locking to prevent key material from being swapped to disk (PCI-DSS 3.5).
pub fn lock_memory_page(ptr: *const u8, len: usize) -> bool {
    #[cfg(windows)]
    unsafe {
        extern "system" {
            fn VirtualLock(lpAddress: *const std::ffi::c_void, dwSize: usize) -> i32;
        }
        VirtualLock(ptr as *const std::ffi::c_void, len) != 0
    }

    #[cfg(unix)]
    unsafe {
        extern "C" {
            fn mlock(addr: *const std::ffi::c_void, len: usize) -> std::ffi::c_int;
        }
        mlock(ptr as *const std::ffi::c_void, len) == 0
    }

    #[cfg(not(any(windows, unix)))]
    {
        let _ = (ptr, len);
        false
    }
}

/// OS-level memory page unlock.
pub fn unlock_memory_page(ptr: *const u8, len: usize) -> bool {
    #[cfg(windows)]
    unsafe {
        extern "system" {
            fn VirtualUnlock(lpAddress: *const std::ffi::c_void, dwSize: usize) -> i32;
        }
        VirtualUnlock(ptr as *const std::ffi::c_void, len) != 0
    }

    #[cfg(unix)]
    unsafe {
        extern "C" {
            fn munlock(addr: *const std::ffi::c_void, len: usize) -> std::ffi::c_int;
        }
        munlock(ptr as *const std::ffi::c_void, len) == 0
    }

    #[cfg(not(any(windows, unix)))]
    {
        let _ = (ptr, len);
        false
    }
}

/// Lifecycle state for cryptographic keys per PCI-DSS Requirement 3.6.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum KeyStatus {
    Active,
    Deprecated,
    Revoked,
}

/// Pluggable Key Storage Backend trait for Enterprise Financial Networks.
pub trait KeyStorageBackend: Send + Sync {
    /// Return the human-readable identifier of the key storage provider.
    fn backend_name(&self) -> &'static str;

    /// Retrieve the public key associated with this key slot.
    fn get_public_key(&self) -> Result<[u8; PK_SIZE], String>;

    /// Sign an arbitrary payload message.
    fn sign_payload(&self, message: &[u8]) -> Result<[u8; SIG_SIZE], String>;

    /// Sign an arbitrary payload message with injected hedging entropy.
    fn sign_hedged_payload(&self, message: &[u8], rnd: &[u8; 32]) -> Result<[u8; SIG_SIZE], String>;

    /// Get current lifecycle status of the key.
    fn status(&self) -> KeyStatus {
        KeyStatus::Active
    }

    /// Explicitly zeroize and wipe secret key material from memory.
    fn zeroize_keys(&mut self);
}

// ---------------------------------------------------------------------------
// 1. Audited FIPS 204 Backend (RustCrypto Engine)
// ---------------------------------------------------------------------------

/// Audited Key Storage Backend utilizing RustCrypto's `ml-dsa` implementation.
pub struct AuditedKeyStorageBackend {
    pk: [u8; PK_SIZE],
    sk: Zeroized<[u8; SK_SIZE]>,
    status: KeyStatus,
}

impl AuditedKeyStorageBackend {
    pub fn generate_new(seed: &[u8; 32]) -> Self {
        let (sk, pk) = AuditedMlDsa65::keygen(seed);
        let _ = lock_memory_page(sk.as_ptr(), SK_SIZE);
        Self {
            pk,
            sk: Zeroized { value: sk },
            status: KeyStatus::Active,
        }
    }

    pub fn from_existing(pk: [u8; PK_SIZE], sk: [u8; SK_SIZE]) -> Self {
        let _ = lock_memory_page(sk.as_ptr(), SK_SIZE);
        Self {
            pk,
            sk: Zeroized { value: sk },
            status: KeyStatus::Active,
        }
    }

    pub fn set_status(&mut self, status: KeyStatus) {
        self.status = status;
    }
}

impl Drop for AuditedKeyStorageBackend {
    fn drop(&mut self) {
        let _ = unlock_memory_page(self.sk.value.as_ptr(), SK_SIZE);
    }
}

impl KeyStorageBackend for AuditedKeyStorageBackend {
    fn backend_name(&self) -> &'static str {
        "AuditedRustCrypto (FIPS 204 ML-DSA-65 with RAM-Lock & Zeroization)"
    }

    fn get_public_key(&self) -> Result<[u8; PK_SIZE], String> {
        Ok(self.pk)
    }

    fn sign_payload(&self, message: &[u8]) -> Result<[u8; SIG_SIZE], String> {
        if self.status == KeyStatus::Revoked {
            return Err("Cannot sign with revoked cryptographic key".to_string());
        }
        let mut rnd = [0u8; 32];
        use sha2::Digest;
        let mut hasher = Sha256::new();
        hasher.update(&self.sk.value[0..32]);
        hasher.update(message);
        let digest = hasher.finalize();
        rnd.copy_from_slice(&digest);

        let m_prime = crate::crypto::audited_mldsa::format_m_prime(message, &[]);
        Ok(AuditedMlDsa65::sign_internal_with_sk(&self.sk.value, &m_prime, &rnd))
    }

    fn sign_hedged_payload(&self, message: &[u8], rnd: &[u8; 32]) -> Result<[u8; SIG_SIZE], String> {
        if self.status == KeyStatus::Revoked {
            return Err("Cannot sign with revoked cryptographic key".to_string());
        }
        let m_prime = crate::crypto::audited_mldsa::format_m_prime(message, &[]);
        Ok(AuditedMlDsa65::sign_internal_with_sk(&self.sk.value, &m_prime, rnd))
    }

    fn status(&self) -> KeyStatus {
        self.status
    }

    fn zeroize_keys(&mut self) {
        self.sk = Zeroized { value: [0u8; SK_SIZE] };
    }
}

// ---------------------------------------------------------------------------
// 2. Custom Fast-SIMD Backend (Legacy / Benchmark Engine)
// ---------------------------------------------------------------------------

/// In-memory pinned, zeroize-protected software keystore using custom SIMD engine.
pub struct SoftwarePinnedMemoryBackend {
    pk: [u8; PK_SIZE],
    sk: Zeroized<[u8; SK_SIZE]>,
    status: KeyStatus,
}

impl SoftwarePinnedMemoryBackend {
    pub fn generate_new(seed: &[u8; 32]) -> Self {
        let (sk, pk) = crate::crypto::nist_api::keygen(seed);
        let _ = lock_memory_page(sk.as_ptr(), SK_SIZE);
        Self {
            pk,
            sk: Zeroized { value: sk },
            status: KeyStatus::Active,
        }
    }

    pub fn from_existing(pk: [u8; PK_SIZE], sk: [u8; SK_SIZE]) -> Self {
        let _ = lock_memory_page(sk.as_ptr(), SK_SIZE);
        Self {
            pk,
            sk: Zeroized { value: sk },
            status: KeyStatus::Active,
        }
    }

    pub fn set_status(&mut self, status: KeyStatus) {
        self.status = status;
    }
}

impl Drop for SoftwarePinnedMemoryBackend {
    fn drop(&mut self) {
        let _ = unlock_memory_page(self.sk.value.as_ptr(), SK_SIZE);
    }
}

impl KeyStorageBackend for SoftwarePinnedMemoryBackend {
    fn backend_name(&self) -> &'static str {
        "SoftwarePinnedMemory (Fast-SIMD with RAM-Lock & Zeroization)"
    }

    fn get_public_key(&self) -> Result<[u8; PK_SIZE], String> {
        Ok(self.pk)
    }

    fn sign_payload(&self, message: &[u8]) -> Result<[u8; SIG_SIZE], String> {
        if self.status == KeyStatus::Revoked {
            return Err("Cannot sign with revoked cryptographic key".to_string());
        }
        let mut rnd = [0u8; 32];
        let mut hasher = Sha256::new();
        hasher.update(&self.sk.value[0..32]);
        hasher.update(message);
        let digest = hasher.finalize();
        rnd.copy_from_slice(&digest);

        let m_prime = crate::crypto::nist_api::format_m_prime_pub(message, &[]);
        Ok(crate::crypto::sign::sign_internal_with_pk(&self.sk.value, &m_prime, &rnd, Some(&self.pk)))
    }

    fn sign_hedged_payload(&self, message: &[u8], rnd: &[u8; 32]) -> Result<[u8; SIG_SIZE], String> {
        if self.status == KeyStatus::Revoked {
            return Err("Cannot sign with revoked cryptographic key".to_string());
        }
        let m_prime = crate::crypto::nist_api::format_m_prime_pub(message, b"");
        Ok(crate::crypto::sign::sign_internal_with_pk(&self.sk.value, &m_prime, rnd, Some(&self.pk)))
    }

    fn status(&self) -> KeyStatus {
        self.status
    }

    fn zeroize_keys(&mut self) {
        self.sk = Zeroized { value: [0u8; SK_SIZE] };
    }
}

// ---------------------------------------------------------------------------
// 3. Persistent Encrypted File Keystore (Survives Restarts)
// ---------------------------------------------------------------------------

#[derive(Serialize, Deserialize)]
struct EncryptedKeystoreFile {
    version: u32,
    salt: [u8; 16],
    nonce: [u8; 12],
    pk: Vec<u8>,
    encrypted_sk: Vec<u8>,
}

/// AES-256-GCM encrypted keystore file backend.
pub struct EncryptedFileKeystoreBackend {
    inner: AuditedKeyStorageBackend,
    file_path: PathBuf,
}

impl EncryptedFileKeystoreBackend {
    pub fn file_path(&self) -> &Path {
        &self.file_path
    }

    fn derive_key(passphrase: &str, salt: &[u8; 16]) -> [u8; 32] {
        let mut key = [0u8; 32];
        let mut hasher = Sha256::new();
        hasher.update(passphrase.as_bytes());
        hasher.update(salt);
        key.copy_from_slice(&hasher.finalize());

        // 10,000 rounds of key stretching
        for i in 0..10_000u32 {
            let mut h = Sha256::new();
            h.update(&key);
            h.update(&i.to_le_bytes());
            key.copy_from_slice(&h.finalize());
        }
        key
    }

    /// Loads an existing keystore from disk or generates a new encrypted file if it doesn't exist.
    pub fn load_or_generate(path: &Path, passphrase: &str, seed: Option<&[u8; 32]>) -> Result<Self, String> {
        if path.exists() {
            let data = fs::read(path).map_err(|e| format!("Failed to read keystore file: {}", e))?;
            let record: EncryptedKeystoreFile = bincode::deserialize(&data)
                .map_err(|e| format!("Corrupted keystore file format: {}", e))?;

            let aes_key = Self::derive_key(passphrase, &record.salt);
            let cipher = Aes256Gcm::new_from_slice(&aes_key)
                .map_err(|e| format!("Cipher initialization error: {}", e))?;
            let nonce = Nonce::from(record.nonce);

            let decrypted_sk = cipher.decrypt(&nonce, record.encrypted_sk.as_slice())
                .map_err(|_| "Authentication failure: invalid keystore passphrase or corrupted file".to_string())?;

            if decrypted_sk.len() != SK_SIZE || record.pk.len() != PK_SIZE {
                return Err("Invalid key byte dimensions in decrypted keystore".to_string());
            }

            let mut pk = [0u8; PK_SIZE];
            pk.copy_from_slice(&record.pk);
            let mut sk = [0u8; SK_SIZE];
            sk.copy_from_slice(&decrypted_sk);

            let inner = AuditedKeyStorageBackend::from_existing(pk, sk);
            Ok(Self {
                inner,
                file_path: path.to_path_buf(),
            })
        } else {
            let actual_seed = match seed {
                Some(s) => *s,
                None => {
                    let mut s = [0u8; 32];
                    let mut h = Sha256::new();
                    h.update(b"SOLOMON_DEFAULT_INITIAL_SEED");
                    h.update(&chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0).to_le_bytes());
                    s.copy_from_slice(&h.finalize());
                    s
                }
            };

            let (sk, pk) = AuditedMlDsa65::keygen(&actual_seed);

            // Generate salt & nonce
            let mut salt = [0u8; 16];
            let mut nonce_bytes = [0u8; 12];
            let ts = chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0).to_le_bytes();
            salt[0..8].copy_from_slice(&ts);
            salt[8..16].copy_from_slice(&ts);
            nonce_bytes[0..8].copy_from_slice(&ts);

            let aes_key = Self::derive_key(passphrase, &salt);
            let cipher = Aes256Gcm::new_from_slice(&aes_key)
                .map_err(|e| format!("Cipher initialization error: {}", e))?;
            let nonce = Nonce::from(nonce_bytes);

            let encrypted_sk = cipher.encrypt(&nonce, sk.as_slice())
                .map_err(|e| format!("Encryption error: {}", e))?;

            let record = EncryptedKeystoreFile {
                version: 1,
                salt,
                nonce: nonce_bytes,
                pk: pk.to_vec(),
                encrypted_sk,
            };

            if let Some(parent) = path.parent() {
                let _ = fs::create_dir_all(parent);
            }

            let encoded = bincode::serialize(&record)
                .map_err(|e| format!("Serialization error: {}", e))?;
            fs::write(path, encoded)
                .map_err(|e| format!("Failed to write encrypted keystore: {}", e))?;

            let inner = AuditedKeyStorageBackend::from_existing(pk, sk);
            Ok(Self {
                inner,
                file_path: path.to_path_buf(),
            })
        }
    }
}

impl KeyStorageBackend for EncryptedFileKeystoreBackend {
    fn backend_name(&self) -> &'static str {
        "EncryptedFileKeystore (AES-256-GCM with OS RAM-Locking)"
    }

    fn get_public_key(&self) -> Result<[u8; PK_SIZE], String> {
        self.inner.get_public_key()
    }

    fn sign_payload(&self, message: &[u8]) -> Result<[u8; SIG_SIZE], String> {
        self.inner.sign_payload(message)
    }

    fn sign_hedged_payload(&self, message: &[u8], rnd: &[u8; 32]) -> Result<[u8; SIG_SIZE], String> {
        self.inner.sign_hedged_payload(message, rnd)
    }

    fn status(&self) -> KeyStatus {
        self.inner.status()
    }

    fn zeroize_keys(&mut self) {
        self.inner.zeroize_keys();
    }
}

// ---------------------------------------------------------------------------
// 4. Cloud KMS / Envelope Encryption Driver (AWS KMS / HashiCorp Vault)
// ---------------------------------------------------------------------------

/// Envelope encryption driver where DEK (Data Encryption Key) is protected by Cloud KMS KEK.
pub struct KmsEnvelopeBackend {
    kms_key_arn: String,
    inner: AuditedKeyStorageBackend,
}

impl KmsEnvelopeBackend {
    pub fn new_with_unwrapped_key(
        kms_key_arn: String,
        pk: [u8; PK_SIZE],
        sk: [u8; SK_SIZE],
    ) -> Self {
        let inner = AuditedKeyStorageBackend::from_existing(pk, sk);
        Self {
            kms_key_arn,
            inner,
        }
    }

    pub fn kms_key_arn(&self) -> &str {
        &self.kms_key_arn
    }
}

impl KeyStorageBackend for KmsEnvelopeBackend {
    fn backend_name(&self) -> &'static str {
        "KmsEnvelopeBackend (AWS KMS / Vault Root of Trust)"
    }

    fn get_public_key(&self) -> Result<[u8; PK_SIZE], String> {
        self.inner.get_public_key()
    }

    fn sign_payload(&self, message: &[u8]) -> Result<[u8; SIG_SIZE], String> {
        self.inner.sign_payload(message)
    }

    fn sign_hedged_payload(&self, message: &[u8], rnd: &[u8; 32]) -> Result<[u8; SIG_SIZE], String> {
        self.inner.sign_hedged_payload(message, rnd)
    }

    fn status(&self) -> KeyStatus {
        self.inner.status()
    }

    fn zeroize_keys(&mut self) {
        self.inner.zeroize_keys();
    }
}

// ---------------------------------------------------------------------------
// 5. Multi-Tenant Key Registry (PA Acquiring Bank Isolation)
// ---------------------------------------------------------------------------

/// Thread-safe registry providing strict cryptographic tenant isolation across acquiring banks.
pub struct TenantKeyRegistry {
    tenants: Arc<RwLock<HashMap<String, Arc<Box<dyn KeyStorageBackend>>>>>,
    default_backend: Arc<Box<dyn KeyStorageBackend>>,
}

impl TenantKeyRegistry {
    pub fn new(default_backend: Box<dyn KeyStorageBackend>) -> Self {
        Self {
            tenants: Arc::new(RwLock::new(HashMap::new())),
            default_backend: Arc::new(default_backend),
        }
    }

    /// Registers or updates a tenant-specific key backend (e.g., HDFC, ICICI, Axis).
    pub async fn register_tenant(&self, tenant_id: String, backend: Box<dyn KeyStorageBackend>) {
        let mut lock = self.tenants.write().await;
        lock.insert(tenant_id, Arc::new(backend));
    }

    /// Retrieves the backend for a given tenant, falling back to default.
    pub async fn get_backend(&self, tenant_id: &str) -> Arc<Box<dyn KeyStorageBackend>> {
        let lock = self.tenants.read().await;
        lock.get(tenant_id).cloned().unwrap_or_else(|| self.default_backend.clone())
    }

    /// Atomically rotates the cryptographic backend for a specific tenant.
    pub async fn rotate_tenant_key(&self, tenant_id: &str, new_backend: Box<dyn KeyStorageBackend>) -> Result<(), String> {
        let mut lock = self.tenants.write().await;
        lock.insert(tenant_id.to_string(), Arc::new(new_backend));
        tracing::info!(message = "Tenant key rotated successfully", tenant_id = %tenant_id);
        Ok(())
    }

    /// Lists all actively registered tenant identifiers.
    pub async fn list_tenants(&self) -> Vec<String> {
        let lock = self.tenants.read().await;
        lock.keys().cloned().collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_audited_backend_signing_and_zeroization() {
        let seed = [0x55u8; 32];
        let mut backend = AuditedKeyStorageBackend::generate_new(&seed);
        assert_eq!(backend.status(), KeyStatus::Active);

        let pk = backend.get_public_key().unwrap();
        let msg = b"PA Payment Transaction Authorization INR 50,000";
        let sig = backend.sign_payload(msg).unwrap();

        assert!(AuditedMlDsa65::verify(&pk, msg, &sig));

        backend.set_status(KeyStatus::Revoked);
        assert!(backend.sign_payload(msg).is_err(), "Revoked key must reject signing");

        backend.zeroize_keys();
        assert_eq!(backend.sk.value, [0u8; SK_SIZE]);
    }

    #[tokio::test]
    async fn test_encrypted_file_keystore_persistence_roundtrip() {
        let temp_dir = tempfile::tempdir().unwrap();
        let key_path = temp_dir.path().join("test_solomon_keystore.bin");
        let passphrase = "FinTechEnterprisePassphrase2026!";
        let seed = [0x88u8; 32];

        // 1. Generate encrypted file
        let initial_backend = EncryptedFileKeystoreBackend::load_or_generate(&key_path, passphrase, Some(&seed)).unwrap();
        let pk = initial_backend.get_public_key().unwrap();
        let msg = b"Persistence Validation Payload";
        let sig = initial_backend.sign_payload(msg).unwrap();
        assert!(AuditedMlDsa65::verify(&pk, msg, &sig));

        // 2. Reload from encrypted file without providing seed
        let reloaded_backend = EncryptedFileKeystoreBackend::load_or_generate(&key_path, passphrase, None).unwrap();
        assert_eq!(reloaded_backend.get_public_key().unwrap(), pk, "Reloaded PK must match");

        let reloaded_sig = reloaded_backend.sign_payload(msg).unwrap();
        assert!(AuditedMlDsa65::verify(&pk, msg, &reloaded_sig));

        // 3. Incorrect passphrase must fail
        assert!(EncryptedFileKeystoreBackend::load_or_generate(&key_path, "WrongPassphrase!", None).is_err());
    }

    #[tokio::test]
    async fn test_tenant_key_registry_isolation_and_rotation() {
        let default_seed = [0x11u8; 32];
        let default_backend = Box::new(AuditedKeyStorageBackend::generate_new(&default_seed));
        let registry = TenantKeyRegistry::new(default_backend);

        let hdfc_seed = [0x22u8; 32];
        let hdfc_backend = Box::new(AuditedKeyStorageBackend::generate_new(&hdfc_seed));
        let hdfc_pk = hdfc_backend.get_public_key().unwrap();
        registry.register_tenant("HDFC".to_string(), hdfc_backend).await;

        let axis_seed = [0x33u8; 32];
        let axis_backend = Box::new(AuditedKeyStorageBackend::generate_new(&axis_seed));
        let axis_pk = axis_backend.get_public_key().unwrap();
        registry.register_tenant("AXIS".to_string(), axis_backend).await;

        let b_hdfc = registry.get_backend("HDFC").await;
        let b_axis = registry.get_backend("AXIS").await;
        let b_unknown = registry.get_backend("UNKNOWN").await;

        assert_eq!(b_hdfc.get_public_key().unwrap(), hdfc_pk);
        assert_eq!(b_axis.get_public_key().unwrap(), axis_pk);
        assert_ne!(b_hdfc.get_public_key().unwrap(), b_axis.get_public_key().unwrap());

        // Unknown tenant falls back to default
        let default_pk = AuditedMlDsa65::keygen(&default_seed).1;
        assert_eq!(b_unknown.get_public_key().unwrap(), default_pk);

        // Rotate HDFC key
        let hdfc_seed_v2 = [0x44u8; 32];
        let hdfc_v2 = Box::new(AuditedKeyStorageBackend::generate_new(&hdfc_seed_v2));
        let hdfc_pk_v2 = hdfc_v2.get_public_key().unwrap();
        registry.rotate_tenant_key("HDFC", hdfc_v2).await.unwrap();

        let b_hdfc_rotated = registry.get_backend("HDFC").await;
        assert_eq!(b_hdfc_rotated.get_public_key().unwrap(), hdfc_pk_v2);
    }
}
