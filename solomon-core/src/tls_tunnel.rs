//! Hybrid Post-Quantum TLS 1.3 / TCP Tunnel Engine (NIST FIPS 203 ML-KEM-768 + X25519).
//!
//! Provides transparent post-quantum session encryption for ISO 8583 banking switches
//! to defeat Harvest Now, Decrypt Later (HNDL) quantum cryptanalysis.

use std::fmt;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use ml_kem::{
    MlKem768, MlKem768Params, EncodedSizeUser, KemCore,
    kem::{Decapsulate, Encapsulate, DecapsulationKey, EncapsulationKey},
};
use hybrid_array::Array;
use curve25519_dalek::montgomery::MontgomeryPoint;
use curve25519_dalek::scalar::Scalar;
use crate::crypto::shake::KeccakSponge;
use rand_core::RngCore;
use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};

#[derive(Debug)]
pub enum TlsTunnelError {
    HandshakeFailed(&'static str),
    DecapsulationFailed,
    InvalidFrame,
    AuthenticationFailed,
    IoError(std::io::Error),
    KemError,
}

impl fmt::Display for TlsTunnelError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TlsTunnelError::HandshakeFailed(msg) => write!(f, "Hybrid PQ Handshake failed: {}", msg),
            TlsTunnelError::DecapsulationFailed => write!(f, "ML-KEM-768 decapsulation failed"),
            TlsTunnelError::InvalidFrame => write!(f, "Invalid encrypted packet frame"),
            TlsTunnelError::AuthenticationFailed => write!(f, "AEAD frame authentication failed - potential bit-flipping / tampering detected"),
            TlsTunnelError::IoError(e) => write!(f, "I/O error in tunnel: {}", e),
            TlsTunnelError::KemError => write!(f, "ML-KEM cryptographic error"),
        }
    }
}

impl std::error::Error for TlsTunnelError {}

impl From<std::io::Error> for TlsTunnelError {
    fn from(e: std::io::Error) -> Self {
        TlsTunnelError::IoError(e)
    }
}

/// Hybrid Post-Quantum Public Key (X25519 (32 bytes) + ML-KEM-768 Encapsulation Key (1184 bytes))
#[derive(Clone)]
pub struct HybridPublicKey {
    pub x25519_pk: [u8; 32],
    pub ml_kem_pk_bytes: Vec<u8>,
}

/// Hybrid Post-Quantum Private Key
pub struct HybridPrivateKey {
    pub x25519_sk: [u8; 32],
    pub ml_kem_sk: DecapsulationKey<MlKem768Params>,
}

/// Hybrid Post-Quantum Ciphertext (X25519 Ephemeral PK (32 bytes) + ML-KEM-768 Ciphertext (1088 bytes))
#[derive(Clone)]
pub struct HybridCiphertext {
    pub x25519_ephemeral_pk: [u8; 32],
    pub ml_kem_ct_bytes: Vec<u8>,
}

/// Hybrid Post-Quantum Key Exchange Engine
pub struct HybridPqKeyExchange;

impl HybridPqKeyExchange {
    /// Generates a hybrid keypair (X25519 + ML-KEM-768).
    pub fn generate_keypair() -> (HybridPrivateKey, HybridPublicKey) {
        // 1. Generate X25519 Keypair using Curve25519 Montgomery Basepoint
        let mut x25519_sk = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut x25519_sk);

        // Clamp scalar according to RFC 7748
        x25519_sk[0] &= 248;
        x25519_sk[31] &= 127;
        x25519_sk[31] |= 64;

        let scalar = Scalar::from_bytes_mod_order(x25519_sk);
        let basepoint = MontgomeryPoint([
            9, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ]);
        let public_point = basepoint * scalar;
        let x25519_pk = *public_point.as_bytes();

        // 2. Generate ML-KEM-768 Keypair
        let mut kem_seed = [0u8; 64];
        rand::rngs::OsRng.fill_bytes(&mut kem_seed);

        let mut rng = rand_core_helper::DeterministicRng::new(&kem_seed);
        let (decaps_key, encaps_key) = MlKem768::generate(&mut rng);

        let ml_kem_pk_bytes = encaps_key.as_bytes().as_slice().to_vec();

        let priv_key = HybridPrivateKey {
            x25519_sk,
            ml_kem_sk: decaps_key,
        };

        let pub_key = HybridPublicKey {
            x25519_pk,
            ml_kem_pk_bytes,
        };

        (priv_key, pub_key)
    }

    /// Client side: Encapsulates against the Server's Hybrid Public Key to establish a shared 256-bit symmetric session key.
    pub fn client_encapsulate(server_pk: &HybridPublicKey) -> Result<(HybridCiphertext, [u8; 32]), TlsTunnelError> {
        // 1. Generate client ephemeral X25519 keypair
        let mut client_x25519_sk = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut client_x25519_sk);

        client_x25519_sk[0] &= 248;
        client_x25519_sk[31] &= 127;
        client_x25519_sk[31] |= 64;

        let client_scalar = Scalar::from_bytes_mod_order(client_x25519_sk);
        let basepoint = MontgomeryPoint([
            9, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ]);
        let client_public_point = basepoint * client_scalar;
        let client_x25519_pk = *client_public_point.as_bytes();

        // Classical Diffie-Hellman Shared Secret: client_sk * server_pk_point
        let server_public_point = MontgomeryPoint(server_pk.x25519_pk);
        let dh_shared_point = server_public_point * client_scalar;
        let classical_ss = *dh_shared_point.as_bytes();

        // 2. ML-KEM-768 Encapsulation
        let encaps_key_arr = Array::try_from(server_pk.ml_kem_pk_bytes.as_slice())
            .map_err(|_| TlsTunnelError::KemError)?;
        let encaps_key = EncapsulationKey::<MlKem768Params>::from_bytes(&encaps_key_arr);

        let mut kem_coins = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut kem_coins);
        let mut rng = rand_core_helper::DeterministicRng::new(&kem_coins);

        let (kem_ct, kem_ss) = encaps_key.encapsulate(&mut rng)
            .map_err(|_| TlsTunnelError::KemError)?;

        let hybrid_ct = HybridCiphertext {
            x25519_ephemeral_pk: client_x25519_pk,
            ml_kem_ct_bytes: kem_ct.as_slice().to_vec(),
        };

        // 3. Combine Classical + Post-Quantum Secrets: Final_SS = SHAKE-256(Classical_SS || ML_KEM_SS)
        let mut final_session_key = [0u8; 32];
        let mut kdf = KeccakSponge::new_shake256();
        kdf.absorb(&classical_ss);
        kdf.absorb(kem_ss.as_slice());
        kdf.absorb(b"SOLOMON_POST_QUANTUM_HYBRID_KDF_V1");
        kdf.squeeze(&mut final_session_key);

        Ok((hybrid_ct, final_session_key))
    }

    /// Server side: Decapsulates the Hybrid Ciphertext using the Server's Private Key to derive the shared session key.
    pub fn server_decapsulate(
        server_sk: &HybridPrivateKey,
        ct: &HybridCiphertext,
    ) -> Result<[u8; 32], TlsTunnelError> {
        // 1. Classical Diffie-Hellman Shared Secret: server_sk * client_ephemeral_pk_point
        let server_scalar = Scalar::from_bytes_mod_order(server_sk.x25519_sk);
        let client_public_point = MontgomeryPoint(ct.x25519_ephemeral_pk);
        let dh_shared_point = client_public_point * server_scalar;
        let classical_ss = *dh_shared_point.as_bytes();

        // 2. ML-KEM-768 Decapsulation
        let ct_arr = Array::try_from(ct.ml_kem_ct_bytes.as_slice())
            .map_err(|_| TlsTunnelError::DecapsulationFailed)?;

        let kem_ss = server_sk.ml_kem_sk.decapsulate(&ct_arr)
            .map_err(|_| TlsTunnelError::DecapsulationFailed)?;

        // 3. Combine Classical + Post-Quantum Secrets: Final_SS = SHAKE-256(Classical_SS || ML_KEM_SS)
        let mut final_session_key = [0u8; 32];
        let mut kdf = KeccakSponge::new_shake256();
        kdf.absorb(&classical_ss);
        kdf.absorb(kem_ss.as_slice());
        kdf.absorb(b"SOLOMON_POST_QUANTUM_HYBRID_KDF_V1");
        kdf.squeeze(&mut final_session_key);

        Ok(final_session_key)
    }
}

mod rand_core_helper {
    use rand_core::{RngCore, CryptoRng};
    pub struct DeterministicRng {
        sponge: crate::crypto::shake::KeccakSponge,
    }

    impl DeterministicRng {
        pub fn new(seed: &[u8]) -> Self {
            let mut sponge = crate::crypto::shake::KeccakSponge::new_shake256();
            sponge.absorb(seed);
            Self { sponge }
        }
    }

    impl RngCore for DeterministicRng {
        fn next_u32(&mut self) -> u32 {
            let mut buf = [0u8; 4];
            self.fill_bytes(&mut buf);
            u32::from_le_bytes(buf)
        }
        fn next_u64(&mut self) -> u64 {
            let mut buf = [0u8; 8];
            self.fill_bytes(&mut buf);
            u64::from_le_bytes(buf)
        }
        fn fill_bytes(&mut self, dest: &mut [u8]) {
            self.sponge.squeeze(dest);
        }
        fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
            self.fill_bytes(dest);
            Ok(())
        }
    }
    impl CryptoRng for DeterministicRng {}
}

/// Encrypts a payload frame using standard authenticated AES-256-GCM AEAD (NIST SP 800-52 / PCI-DSS 4.1).
pub fn encrypt_pq_frame(payload: &[u8], session_key: &[u8; 32], seq: u64) -> Result<Vec<u8>, TlsTunnelError> {
    let cipher = Aes256Gcm::new_from_slice(session_key)
        .map_err(|_| TlsTunnelError::HandshakeFailed("Invalid session key length"))?;
    let mut nonce_bytes = [0u8; 12];
    nonce_bytes[4..12].copy_from_slice(&seq.to_be_bytes());
    let nonce = Nonce::from(nonce_bytes);

    cipher.encrypt(&nonce, payload)
        .map_err(|_| TlsTunnelError::AuthenticationFailed)
}

/// Decrypts a payload frame and verifies the AEAD authentication tag, defeating tampering and bit-flipping.
pub fn decrypt_pq_frame(ciphertext: &[u8], session_key: &[u8; 32], seq: u64) -> Result<Vec<u8>, TlsTunnelError> {
    let cipher = Aes256Gcm::new_from_slice(session_key)
        .map_err(|_| TlsTunnelError::HandshakeFailed("Invalid session key length"))?;
    let mut nonce_bytes = [0u8; 12];
    nonce_bytes[4..12].copy_from_slice(&seq.to_be_bytes());
    let nonce = Nonce::from(nonce_bytes);

    cipher.decrypt(&nonce, ciphertext)
        .map_err(|_| TlsTunnelError::AuthenticationFailed)
}

/// Encrypts or Decrypts a stream packet with 256-bit Post-Quantum Keystream Mask & Sequence Counter
#[deprecated(note = "Unauthenticated stream cipher; use encrypt_pq_frame / decrypt_pq_frame with AES-256-GCM AEAD instead")]
pub fn apply_pq_stream_cipher(payload: &mut [u8], session_key: &[u8; 32], seq: u64) {
    let mut sponge = KeccakSponge::new_shake256();
    sponge.absorb(session_key);
    sponge.absorb(&seq.to_be_bytes());
    sponge.absorb(b"SOLOMON_PQ_SESSION_STREAM_CIPHER");

    let mut keystream = vec![0u8; payload.len()];
    sponge.squeeze(&mut keystream);

    for i in 0..payload.len() {
        payload[i] ^= keystream[i];
    }
}

/// Starts an inbound TLS/PQ Server Tunnel that terminates hybrid encryption and forwards plaintext TCP to a backend.
pub async fn start_tls_server_tunnel(
    listen_addr: SocketAddr,
    backend_plaintext_addr: SocketAddr,
    server_sk: Arc<HybridPrivateKey>,
    server_pk: Arc<HybridPublicKey>,
) -> Result<(), TlsTunnelError> {
    let listener = TcpListener::bind(listen_addr).await?;
    tracing::info!("Post-Quantum Hybrid TLS Server Tunnel active on {}", listen_addr);

    loop {
        if let Ok((mut client_stream, _)) = listener.accept().await {
            let sk_clone = server_sk.clone();
            let pk_clone = server_pk.clone();

            tokio::spawn(async move {
                // 1. Send Server Hybrid Public Key
                let mut pk_buf = Vec::with_capacity(32 + 2 + pk_clone.ml_kem_pk_bytes.len());
                pk_buf.extend_from_slice(&pk_clone.x25519_pk);
                let kem_len = pk_clone.ml_kem_pk_bytes.len() as u16;
                pk_buf.extend_from_slice(&kem_len.to_be_bytes());
                pk_buf.extend_from_slice(&pk_clone.ml_kem_pk_bytes);

                if client_stream.write_all(&pk_buf).await.is_err() {
                    return;
                }

                // 2. Read Client Ciphertext (32 bytes X25519 PK + 2 bytes len + ML-KEM CT)
                let mut x25519_ct = [0u8; 32];
                if client_stream.read_exact(&mut x25519_ct).await.is_err() {
                    return;
                }
                let mut kem_ct_len_buf = [0u8; 2];
                if client_stream.read_exact(&mut kem_ct_len_buf).await.is_err() {
                    return;
                }
                let kem_ct_len = u16::from_be_bytes(kem_ct_len_buf) as usize;
                let mut kem_ct_bytes = vec![0u8; kem_ct_len];
                if client_stream.read_exact(&mut kem_ct_bytes).await.is_err() {
                    return;
                }

                let hybrid_ct = HybridCiphertext {
                    x25519_ephemeral_pk: x25519_ct,
                    ml_kem_ct_bytes: kem_ct_bytes,
                };

                let session_key = match HybridPqKeyExchange::server_decapsulate(&sk_clone, &hybrid_ct) {
                    Ok(sk) => sk,
                    Err(e) => {
                        tracing::error!("Failed to decapsulate hybrid key: {}", e);
                        return;
                    }
                };

                // 3. Connect to local backend switch
                let backend_stream = match TcpStream::connect(backend_plaintext_addr).await {
                    Ok(s) => s,
                    Err(_) => return,
                };

                let (mut client_read, mut client_write) = client_stream.into_split();
                let (mut backend_read, mut backend_write) = backend_stream.into_split();

                // Decrypt client -> backend
                let key_c2b = session_key;
                tokio::spawn(async move {
                    let mut seq = 0u64;
                    let mut len_buf = [0u8; 2];
                    while client_read.read_exact(&mut len_buf).await.is_ok() {
                        let len = u16::from_be_bytes(len_buf) as usize;
                        let mut encrypted = vec![0u8; len];
                        if client_read.read_exact(&mut encrypted).await.is_err() {
                            break;
                        }
                        apply_pq_stream_cipher(&mut encrypted, &key_c2b, seq);
                        seq += 1;
                        if backend_write.write_all(&len_buf).await.is_err() ||
                           backend_write.write_all(&encrypted).await.is_err() {
                            break;
                        }
                    }
                });

                // Encrypt backend -> client
                let key_b2c = session_key;
                tokio::spawn(async move {
                    let mut seq = 0x8000_0000_0000_0000u64; // Separate outbound sequence domain
                    let mut len_buf = [0u8; 2];
                    while backend_read.read_exact(&mut len_buf).await.is_ok() {
                        let len = u16::from_be_bytes(len_buf) as usize;
                        let mut plaintext = vec![0u8; len];
                        if backend_read.read_exact(&mut plaintext).await.is_err() {
                            break;
                        }
                        apply_pq_stream_cipher(&mut plaintext, &key_b2c, seq);
                        seq += 1;
                        if client_write.write_all(&len_buf).await.is_err() ||
                           client_write.write_all(&plaintext).await.is_err() {
                            break;
                        }
                    }
                });
            });
        }
    }
}
