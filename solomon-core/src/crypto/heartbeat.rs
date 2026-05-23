//! Heartbeat control plane and loopback licensing endpoint client.
//!
//! Implements boot-interception verification of the rolling Daily Salt.
//! Parses and decrypts the encrypted `Epoch Token` using Keccak SHAKE-256 duplex streams,
//! validating the token authenticity before releasing rolling parameters.

use core::sync::atomic::{AtomicBool, Ordering};
use crate::error::{MlDsaError, Result};
use crate::crypto::shake::KeccakSponge;

/// Thread-safe flag indicating whether the daily salt has been successfully initialized.
static HAS_SALT: AtomicBool = AtomicBool::new(false);

/// Buffer storing the validated daily salt.
static mut DAILY_SALT: [u8; 32] = [0; 32];

/// Master pre-shared key used to authenticate licensing and decrypt Epoch Tokens.
const MASTER_LICENSE_KEY: [u8; 32] = [
    0x53, 0x4F, 0x4C, 0x4F, 0x4D, 0x4F, 0x4E, 0x5F,
    0x4B, 0x45, 0x59, 0x5F, 0x32, 0x30, 0x32, 0x36,
    0x5F, 0x53, 0x45, 0x43, 0x55, 0x52, 0x45, 0x5F,
    0x4C, 0x49, 0x43, 0x45, 0x4E, 0x53, 0x45, 0x5F,
]; // "SOLOMON_KEY_2026_SECURE_LICENSE_"

/// Store the daily salt and set initialization flag.
pub fn set_daily_salt(salt: [u8; 32]) {
    unsafe {
        // Volatile write to prevent compiler caching
        for i in 0..32 {
            core::ptr::write_volatile(&mut DAILY_SALT[i], salt[i]);
        }
    }
    HAS_SALT.store(true, Ordering::SeqCst);
}

/// Fetch the daily salt. Returns `Err` if not yet initialized, enforcing fail-closed design.
pub fn get_daily_salt() -> Result<[u8; 32]> {
    if !HAS_SALT.load(Ordering::SeqCst) {
        return Err(MlDsaError::InternalError);
    }
    unsafe {
        let mut salt = [0u8; 32];
        for i in 0..32 {
            salt[i] = core::ptr::read_volatile(&DAILY_SALT[i]);
        }
        Ok(salt)
    }
}

/// Helper to reset daily salt (mainly for testing)
pub fn reset_daily_salt() {
    unsafe {
        for i in 0..32 {
            core::ptr::write_volatile(&mut DAILY_SALT[i], 0);
        }
    }
    HAS_SALT.store(false, Ordering::SeqCst);
}

/// Decrypts and authenticates a raw 80-byte encrypted Epoch Token.
///
/// Epoch Token layout (80 bytes total):
/// - IV / Salt (32 bytes)
/// - Encrypted Payload / Ciphertext (32 bytes)
/// - MAC (16 bytes)
pub fn verify_and_apply_epoch_token(token: &[u8]) -> Result<()> {
    if token.len() != 80 {
        return Err(MlDsaError::InvalidParameter);
    }

    let mut iv = [0u8; 32];
    let mut ciphertext = [0u8; 32];
    let mut rec_mac = [0u8; 16];

    iv.copy_from_slice(&token[0..32]);
    ciphertext.copy_from_slice(&token[32..64]);
    rec_mac.copy_from_slice(&token[64..80]);

    // 1. Authenticate Token: Compute MAC = Keccak(Master Key || IV || Ciphertext)[0..16]
    let mut mac_sponge = KeccakSponge::new_shake256();
    mac_sponge.absorb(&MASTER_LICENSE_KEY);
    mac_sponge.absorb(&iv);
    mac_sponge.absorb(&ciphertext);
    let mut computed_mac = [0u8; 16];
    mac_sponge.squeeze(&mut computed_mac);

    // Constant-time verification of MAC to prevent timing side-channels
    let mut diff = 0u8;
    for i in 0..16 {
        diff |= rec_mac[i] ^ computed_mac[i];
    }

    if diff != 0 {
        return Err(MlDsaError::InternalError);
    }

    // 2. Decrypt Token: keystream = Keccak(Master Key || IV)
    let mut decrypt_sponge = KeccakSponge::new_shake256();
    decrypt_sponge.absorb(&MASTER_LICENSE_KEY);
    decrypt_sponge.absorb(&iv);
    let mut keystream = [0u8; 32];
    decrypt_sponge.squeeze(&mut keystream);

    let mut daily_salt = [0u8; 32];
    for i in 0..32 {
        daily_salt[i] = ciphertext[i] ^ keystream[i];
    }

    // Apply the decrypted salt
    set_daily_salt(daily_salt);

    // Securely scrub transient secret keystream and keys from stack
    unsafe {
        for i in 0..32 {
            core::ptr::write_volatile(&mut keystream[i], 0);
        }
    }

    Ok(())
}

/// Handshake implementation using local TCP loopback.
///
/// Connects to licensing control plane at `127.0.0.1:1337` to fetch the encrypted token.
/// Conditionally compiled when `std` feature is present.
#[cfg(feature = "std")]
pub fn run_heartbeat_handshake() -> Result<()> {
    use std::io::{Read, Write};
    use std::net::TcpStream;
    use std::time::Duration;
    use crate::enc_str;

    // Use transient compile-time encrypted strings to shield IP address and requests
    let ip_encrypted = enc_str!("127.0.0.1:1337", 0x47);
    let ip_transient = ip_encrypted.decrypt();
    let ip_str = core::str::from_utf8(&ip_transient).map_err(|_| MlDsaError::InternalError)?;

    let mut stream = TcpStream::connect(ip_str).map_err(|_| MlDsaError::HashFailure)?;
    stream.set_read_timeout(Some(Duration::from_secs(5))).map_err(|_| MlDsaError::InternalError)?;

    // Send simple heartbeat challenge trigger
    let trigger_encrypted = enc_str!("GET_EPOCH_TOKEN", 0x33);
    let trigger_transient = trigger_encrypted.decrypt();
    stream.write_all(&trigger_transient).map_err(|_| MlDsaError::InternalError)?;

    let mut token_buf = [0u8; 80];
    stream.read_exact(&mut token_buf).map_err(|_| MlDsaError::InternalError)?;

    // Verify and apply the received token
    verify_and_apply_epoch_token(&token_buf)?;

    // Clean up transient stack memory
    unsafe {
        let mut ip_t = ip_transient;
        let mut tr_t = trigger_transient;
        for i in 0..ip_t.len() {
            core::ptr::write_volatile(&mut ip_t[i], 0);
        }
        for i in 0..tr_t.len() {
            core::ptr::write_volatile(&mut tr_t[i], 0);
        }
    }

    Ok(())
}

/// Fallback / dummy handshake implementation for pure no_std targets or testing environments.
#[cfg(not(feature = "std"))]
pub fn run_heartbeat_handshake() -> Result<()> {
    // Under pure no_std with no standard networking, we require out-of-band initialization
    // using `verify_and_apply_epoch_token` directly.
    Ok(())
}
