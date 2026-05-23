// control_plane/src/api.rs
use axum::{
    extract::State,
    http::StatusCode,
    Json,
};
use serde::{Deserialize, Serialize};
use sqlx::SqlitePool;
use std::sync::Arc;
use rand::Rng;
use base64::{prelude::BASE64_STANDARD, Engine};
use sha3::digest::{Update, ExtendableOutput, XofReader};
use sha3::Shake256;

use crate::crypto::MasterSigner;

const MASTER_LICENSE_KEY: [u8; 32] = [
    0x53, 0x4F, 0x4C, 0x4F, 0x4D, 0x4F, 0x4E, 0x5F,
    0x4B, 0x45, 0x59, 0x5F, 0x32, 0x30, 0x32, 0x36,
    0x5F, 0x53, 0x45, 0x43, 0x55, 0x52, 0x45, 0x5F,
    0x4C, 0x49, 0x43, 0x45, 0x4E, 0x53, 0x45, 0x5F,
]; // "SOLOMON_KEY_2026_SECURE_LICENSE_"

/// Shared application state
pub struct AppState {
    pub db_pool: SqlitePool,
    pub signer: MasterSigner,
}

// ==========================================
// 1. Legacy / Phase 4 base64 endpoint schemas
// ==========================================

#[derive(Deserialize)]
pub struct HandshakeRequest {
    pub license_id: String,
    pub hardware_fingerprint: String,
    pub timestamp: i64,
}

#[derive(Serialize)]
pub struct HandshakeResponse {
    pub daily_salt: String, // base64 encoded
    pub signature: String,  // base64 encoded
}

// ==========================================
// 2. Proxy heartbeat hex-encoded schemas
// ==========================================

#[derive(Deserialize)]
pub struct LicensingRequest {
    pub license_id: String,
    pub hardware_fingerprint: String,
}

#[derive(Serialize)]
pub struct LicenseResponse {
    pub token: String,     // Hex-encoded 80-byte token
    pub signature: String, // Hex-encoded 64-byte Ed25519 signature
}

// ==========================================
// 3. Database lookup helper
// ==========================================

#[derive(sqlx::FromRow)]
struct DBClient {
    hardware_fingerprint: Option<String>,
    is_active: i64,
}

/// Helper function to perform Trust-On-First-Use and lookup operations
async fn authenticate_client(
    pool: &SqlitePool,
    license_id: &str,
    fingerprint: &str,
) -> Result<(), StatusCode> {
    // 1. Fetch license details from database
    let row = sqlx::query_as::<_, DBClient>(
        "SELECT hardware_fingerprint, is_active FROM clients WHERE license_id = ?1;"
    )
    .bind(license_id)
    .fetch_optional(pool)
    .await
    .map_err(|e| {
        eprintln!("[Database Error] Fetch failed: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    let client = match row {
        Some(c) => c,
        None => {
            println!("[Auth] License ID '{}' not found. Returning 401.", license_id);
            return Err(StatusCode::UNAUTHORIZED);
        }
    };

    // 2. Check SaaS active state
    if client.is_active == 0 {
        println!("[Auth] License ID '{}' is suspended. Returning 401.", license_id);
        return Err(StatusCode::UNAUTHORIZED);
    }

    // 3. Trust-On-First-Use (TOFU) hardware binding
    match client.hardware_fingerprint {
        None => {
            println!(
                "[Auth] TOFU Lock: Registering hardware fingerprint '{}' to license '{}'.",
                fingerprint, license_id
            );
            sqlx::query(
                "UPDATE clients SET hardware_fingerprint = ?1 WHERE license_id = ?2;"
            )
            .bind(fingerprint)
            .bind(license_id)
            .execute(pool)
            .await
            .map_err(|e| {
                eprintln!("[Database Error] Update failed: {}", e);
                StatusCode::INTERNAL_SERVER_ERROR
            })?;
        }
        Some(stored_fingerprint) => {
            if stored_fingerprint != fingerprint {
                println!(
                    "[Auth] SECURITY ERROR: Fingerprint mismatch! Stored: '{}', Received: '{}'. Returning 403.",
                    stored_fingerprint, fingerprint
                );
                return Err(StatusCode::FORBIDDEN);
            }
        }
    }

    Ok(())
}

// ==========================================
// 4. Route Handlers
// ==========================================

/// Legacy Endpoint POST /v1/epoch
/// Accepts base64 request payloads and returns base64 responses
pub async fn verify_handshake(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<HandshakeRequest>,
) -> Result<Json<HandshakeResponse>, StatusCode> {
    println!("[API] Received /v1/epoch request for license: {}", payload.license_id);

    // Authenticate and lock fingerprint
    authenticate_client(&state.db_pool, &payload.license_id, &payload.hardware_fingerprint).await?;

    // Generate random 32-byte daily salt
    let mut daily_salt = [0u8; 32];
    rand::thread_rng().fill(&mut daily_salt);

    // Sign daily salt
    let sig_bytes = state.signer.sign(&daily_salt);

    let salt_b64 = BASE64_STANDARD.encode(daily_salt);
    let sig_b64 = BASE64_STANDARD.encode(sig_bytes);

    println!("[API] Successfully issued /v1/epoch token.");
    Ok(Json(HandshakeResponse {
        daily_salt: salt_b64,
        signature: sig_b64,
    }))
}

/// Proxy Heartbeat Endpoint POST /licensing
/// Directly compatible with the live reverse proxy binary
pub async fn verify_licensing(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<LicensingRequest>,
) -> Result<Json<LicenseResponse>, StatusCode> {
    println!("[API] Received /licensing request for proxy license: {}", payload.license_id);

    // Authenticate and lock fingerprint
    authenticate_client(&state.db_pool, &payload.license_id, &payload.hardware_fingerprint).await?;

    // 1. Generate 32-byte daily salt matching the local launcher bootstrap salt
    let daily_salt = *b"LOCAL_DEV_SALT_32_BYTES_LONG_000";

    // 2. Generate 32-byte random IV
    let mut iv = [0u8; 32];
    rand::thread_rng().fill(&mut iv);

    // 3. Keystream = SHAKE-256(Master Key || IV) (32 bytes)
    let mut keystream_hasher = Shake256::default();
    keystream_hasher.update(&MASTER_LICENSE_KEY);
    keystream_hasher.update(&iv);
    let mut keystream_reader = keystream_hasher.finalize_xof();
    let mut keystream = [0u8; 32];
    keystream_reader.read(&mut keystream);

    // 4. Ciphertext = Salt ^ Keystream (32 bytes)
    let mut ciphertext = [0u8; 32];
    for i in 0..32 {
        ciphertext[i] = daily_salt[i] ^ keystream[i];
    }

    // 5. MAC = SHAKE-256(Master Key || IV || Ciphertext)[0..16] (16 bytes)
    let mut mac_hasher = Shake256::default();
    mac_hasher.update(&MASTER_LICENSE_KEY);
    mac_hasher.update(&iv);
    mac_hasher.update(&ciphertext);
    let mut mac_reader = mac_hasher.finalize_xof();
    let mut mac = [0u8; 16];
    mac_reader.read(&mut mac);

    // 6. Assemble 80-byte Epoch Token
    let mut token_bytes = [0u8; 80];
    token_bytes[0..32].copy_from_slice(&iv);
    token_bytes[32..64].copy_from_slice(&ciphertext);
    token_bytes[64..80].copy_from_slice(&mac);

    // 7. Ed25519 sign the 80-byte token_bytes
    let sig_bytes = state.signer.sign(&token_bytes);

    // 8. Hex-encode responses for JSON transport
    let token_hex = hex::encode(token_bytes);
    let sig_hex = hex::encode(sig_bytes);

    println!("[API] Successfully issued Keccak SHAKE-256 Epoch Token.");
    Ok(Json(LicenseResponse {
        token: token_hex,
        signature: sig_hex,
    }))
}

// Simple hex helper module to avoid extra dependencies for hex encoding
mod hex {
    pub fn encode(bytes: impl AsRef<[u8]>) -> String {
        let mut s = String::with_capacity(bytes.as_ref().len() * 2);
        for &b in bytes.as_ref() {
            s.push_str(&format!("{:02x}", b));
        }
        s
    }
}
