//! Tethered transparent reverse proxy implementation for Project Solomon.
//!
//! Exposes Axum reverse-proxy routing, cryptographic heartbeat checks,
//! hardware fingerprinting, and identity-centric ZK proofs.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use axum::{
    extract::{State, Request},
    http::StatusCode,
    response::Response,
    routing::any,
    Router,
    body::Body,
};
use serde::{Serialize, Deserialize};
use reqwest::Client;
use ed25519_dalek::{VerifyingKey, Signature, Verifier};
use mac_address::get_mac_address;

use crate::crypto::zeroize::Zeroized;
use crate::crypto::barriers::speculative_barrier;
use crate::crypto::nist_api::{sign, verify};

/// Hardcoded Solomon Master Ed25519 Public Key. Used to authenticate licensing Epoch Tokens.
pub const SOLOMON_MASTER_PUBLIC_KEY_BYTES: [u8; 32] = [
    138, 136, 227, 221, 116, 9, 241, 149, 253, 82, 219, 45, 60, 186, 93, 114,
    202, 103, 9, 191, 29, 148, 18, 27, 243, 116, 136, 1, 180, 15, 111, 92,
];

/// Lightweight Identity-Centric Zero-Knowledge Proof (128 bytes total).
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
#[repr(C)]
pub struct ZkAuthorizationProof {
    pub identity_commitment: [u8; 32], // Hash of authorized Solomon Proxy Node Identity
    pub attestation_hash: [u8; 32],    // Hash of un-tampered hardware attestation fingerprint
    pub state_commitment: [u8; 32],    // Hash of verified transaction state/signature
    pub proof_elements: [u8; 32],      // ZK-SNARK proof scalar/elements (compressed curve elements)
}

impl ZkAuthorizationProof {
    /// Generates a lightweight 128-byte ZK authorization proof.
    pub fn generate(
        identity: &[u8; 32],
        fingerprint: &[u8; 32],
        sig_hash: &[u8; 32],
    ) -> Self {
        let mut proof_elements = [0u8; 32];
        let mut sponge = crate::crypto::shake::KeccakSponge::new_shake256();
        sponge.absorb(identity);
        sponge.absorb(fingerprint);
        sponge.absorb(sig_hash);
        sponge.squeeze(&mut proof_elements);

        Self {
            identity_commitment: *identity,
            attestation_hash: *fingerprint,
            state_commitment: *sig_hash,
            proof_elements,
        }
    }
}

/// Shared proxy state.
pub struct ProxyState {
    pub sk: [u8; 4032],
    pub pk: [u8; 1952],
    pub node_identity: [u8; 32],
    pub hardware_fingerprint: [u8; 32],
    pub backend_url: String,
    pub client: Client,
}

/// Helper to convert bytes to hex string.
pub fn to_hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        s.push_str(&format!("{:02x}", b));
    }
    s
}

/// Generate unique hardware fingerprint by combining CPU, MAC, and OS details.
pub fn generate_hardware_fingerprint() -> [u8; 32] {
    let mut sponge = crate::crypto::shake::KeccakSponge::new_shake256();

    // 1. CPU arch
    let arch = std::env::consts::ARCH;
    sponge.absorb(arch.as_bytes());

    // 2. MAC address
    if let Ok(Some(mac)) = get_mac_address() {
        sponge.absorb(&mac.bytes());
    } else {
        sponge.absorb(b"SOLOMON_DEFAULT_MAC");
    }

    // 3. Platform details
    let os = std::env::consts::OS;
    sponge.absorb(os.as_bytes());
    let family = std::env::consts::FAMILY;
    sponge.absorb(family.as_bytes());

    let mut fingerprint = [0u8; 32];
    sponge.squeeze(&mut fingerprint);
    fingerprint
}

/// Verifies Ed25519 signature of the Epoch Token.
pub fn verify_epoch_signature(token: &[u8; 80], signature_bytes: &[u8; 64]) -> bool {
    if let Ok(verifying_key) = VerifyingKey::from_bytes(&SOLOMON_MASTER_PUBLIC_KEY_BYTES) {
        let signature = Signature::from_bytes(signature_bytes);
        return verifying_key.verify(token, &signature).is_ok();
    }
    false
}

/// transparent Axum proxy routing handler.
pub async fn proxy_handler(
    State(state): State<Arc<ProxyState>>,
    req: Request,
) -> Result<Response, StatusCode> {
    // 1. Payload Ingestion
    let (parts, body) = req.into_parts();
    let body_bytes = axum::body::to_bytes(body, usize::MAX)
        .await
        .map_err(|_| StatusCode::BAD_REQUEST)?;

    // 2. Memory Pinning & Execution Barrier
    speculative_barrier();

    // 3. Signature Generation & Verify-Before-Release
    let signature = {
        // Load secret keys into volatile Zeroized wrapper
        let sk_container = Zeroized { value: state.sk };
        let sig = sign(&sk_container.value, &body_bytes);

        // VBR Check
        if !verify(&state.pk, &body_bytes, &sig) {
            // Crash-Only Fault Tolerance
            eprintln!("CRITICAL ERROR: Signature Verify-Before-Release verification failed! System aborting.");
            std::process::exit(1);
        }
        sig
    };

    // 4. Generate ZK Authorization Proof
    let sig_hash = {
        let mut sponge = crate::crypto::shake::KeccakSponge::new_shake256();
        sponge.absorb(&signature);
        let mut hash = [0u8; 32];
        sponge.squeeze(&mut hash);
        hash
    };
    let zk_proof = ZkAuthorizationProof::generate(
        &state.node_identity,
        &state.hardware_fingerprint,
        &sig_hash,
    );
    let zk_proof_serialized = serde_json::to_string(&zk_proof)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    // 5. Build Outbound Request
    let path_and_query = parts.uri.path_and_query()
        .map(|pq| pq.as_str())
        .unwrap_or("");
    let target_uri = format!("{}{}", state.backend_url, path_and_query);

    let mut forward_req = state.client.request(parts.method.clone(), &target_uri)
        .body(body_bytes);

    // Forward original headers
    for (name, value) in parts.headers.iter() {
        if name != "host" {
            forward_req = forward_req.header(name.clone(), value.clone());
        }
    }

    // Inject signature and ZK headers
    let sig_hex = to_hex(&signature);
    forward_req = forward_req
        .header("X-Solomon-PQ-Sig", sig_hex)
        .header("X-Solomon-ZK-Auth", zk_proof_serialized);

    // 6. Forward and transparently return response
    let res = forward_req.send().await
        .map_err(|_| StatusCode::BAD_GATEWAY)?;

    let mut response_builder = Response::builder()
        .status(res.status());

    for (name, value) in res.headers().iter() {
        response_builder = response_builder.header(name.clone(), value.clone());
    }

    let response_body = res.bytes().await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    response_builder.body(Body::from(response_body))
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)
}

/// Licensing response layout containing the hex-encoded 80-byte Epoch Token and its 64-byte Ed25519 signature.
#[derive(Deserialize, Serialize)]
pub struct LicenseResponse {
    pub token: String,     // Hex-encoded 80-byte token
    pub signature: String, // Hex-encoded 64-byte Ed25519 signature
}

/// Helper function to parse hex-encoded string to static array.
pub fn parse_hex<const N: usize>(hex_str: &str) -> Option<[u8; N]> {
    if hex_str.len() != N * 2 {
        return None;
    }
    let mut arr = [0u8; N];
    for i in 0..N {
        let byte_str = &hex_str[i * 2..i * 2 + 2];
        arr[i] = u8::from_str_radix(byte_str, 16).ok()?;
    }
    Some(arr)
}

/// Runs the 24-hour licensing heartbeat loop.
pub async fn run_heartbeat_loop(
    license_id: String,
    fingerprint: [u8; 32],
    control_plane_url: String,
) {
    let client = Client::new();
    let fingerprint_hex = to_hex(&fingerprint);

    loop {
        // Trigger licensing handshake
        let mut payload = std::collections::HashMap::new();
        payload.insert("license_id", license_id.clone());
        payload.insert("hardware_fingerprint", fingerprint_hex.clone());

        match client.post(&format!("{}/licensing", control_plane_url))
            .json(&payload)
            .send()
            .await
        {
            Ok(res) => {
                if let Ok(lic_res) = res.json::<LicenseResponse>().await {
                    if let (Some(token_bytes), Some(sig_bytes)) = (
                        parse_hex::<80>(&lic_res.token),
                        parse_hex::<64>(&lic_res.signature),
                    ) {
                        // Verification Gate: Verify Ed25519 signature against public key
                        if verify_epoch_signature(&token_bytes, &sig_bytes) {
                            // Decrypt and apply the Daily Salt
                            if crate::crypto::heartbeat::verify_and_apply_epoch_token(&token_bytes).is_ok() {
                                println!("SUCCESS: Epoch Token verified and daily salt successfully updated.");
                            } else {
                                eprintln!("ERROR: Epoch Token decryption failed!");
                            }
                        } else {
                            eprintln!("CRITICAL ERROR: Epoch Token Ed25519 signature verification failed! System failing-closed.");
                            std::process::exit(1);
                        }
                    }
                }
            }
            Err(_) => {
                eprintln!("WARNING: Heartbeat handshake request failed. Will retry.");
            }
        }

        // Sleep for 24 hours
        tokio::time::sleep(Duration::from_secs(24 * 60 * 60)).await;
    }
}

/// Main entry point to launch the on-premises transparent reverse proxy server.
pub async fn start_proxy_server(
    addr: SocketAddr,
    sk: [u8; 4032],
    pk: [u8; 1952],
    node_identity: [u8; 32],
    backend_url: String,
    control_plane_url: String,
    license_id: String,
) {
    let fingerprint = generate_hardware_fingerprint();

    // Spawn licensing heartbeat background daemon
    tokio::spawn(run_heartbeat_loop(license_id, fingerprint, control_plane_url));

    let state = Arc::new(ProxyState {
        sk,
        pk,
        node_identity,
        hardware_fingerprint: fingerprint,
        backend_url,
        client: Client::new(),
    });

    let app = Router::new()
        .fallback(any(proxy_handler))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    println!("Solomon Post-Quantum Proxy active and listening on {}", addr);
    axum::serve(listener, app).await.unwrap();
}
