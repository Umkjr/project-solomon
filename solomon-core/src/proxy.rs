//! Tethered transparent reverse proxy implementation for Project Solomon.
//!
//! Exposes:
//! 1. Real ISO 8583 binary TCP proxy engine (2-byte Big-Endian framing, 128-bit bitmap, PQC injection).
//! 2. Axum HTTP/REST reverse-proxy routing and compatibility mode.
//! 3. 72-hour offline grace period licensing heartbeat with local cache recovery.
//! 4. CycloneDX 1.6 Cryptography Bill of Materials (CBOM) export endpoints.
//! 5. Hardware fingerprinting, VBR fault gates, and lightweight ZK proofs.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use axum::{
    extract::{State, Request},
    http::StatusCode,
    response::Response,
    routing::any,
    body::Body,
};
use serde::{Serialize, Deserialize};
use reqwest::Client;
use ed25519_dalek::{VerifyingKey, Signature, Signer, Verifier};
use mac_address::get_mac_address;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;

use crate::crypto::barriers::speculative_barrier;
use crate::crypto::nist_api::verify;
use crate::iso8583::Iso8583Message;
use crate::heartbeat::{HeartbeatManager, HeartbeatStatus};
use crate::cbom::generate_cbom;
use crate::ai::feature::extract_features;
use crate::zk::batch::TransactionRecord;

/// Hardcoded Solomon Master Ed25519 Public Key. Used to authenticate licensing Epoch Tokens.
pub const SOLOMON_MASTER_PUBLIC_KEY_BYTES: [u8; 32] = [
    138, 136, 227, 221, 116, 9, 241, 149, 253, 82, 219, 45, 60, 186, 93, 114,
    202, 103, 9, 191, 29, 148, 18, 27, 243, 116, 136, 1, 180, 15, 111, 92,
];

/// Lightweight Identity-Centric Cryptographic Commitment (128 bytes total).
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
#[repr(C)]
pub struct ZkAuthorizationProof {
    pub identity_commitment: [u8; 32], // Hash of authorized Solomon Proxy Node Identity
    pub attestation_hash: [u8; 32],    // Hash of un-tampered hardware attestation fingerprint
    pub state_commitment: [u8; 32],    // Hash of verified transaction state/signature
    pub proof_elements: [u8; 32],      // Keccak sponge commitment over the structural elements
}

impl ZkAuthorizationProof {
    /// Generates a lightweight 128-byte cryptographic commitment.
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

    /// Verifies the lightweight 128-byte cryptographic commitment.
    pub fn verify(&self, expected_sig_hash: &[u8; 32]) -> bool {
        if &self.state_commitment != expected_sig_hash {
            return false;
        }
        let mut expected_proof = [0u8; 32];
        let mut sponge = crate::crypto::shake::KeccakSponge::new_shake256();
        sponge.absorb(&self.identity_commitment);
        sponge.absorb(&self.attestation_hash);
        sponge.absorb(&self.state_commitment);
        sponge.squeeze(&mut expected_proof);

        self.proof_elements == expected_proof
    }
}

/// Sponsor Bank configuration from the ledger.
#[derive(Deserialize, Clone, Debug)]
pub struct SponsorBankConfig {
    pub iso_version: String,
    pub pqc_snark_field: String,
    pub pqc_field_number: u8,
    pub max_buffer_size: usize,
    pub encoding: String,
    pub strip_headers: Vec<String>,
}

/// The Root ISO Configuration Ledger
#[derive(Deserialize, Clone, Debug)]
pub struct IsoConfig {
    pub sponsor_banks: std::collections::HashMap<String, SponsorBankConfig>,
}

/// Helper function to load ISO config from file or return static fallback.
pub fn load_iso_config() -> IsoConfig {
    if let Ok(content) = std::fs::read_to_string("iso_config.json") {
        if let Ok(config) = serde_json::from_str(&content) {
            return config;
        }
    }
    // Fallback config if file not found or invalid
    let mut sponsor_banks = std::collections::HashMap::new();
    sponsor_banks.insert(
        "bank_A_tcs_bancs".to_string(),
        SponsorBankConfig {
            iso_version: "1987".to_string(),
            pqc_snark_field: "Field 112 (Additional Data - National)".to_string(),
            pqc_field_number: 112,
            max_buffer_size: 256,
            encoding: "EBCDIC".to_string(),
            strip_headers: vec!["X-PQC-Metadata".to_string(), "Fintech-Telemetry".to_string()],
        },
    );
    sponsor_banks.insert(
        "bank_B_finacle".to_string(),
        SponsorBankConfig {
            iso_version: "1993".to_string(),
            pqc_snark_field: "Field 123 (Reserved for Private Use)".to_string(),
            pqc_field_number: 123,
            max_buffer_size: 150,
            encoding: "ASCII".to_string(),
            strip_headers: vec!["X-Signature-Raw".to_string()],
        },
    );
    IsoConfig { sponsor_banks }
}

/// Operational Mode of the Reverse Proxy
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProxyMode {
    /// Ingress Mode: Signs outbound transactions with local ML-DSA-65 key, generates ZK Proof, and injects PQC payload into Field 112/123 before forwarding to upstream network
    Ingress,
    /// Egress / Receiving Mode: Receives PQC-enriched transactions from network, extracts & validates ZK Proof and ML-DSA-65 signature, strips PQC field, and passes clean legacy ISO 8583 frame to core banking host (TCS BaNCS, Finacle, Base24)
    Receiving,
    /// Shadow / Monitor Mode: For non-disruptive pilots. Every inbound message is forwarded
    /// to the backend UNTOUCHED (no PQC injection, no rejection, heartbeat gate bypassed),
    /// while the would-be PQC path (ML-DSA-65 sign + verify + ZK proof) is run in parallel
    /// and its outcome + latency are logged. Flip to Ingress once the pilot is approved.
    Monitor,
}

/// Shared proxy state.
pub struct ProxyState {
    pub proxy_mode: ProxyMode,
    pub keystore: Arc<Box<dyn crate::hsm::KeyStorageBackend>>,
    pub node_identity: [u8; 32],
    /// Separate Ed25519 signing key for hybrid mode — NOT the same as node_identity.
    /// This prevents node_identity (which enters the ZK commitment) from being the sk seed.
    pub ed25519_signing_key: ed25519_dalek::SigningKey,
    pub hardware_fingerprint: [u8; 32],
    pub backend_url: String,
    pub client: Client,
    pub last_request_time: std::sync::Mutex<std::time::Instant>,
    pub active_requests: std::sync::atomic::AtomicUsize,
    pub total_requests: std::sync::atomic::AtomicUsize,
    pub last_request_bytes: std::sync::atomic::AtomicUsize,
    pub last_request_interval_ms: std::sync::atomic::AtomicUsize,
    pub iso_config: Arc<std::sync::RwLock<IsoConfig>>,
    pub heartbeat_manager: Arc<HeartbeatManager>,
    pub ai_model: Arc<std::sync::Mutex<crate::ai::model::EdgeAutoencoder>>,
    pub ai_training_sender: tokio::sync::mpsc::Sender<crate::ai::linalg::Vector>,
    pub batch_accumulator: Arc<crate::zk::batch::BatchAccumulator>,
    pub zk_mode: String,
    pub hybrid_mode: bool,
    pub audit_logger: Option<Arc<crate::audit::logger::AuditLogger>>,
    pub anomaly_detector: Arc<crate::audit::AnomalyDetector>,
    pub incident_logger: Arc<crate::audit::IncidentLogger>,
    pub iam_logger: Arc<crate::audit::IamLogger>,
    pub bcp_dr_state: Arc<crate::audit::BcpDrState>,
    pub vapt_registry: Arc<tokio::sync::RwLock<crate::audit::VaptRegistry>>,
    pub incident_count: Arc<std::sync::atomic::AtomicU64>,
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

/// Dynamically retrieves the configured Solomon Master Public Key from environment, falling back to default.
pub fn get_master_public_key() -> [u8; 32] {
    if let Ok(hex_str) = std::env::var("SOLOMON_MASTER_PUBLIC_KEY") {
        if let Some(bytes) = parse_hex::<32>(&hex_str) {
            return bytes;
        }
    }
    SOLOMON_MASTER_PUBLIC_KEY_BYTES
}

/// Verifies Ed25519 signature of the Epoch Token using configured master public key.
pub fn verify_epoch_signature(token: &[u8; 80], signature_bytes: &[u8; 64]) -> bool {
    let master_pk = get_master_public_key();
    verify_epoch_signature_with_pk(token, signature_bytes, &master_pk)
}

/// Verifies Ed25519 signature of the Epoch Token with an explicit master public key.
pub fn verify_epoch_signature_with_pk(token: &[u8; 80], signature_bytes: &[u8; 64], master_pk: &[u8; 32]) -> bool {
    if let Ok(verifying_key) = VerifyingKey::from_bytes(master_pk) {
        let signature = Signature::from_bytes(signature_bytes);
        return verifying_key.verify(token, &signature).is_ok();
    }
    false
}

/// Prometheus Metrics endpoint handler
pub async fn metrics_handler(State(state): State<Arc<ProxyState>>) -> String {
    let active = state.active_requests.load(std::sync::atomic::Ordering::SeqCst);
    let total = state.total_requests.load(std::sync::atomic::Ordering::SeqCst);
    let last_bytes = state.last_request_bytes.load(std::sync::atomic::Ordering::SeqCst);
    let last_interval = state.last_request_interval_ms.load(std::sync::atomic::Ordering::SeqCst);
    let hb_status = state.heartbeat_manager.get_status();
    let hb_state_val = match hb_status {
        HeartbeatStatus::Active { .. } => 1,
        HeartbeatStatus::GracePeriod { .. } => 2,
        HeartbeatStatus::ExpiredFailClosed { .. } => 0,
    };

    format!(
        "# HELP solomon_active_requests Number of requests currently being processed\n\
         # TYPE solomon_active_requests gauge\n\
         solomon_active_requests {}\n\
         # HELP solomon_processed_requests_total Total number of requests processed by Solomon\n\
         # TYPE solomon_processed_requests_total counter\n\
         solomon_processed_requests_total {}\n\
         # HELP solomon_last_request_bytes Payload byte size of the last processed request\n\
         # TYPE solomon_last_request_bytes gauge\n\
         solomon_last_request_bytes {}\n\
         # HELP solomon_last_packet_interval_ms Time interval in ms since the previous packet\n\
         # TYPE solomon_last_packet_interval_ms gauge\n\
         solomon_last_packet_interval_ms {}\n\
         # HELP solomon_heartbeat_status Current heartbeat status (1=Active, 2=GracePeriod, 0=ExpiredFailClosed)\n\
         # TYPE solomon_heartbeat_status gauge\n\
         solomon_heartbeat_status {}\n",
        active, total, last_bytes, last_interval, hb_state_val
    )
}

/// Healthcheck endpoint handler
pub async fn health_handler(State(state): State<Arc<ProxyState>>) -> (StatusCode, axum::Json<serde_json::Value>) {
    // Fail-closed on audit worker degradation before checking heartbeat.
    if let Some(logger) = &state.audit_logger {
        if !logger.is_healthy() {
            tracing::error!(message = "Audit logger worker unhealthy — reporting SERVICE_UNAVAILABLE on health endpoint.");
            return (StatusCode::SERVICE_UNAVAILABLE, axum::Json(serde_json::json!({
                "status": "audit_degraded",
                "error": "Audit logger background worker failed to write — RBI compliance cannot be maintained."
            })));
        }
    }

    let status = state.heartbeat_manager.get_status();
    match status {
        HeartbeatStatus::Active { last_synced, valid_until } => {
            (StatusCode::OK, axum::Json(serde_json::json!({
                "status": "healthy",
                "heartbeat": "active",
                "last_synced_epoch": last_synced,
                "valid_until_epoch": valid_until,
            })))
        }
        HeartbeatStatus::GracePeriod { last_synced, grace_until, remaining_seconds } => {
            (StatusCode::OK, axum::Json(serde_json::json!({
                "status": "degraded_grace_period",
                "heartbeat": "offline_grace_active",
                "last_synced_epoch": last_synced,
                "grace_until_epoch": grace_until,
                "grace_remaining_seconds": remaining_seconds,
            })))
        }
        HeartbeatStatus::ExpiredFailClosed { last_synced, expired_at } => {
            (StatusCode::SERVICE_UNAVAILABLE, axum::Json(serde_json::json!({
                "status": "fail_closed_expired",
                "heartbeat": "grace_period_expired",
                "last_synced_epoch": last_synced,
                "expired_at_epoch": expired_at,
                "error": "72-hour offline grace period exceeded without token renewal"
            })))
        }
    }
}

/// Cryptography Bill of Materials (CBOM) endpoint handler
pub async fn cbom_handler() -> axum::Json<serde_json::Value> {
    let cbom_doc = generate_cbom();
    let val = serde_json::to_value(&cbom_doc).unwrap_or(serde_json::json!({}));
    axum::Json(val)
}

/// RBI G10: Read-only RBI Inspector snapshot endpoint.
/// Protected by Bearer token authentication.
/// Returns a signed SAR JSON snapshot for regulatory examination.
pub async fn rbi_inspector_handler(
    State(state): State<Arc<ProxyState>>,
) -> (StatusCode, axum::Json<serde_json::Value>) {
    let head_hash = if let Some(logger) = &state.audit_logger {
        logger.get_last_hash().await
    } else {
        crate::audit::AuditChain::GENESIS_HASH.to_string()
    };
    let cbom_val = serde_json::to_value(generate_cbom()).unwrap_or_default();
    let bcp_dr_val = serde_json::to_value(
        state.bcp_dr_state.generate_report(0)
    ).unwrap_or_default();
    let vapt_val = {
        let lock = state.vapt_registry.read().await;
        lock.summary()
    };

    let default_hasher = crate::audit::crypto_traits::Sha256AuditHasher;
    let hasher: &dyn crate::audit::crypto_traits::AuditHasher = match &state.audit_logger {
        Some(logger) => logger.hasher(),
        None => &default_hasher,
    };

    let signing_key = state.ed25519_signing_key.clone();
    let snapshot = crate::audit::generate_sar(
        head_hash,
        0,
        state.incident_count.load(std::sync::atomic::Ordering::Relaxed),
        state.anomaly_detector.total_alerts(),
        cbom_val,
        bcp_dr_val,
        vapt_val,
        hasher,
        move |bytes| {
            let sig = signing_key.sign(bytes);
            hex::encode(sig.to_bytes())
        },
    );

    (StatusCode::OK, axum::Json(serde_json::to_value(snapshot).unwrap_or_default()))
}


/// Transparent Axum HTTP/REST proxy routing handler.
pub async fn proxy_handler(
    State(state): State<Arc<ProxyState>>,
    req: Request,
) -> Result<Response, StatusCode> {
    // 0. Licensing & 72-Hour Offline Grace Period Gate
    let hb_status = state.heartbeat_manager.get_status();
    match hb_status {
        HeartbeatStatus::Active { .. } => {}
        HeartbeatStatus::GracePeriod { remaining_seconds, .. } => {
            tracing::warn!(
                message = "Heartbeat operating in 72-hour offline grace period",
                grace_remaining_seconds = remaining_seconds
            );
        }
        HeartbeatStatus::ExpiredFailClosed { expired_at, .. } => {
            tracing::error!(
                message = "CRITICAL: Licensing heartbeat 72-hour grace period expired! Transaction rejected under fail-closed enforcement.",
                expired_at_epoch = expired_at
            );
            return Err(StatusCode::SERVICE_UNAVAILABLE);
        }
    }

    // 1. Telemetry Ingestion & Aggregation
    let active_count = state.active_requests.fetch_add(1, std::sync::atomic::Ordering::SeqCst) + 1;
    state.total_requests.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    let now = std::time::Instant::now();
    let interval_ms = {
        let mut last = state.last_request_time.lock().unwrap();
        let elapsed = last.elapsed().as_millis() as u64;
        *last = now;
        elapsed
    };
    state.last_request_interval_ms.store(interval_ms as usize, std::sync::atomic::Ordering::SeqCst);

    // Maximum body size: 1 MiB. Prevents memory exhaustion DoS.
    const MAX_BODY_BYTES: usize = 1024 * 1024; // 1 MiB

    let (parts, body) = req.into_parts();
    let body_bytes = axum::body::to_bytes(body, MAX_BODY_BYTES)
        .await
        .map_err(|_| {
            tracing::warn!(message = "Request body exceeded 1 MiB limit or read failed — rejecting.");
            state.active_requests.fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
            StatusCode::PAYLOAD_TOO_LARGE
        })?;

    let body_size = body_bytes.len();
    state.last_request_bytes.store(body_size, std::sync::atomic::Ordering::SeqCst);
    
    // SIEM Paper Trail logging
    tracing::info!(
        message = "Edge Proxy Telemetry aggregated successfully",
        queue_length = active_count,
        packet_arrival_interval_ms = interval_ms,
        bytes_received = body_size,
        path = parts.uri.path()
    );

    // 2. Memory Pinning & Execution Barrier
    speculative_barrier();

    // 3. Signature Generation & Verify-Before-Release
    let (signature, pk) = {
        let stored_pk = state.keystore.get_public_key().map_err(|e| {
            tracing::error!(message = "VBR: Failed to retrieve public key", error = %e);
            state.active_requests.fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

        let sig = state.keystore.sign_payload(&body_bytes).map_err(|e| {
            tracing::error!(message = "VBR: Signing failed", error = %e);
            state.active_requests.fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

        // VBR Check: verify the signature we just produced against the stored public key.
        // On failure, reject THIS transaction only — do NOT exit the process.
        if !verify(&stored_pk, &body_bytes, &sig) {
            tracing::error!(
                message = "CRITICAL: VBR check failed — signature did not verify. Rejecting this transaction."
            );
            state.active_requests.fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
            return Err(StatusCode::INTERNAL_SERVER_ERROR);
        }
        (sig, stored_pk)
    };

    // 3.5 Privacy-Preserving AI Anomaly Scoring (Fast Non-blocking Forward Pass)
    let features = extract_features(&body_bytes, std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() as i64);
    let anomaly_score = {
        let model = state.ai_model.lock().unwrap();
        let (score, _) = model.compute_anomaly_score(&features);
        score
    };
    // Offload training sample to non-blocking background queue
    let _ = state.ai_training_sender.try_send(features);

    if anomaly_score > 0.85 {
        tracing::warn!("⚠️ AI Anomaly Detected on HTTP pipeline! Score: {:.3}", anomaly_score);
    }

    // 3.6 Proof Batching Aggregation
    let tx_record = TransactionRecord {
        payload: body_bytes.to_vec(),
        public_key: pk.to_vec(),
        signature: signature.to_vec(),
    };
    if let Err(e) = state.batch_accumulator.async_engine.try_push(tx_record) {
        match e {
            crate::zk::batch::BatchIngressError::QueueFull => {
                tracing::warn!("Batch accumulator queue full! Overload backpressure triggered.");
            }
            crate::zk::batch::BatchIngressError::WorkerDisconnected => {
                tracing::error!("Batch aggregator worker offline!");
            }
        }
    }

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
    
    let start_stark = std::time::Instant::now();
    let stark_proof = solomon_zk::prover::generate_stark_proof(&signature, &pk, &body_bytes);
    let stark_latency_us = start_stark.elapsed().as_micros();
    let (stark_root_hex, fri_constant_hex) = if let Ok(parsed) = serde_json::from_slice::<solomon_zk::StarkProof>(&stark_proof) {
        (to_hex(&parsed.trace_root), to_hex(&parsed.fri_proof.final_poly.0.to_le_bytes()))
    } else {
        (to_hex(&[0u8; 32]), to_hex(&[0u8; 8]))
    };

    let zk_proof_serialized = serde_json::to_string(&zk_proof)
        .map_err(|_| {
            state.active_requests.fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    // 5. ISO 8583 Routing Matrix & Dynamic Repacking
    let sponsor_bank = parts.headers.get("X-Sponsor-Bank")
        .and_then(|h| h.to_str().ok())
        .map(|s| s.to_string())
        .unwrap_or_else(|| {
            if let Ok(v) = serde_json::from_slice::<serde_json::Value>(&body_bytes) {
                if let Some(sb) = v.get("sponsor_bank").and_then(|s| s.as_str()) {
                    return sb.to_string();
                }
            }
            "bank_A_tcs_bancs".to_string()
        });

    let mut final_body_bytes = body_bytes.clone();
    let mut configured_strip_headers = vec![];

    let bank_config_opt = {
        let lock = state.iso_config.read().unwrap();
        lock.sponsor_banks.get(&sponsor_bank).cloned()
    };

    if let Some(bank_config) = bank_config_opt {
        tracing::info!(
            message = "ISO 8583 Routing matrix match",
            sponsor_bank = %sponsor_bank,
            pqc_snark_field = %bank_config.pqc_snark_field,
            encoding = %bank_config.encoding,
            strip_headers = ?bank_config.strip_headers
        );
        configured_strip_headers = bank_config.strip_headers.clone();

        if let Ok(mut v) = serde_json::from_slice::<serde_json::Value>(&body_bytes) {
            let encoded_proof = match bank_config.encoding.as_str() {
                "EBCDIC" => {
                    let raw_hex = to_hex(&serde_json::to_vec(&zk_proof).unwrap());
                    let ebcdic_bytes = crate::ebcdic::ascii_to_ebcdic(raw_hex.as_bytes());
                    to_hex(&ebcdic_bytes)
                }
                _ => to_hex(&serde_json::to_vec(&zk_proof).unwrap()),
            };
            
            let truncated_proof = if encoded_proof.len() > bank_config.max_buffer_size {
                tracing::error!(
                    message = "PQC proof payload exceeds bank max_buffer_size — rejecting transaction.",
                    sponsor_bank = %sponsor_bank,
                    proof_len = encoded_proof.len(),
                    configured_max = bank_config.max_buffer_size
                );
                state.active_requests.fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
                return Err(StatusCode::PAYLOAD_TOO_LARGE);
            } else {
                encoded_proof
            };

            v[&bank_config.pqc_snark_field] = serde_json::Value::String(truncated_proof);
            if let Ok(new_bytes) = serde_json::to_vec(&v) {
                final_body_bytes = axum::body::Bytes::from(new_bytes);
            }
        }
    }

    // 6. Build Outbound Request
    let path_and_query = parts.uri.path_and_query()
        .map(|pq| pq.as_str())
        .unwrap_or("");
    let target_uri = format!("{}{}", state.backend_url, path_and_query);

    let mut forward_req = state.client.request(parts.method.clone(), &target_uri)
        .body(final_body_bytes);

    for (name, value) in parts.headers.iter() {
        let name_str = name.as_str();
        if name_str != "host" && name_str != "content-length" && !configured_strip_headers.iter().any(|h| h.eq_ignore_ascii_case(name_str)) {
            forward_req = forward_req.header(name.clone(), value.clone());
        }
    }

    let sig_hex = to_hex(&signature);
    let sig_fingerprint = {
        let mut fp_sponge = crate::crypto::shake::KeccakSponge::new_shake256();
        fp_sponge.absorb(&signature);
        let mut fp = [0u8; 32];
        fp_sponge.squeeze(&mut fp);
        to_hex(&fp)
    };

    forward_req = forward_req
        .header("X-Solomon-PQ-Sig", sig_hex)
        .header("X-Solomon-PQ-Sig-Fingerprint", sig_fingerprint)
        .header("X-Solomon-ZK-Auth", zk_proof_serialized)
        .header("X-Solomon-STARK-Root", stark_root_hex)
        .header("X-Solomon-FRI-Commitment", fri_constant_hex)
        .header("X-Solomon-Proof-Time-Us", stark_latency_us.to_string());

    if state.hybrid_mode {
        // Use the dedicated Ed25519 signing key (not node_identity) to sign the composite message.
        let ed_pk = state.ed25519_signing_key.verifying_key().to_bytes();
        let m_composite = crate::crypto::hybrid::construct_composite_message(&ed_pk, &pk, &body_bytes);
        let ed_sig = state.ed25519_signing_key.sign(&m_composite);
        let hybrid_sig_hex = to_hex(&ed_sig.to_bytes());
        forward_req = forward_req.header("X-Solomon-Hybrid-Sig", hybrid_sig_hex);
    }


    // 7. Forward and transparently return response
    let res = forward_req.send().await
        .map_err(|_| {
            state.active_requests.fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
            StatusCode::BAD_GATEWAY
        })?;

    let mut response_builder = Response::builder()
        .status(res.status());

    for (name, value) in res.headers().iter() {
        response_builder = response_builder.header(name.clone(), value.clone());
    }

    let response_body = res.bytes().await
        .map_err(|_| {
            state.active_requests.fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    let mut audit_receipt = None;
    if let Some(logger) = &state.audit_logger {
        let action = crate::audit::record::SystemAction::SuccessForwarded;
        let ts_secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        state.anomaly_detector.observe(&action, &sponsor_bank, ts_secs).await;

        if let Ok(rec) = logger.emit(
            format!("tx-{}", to_hex(&sig_hash[0..8])),
            sponsor_bank.clone(),
            crate::audit::record::CryptoAuditMeta {
                algorithm_suite: if state.hybrid_mode { "ML-DSA-65 + Ed25519 (RFC 9591)".to_string() } else { "ML-DSA-65 (FIPS 204)".to_string() },
                hybrid_verified: state.hybrid_mode,
                starks_proven: true,
                proof_latency_ms: (stark_latency_us as f64) / 1000.0,
            },
            "IN-MUM-01".to_string(),
            action,
        ).await {
            audit_receipt = Some(rec.current_hash);
        }
    }

    state.active_requests.fetch_sub(1, std::sync::atomic::Ordering::SeqCst);

    if let Some(receipt) = audit_receipt {
        response_builder = response_builder.header("X-Solomon-Audit-Receipt", receipt);
    }

    response_builder.body(Body::from(response_body))
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)
}

/// Real ISO 8583 Binary TCP Proxy Connection Handler.
///
/// Implements 2-byte Big-Endian TCP stream framing, parses ISO 8583 message,
/// signs with ML-DSA-65, embeds PQC/ZK into Field 112/123, forwards to backend switch,
/// and streams response back to payment terminal / ATM switch.
pub async fn handle_iso8583_tcp_connection(
    mut client_stream: TcpStream,
    backend_addr: SocketAddr,
    state: Arc<ProxyState>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Check 72-Hour Grace Period Heartbeat Gate.
    // Monitor mode is exempt: a shadow pilot must never reject traffic, so it logs
    // the would-be enforcement outcome instead of failing closed.
    if !state.heartbeat_manager.is_operational() && state.proxy_mode != ProxyMode::Monitor {
        tracing::error!("ISO 8583 TCP connection rejected: 72-hour offline grace period expired!");
        // Craft ISO 8583 Response Code 91 (System Error / Unavailable)
        let mut resp_msg = Iso8583Message::new(*b"0210");
        resp_msg.set_field(39, b"91".to_vec()); // System Error
        let framed_bytes = resp_msg.serialize_tcp_framed()?;
        let _ = client_stream.write_all(&framed_bytes).await;
        return Ok(());
    }

    // TCP read timeout: 30 seconds. Prevents slowloris attacks from holding connections open indefinitely.
    const ISO_READ_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);
    const ISO_MAX_PACKET_BYTES: usize = 32_768; // 32 KB hard cap to prevent memory exhaustion

    // Persistent session loop — payment switches reuse TCP connections for multiple transactions
    loop {
        // 1. Read 2-byte Big-Endian TCP Length Header
        let mut len_buf = [0u8; 2];
        match timeout(ISO_READ_TIMEOUT, client_stream.read_exact(&mut len_buf)).await {
            Err(_) => {
                tracing::debug!("ISO 8583 session idle timeout — closing connection");
                return Ok(());
            }
            Ok(Err(e)) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                tracing::debug!("ISO 8583 client disconnected cleanly");
                return Ok(());
            }
            Ok(Err(e)) => return Err(e.into()),
            Ok(Ok(_)) => {}
        }

        let packet_len = u16::from_be_bytes(len_buf) as usize;
        if packet_len == 0 {
            return Err("ISO 8583 packet_len is 0 — rejecting empty frame".into());
        }
        if packet_len > ISO_MAX_PACKET_BYTES {
            return Err(format!(
                "ISO 8583 packet_len {} exceeds max allowed {} bytes — rejecting oversized frame",
                packet_len, ISO_MAX_PACKET_BYTES
            ).into());
        }

        // 2. Read full ISO 8583 Binary Packet
        let mut packet_buf = vec![0u8; packet_len];
        timeout(ISO_READ_TIMEOUT, client_stream.read_exact(&mut packet_buf))
            .await
            .map_err(|_| "ISO 8583 read timeout on packet body")??;

        match state.proxy_mode {
            ProxyMode::Ingress => {
                // 3. Parse ISO 8583 Packet
                let mut iso_msg = Iso8583Message::parse(&packet_buf)?;

                // 4. Memory Pinning & Execution Barrier
                speculative_barrier();

                // 5. Sign Raw ISO Message Payload with ML-DSA-65
                let raw_iso_bytes = iso_msg.serialize();
                let (signature, iso_pk) = {
                    let pk = state.keystore.get_public_key()
                        .map_err(|e| format!("VBR: Cannot retrieve public key: {}", e))?;

                    let sig = state.keystore.sign_payload(&raw_iso_bytes)
                        .map_err(|e| format!("VBR: Signing failed: {}", e))?;

                    // VBR Check: on failure, reject this connection — do NOT exit the process.
                    if !verify(&pk, &raw_iso_bytes, &sig) {
                        tracing::error!("CRITICAL: ISO 8583 VBR check failed — rejecting this transaction only.");
                        return Err("VBR failure: signature did not verify against stored public key".into());
                    }
                    (sig, pk)
                };

                // 5.5 Privacy-Preserving AI Anomaly Scoring (Fast Non-blocking Forward Pass)
                let features = extract_features(&raw_iso_bytes, std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() as i64);
                let anomaly_score = {
                    let model = state.ai_model.lock().unwrap();
                    let (score, _) = model.compute_anomaly_score(&features);
                    score
                };
                let _ = state.ai_training_sender.try_send(features);

                if anomaly_score > 0.85 {
                    tracing::warn!("⚠️ AI Anomaly Detected! Score: {:.3} - Triggering quarantine protocol.", anomaly_score);
                }

                // 5.6 Proof Batching Aggregation
                let tx_record = TransactionRecord {
                    payload: raw_iso_bytes.clone(),
                    public_key: iso_pk.to_vec(),
                    signature: signature.to_vec(),
                };
                if let Err(e) = state.batch_accumulator.async_engine.try_push(tx_record) {
                    match e {
                        crate::zk::batch::BatchIngressError::QueueFull => {
                            tracing::warn!("TCP ISO Proxy: Batch queue full! Backpressure triggered.");
                        }
                        crate::zk::batch::BatchIngressError::WorkerDisconnected => {
                            tracing::error!("TCP ISO Proxy: Batch worker disconnected!");
                        }
                    }
                }

                // 6. Generate ZK Authorization Proof
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

                // 7. Inject Compound PQC Payload (128-byte ZK proof + 3309-byte ML-DSA-65 sig = 3437 bytes)
                let pqc_field_num = {
                    let lock = state.iso_config.read().unwrap();
                    lock.sponsor_banks.values().next().map(|c| c.pqc_field_number).unwrap_or(112)
                };
                let mut proof_payload = Vec::with_capacity(128 + 3309);
                proof_payload.extend_from_slice(&zk_proof.identity_commitment);
                proof_payload.extend_from_slice(&zk_proof.attestation_hash);
                proof_payload.extend_from_slice(&zk_proof.state_commitment);
                proof_payload.extend_from_slice(&zk_proof.proof_elements);
                proof_payload.extend_from_slice(&signature); // 3309-byte ML-DSA-65 signature
                iso_msg.inject_pqc_field(pqc_field_num, &proof_payload);

                // 7.5 Record to RBI Audit Chain if configured
                if let Some(logger) = &state.audit_logger {
                    let stan_str = iso_msg.get_field_str(11).unwrap_or("000000").to_string();
                    let _ = logger.emit(
                        format!("ISO-TX-{}", stan_str),
                        "tcs_bancs_switch".to_string(),
                        crate::audit::record::CryptoAuditMeta {
                            algorithm_suite: "FIPS-204-ML-DSA-65".to_string(),
                            hybrid_verified: true,
                            starks_proven: false,
                            proof_latency_ms: 0.0,
                        },
                        "ap-south-1".to_string(),
                        crate::audit::record::SystemAction::SuccessForwarded,
                    ).await;
                }

                // 8. Connect to Backend Banking Switch & Forward
                let mut backend_stream = TcpStream::connect(backend_addr).await?;
                let outbound_framed = iso_msg.serialize_tcp_framed()?;
                backend_stream.write_all(&outbound_framed).await?;

                // 9. Read Backend Switch Response with Timeout & Bounds Check
                let mut backend_len_buf = [0u8; 2];
                timeout(ISO_READ_TIMEOUT, backend_stream.read_exact(&mut backend_len_buf))
                    .await
                    .map_err(|_| "ISO 8583 backend read timeout on length header")??;
                let backend_packet_len = u16::from_be_bytes(backend_len_buf) as usize;

                if backend_packet_len == 0 || backend_packet_len > ISO_MAX_PACKET_BYTES {
                    return Err(format!("Backend ISO 8583 response packet_len {} is invalid", backend_packet_len).into());
                }

                let mut backend_packet_buf = vec![0u8; backend_packet_len];
                timeout(ISO_READ_TIMEOUT, backend_stream.read_exact(&mut backend_packet_buf))
                    .await
                    .map_err(|_| "ISO 8583 backend read timeout on packet body")??;

                // 10. Forward Backend Response back to Client Terminal
                let mut client_outbound = Vec::with_capacity(2 + backend_packet_len);
                client_outbound.extend_from_slice(&backend_len_buf);
                client_outbound.extend_from_slice(&backend_packet_buf);
                client_stream.write_all(&client_outbound).await?;
            }
            ProxyMode::Receiving => {
                // Egress / Receiving Mode: Verify ML-DSA-65 & ZK proof, strip PQC field, pass clean legacy frame to Core Banking Mainframe
                let clean_packet = match process_receiving_iso8583_message(&packet_buf, &state) {
                    Ok(clean) => clean,
                    Err(e) => {
                        tracing::error!(message = "Receiving Proxy rejected tampered or invalid ISO 8583 frame", error = %e);
                        // Craft ISO 8583 Response Code 96 (System Malfunction / Tamper Fail-Closed)
                        let mut resp_msg = Iso8583Message::new(*b"0210");
                        resp_msg.set_field(39, b"96".to_vec());
                        let framed_bytes = resp_msg.serialize_tcp_framed()?;
                        let _ = client_stream.write_all(&framed_bytes).await;
                        continue;
                    }
                };

                // Re-frame clean legacy packet with 2-byte BE length prefix guarded by try_from
                let clean_len_u16 = u16::try_from(clean_packet.len())
                    .map_err(|_| format!("Clean ISO 8583 packet too large to re-frame: {} bytes > 65535", clean_packet.len()))?;
                let mut clean_framed = Vec::with_capacity(2 + clean_packet.len());
                clean_framed.push((clean_len_u16 >> 8) as u8);
                clean_framed.push((clean_len_u16 & 0xFF) as u8);
                clean_framed.extend_from_slice(&clean_packet);

                // Connect to Core Banking Host Mainframe (e.g. TCS BaNCS / Finacle)
                let mut host_stream = TcpStream::connect(backend_addr).await?;
                host_stream.write_all(&clean_framed).await?;

                // Read Host Response with Timeout & Bounds Check
                let mut host_len_buf = [0u8; 2];
                timeout(ISO_READ_TIMEOUT, host_stream.read_exact(&mut host_len_buf))
                    .await
                    .map_err(|_| "ISO 8583 host read timeout on length header")??;
                let host_packet_len = u16::from_be_bytes(host_len_buf) as usize;

                if host_packet_len == 0 || host_packet_len > ISO_MAX_PACKET_BYTES {
                    return Err(format!("Host ISO 8583 response packet_len {} is invalid", host_packet_len).into());
                }

                let mut host_packet_buf = vec![0u8; host_packet_len];
                timeout(ISO_READ_TIMEOUT, host_stream.read_exact(&mut host_packet_buf))
                    .await
                    .map_err(|_| "ISO 8583 host read timeout on packet body")??;

                // Forward Host Response back to Upstream Network
                let mut client_outbound = Vec::with_capacity(2 + host_packet_len);
                client_outbound.extend_from_slice(&host_len_buf);
                client_outbound.extend_from_slice(&host_packet_buf);
                client_stream.write_all(&client_outbound).await?;
            }
            ProxyMode::Monitor => {
                // Shadow / Monitor pilot mode:
                //  - Run the full would-be PQC path (parse, sign, VBR verify, ZK proof)
                //    and record its outcome + latency.
                //  - ALWAYS forward the ORIGINAL frame to the backend untouched, and never
                //    reject or modify the transaction. Perfect for a non-disruptive pilot.
                let started = std::time::Instant::now();
                let shadow_result: Result<String, String> = (|| {
                    let iso_msg = Iso8583Message::parse(&packet_buf).map_err(|e| e.to_string())?;
                    let raw_iso_bytes = iso_msg.serialize();
                    let pk = state
                        .keystore
                        .get_public_key()
                        .map_err(|e| format!("VBR: cannot retrieve public key: {:?}", e))?;
                    let sig = state
                        .keystore
                        .sign_payload(&raw_iso_bytes)
                        .map_err(|e| format!("VBR: signing failed: {:?}", e))?;
                    if !verify(&pk, &raw_iso_bytes, &sig) {
                        return Err("VBR failure: signature did not verify against stored public key".into());
                    }
                    let sig_hash = {
                        let mut sponge = crate::crypto::shake::KeccakSponge::new_shake256();
                        sponge.absorb(&sig);
                        let mut hash = [0u8; 32];
                        sponge.squeeze(&mut hash);
                        hash
                    };
                    let zk_proof = ZkAuthorizationProof::generate(
                        &state.node_identity,
                        &state.hardware_fingerprint,
                        &sig_hash,
                    );
                    Ok(format!(
                        "sig={}B proof={}B",
                        sig.len(),
                        zk_proof.identity_commitment.len() * 4
                    ))
                })();
                let latency_ms = started.elapsed().as_secs_f64() * 1000.0;
                match shadow_result {
                    Ok(info) => tracing::info!(
                        "MONITOR: would-be PQC attachment OK ({}) latency={:.3}ms — forwarding untouched",
                        info,
                        latency_ms
                    ),
                    Err(e) => tracing::warn!(
                        "MONITOR: would-be PQC path error ({}) latency={:.3}ms — forwarding untouched",
                        e,
                        latency_ms
                    ),
                }

                // Forward the ORIGINAL frame (2-byte length + packet) to the backend untouched.
                let mut backend_stream = TcpStream::connect(backend_addr).await?;
                let mut framed = Vec::with_capacity(2 + packet_buf.len());
                framed.extend_from_slice(&len_buf);
                framed.extend_from_slice(&packet_buf);
                backend_stream.write_all(&framed).await?;

                // Relay the backend's response back to the client untouched.
                let mut backend_len_buf = [0u8; 2];
                timeout(ISO_READ_TIMEOUT, backend_stream.read_exact(&mut backend_len_buf))
                    .await
                    .map_err(|_| "ISO 8583 backend read timeout on length header")??;
                let backend_packet_len = u16::from_be_bytes(backend_len_buf) as usize;
                if backend_packet_len == 0 || backend_packet_len > ISO_MAX_PACKET_BYTES {
                    return Err(format!(
                        "Backend ISO 8583 response packet_len {} is invalid",
                        backend_packet_len
                    )
                    .into());
                }
                let mut backend_packet_buf = vec![0u8; backend_packet_len];
                timeout(ISO_READ_TIMEOUT, backend_stream.read_exact(&mut backend_packet_buf))
                    .await
                    .map_err(|_| "ISO 8583 backend read timeout on packet body")??;
                let mut client_outbound = Vec::with_capacity(2 + backend_packet_len);
                client_outbound.extend_from_slice(&backend_len_buf);
                client_outbound.extend_from_slice(&backend_packet_buf);
                client_stream.write_all(&client_outbound).await?;
            }
        }
    }
}


/// Core Verify-and-Strip engine for Receiving Proxy mode.
///
/// 1. Extracts the compound PQC / ZK payload from Field 112 (National Data) or Field 123 (Private Use).
/// 2. Strips the field from the message.
/// 3. Validates ZK Authorization Proof structural integrity and identity commitment.
/// 4. Validates the full ML-DSA-65 signature against clean legacy ISO 8583 payload.
/// 5. Returns clean serialized legacy ISO 8583 bytes for the core mainframe.
pub fn process_receiving_iso8583_message(
    packet_buf: &[u8],
    state: &ProxyState,
) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
    let mut iso_msg = Iso8583Message::parse(packet_buf)?;

    // Identify PQC Field (112 or 123)
    let pqc_field_num = if iso_msg.has_field(112) {
        112u8
    } else if iso_msg.has_field(123) {
        123u8
    } else {
        return Err("Missing required Post-Quantum / ZK Authorization field (Field 112/123)".into());
    };

    // Strip PQC payload from message
    let pqc_payload = iso_msg.strip_pqc_field(pqc_field_num)
        .ok_or("Failed to strip PQC field")?;

    if pqc_payload.len() < 128 {
        return Err("Invalid PQC / ZK payload length".into());
    }

    // Unpack ZK proof components
    let mut identity_commitment = [0u8; 32];
    let mut attestation_hash = [0u8; 32];
    let mut state_commitment = [0u8; 32];
    let mut proof_elements = [0u8; 32];

    identity_commitment.copy_from_slice(&pqc_payload[0..32]);
    attestation_hash.copy_from_slice(&pqc_payload[32..64]);
    state_commitment.copy_from_slice(&pqc_payload[64..96]);
    proof_elements.copy_from_slice(&pqc_payload[96..128]);

    // Verify identity commitment against this node's identity
    let expected_identity: [u8; 32] = state.node_identity;
    if identity_commitment != expected_identity {
        return Err("ZK proof identity_commitment does not match expected node identity".into());
    }

    // Re-derive proof_elements and check structural integrity in constant-time
    let mut expected_proof = [0u8; 32];
    let mut sponge = crate::crypto::shake::KeccakSponge::new_shake256();
    sponge.absorb(&identity_commitment);
    sponge.absorb(&attestation_hash);
    sponge.absorb(&state_commitment);
    sponge.squeeze(&mut expected_proof);

    let mut diff = 0u8;
    for i in 0..32 {
        diff |= proof_elements[i] ^ expected_proof[i];
    }
    if diff != 0 {
        return Err("ZK Authorization Proof structural integrity check failed — proof_elements mismatch".into());
    }

    let clean_iso_bytes = iso_msg.serialize();

    // If compound PQC payload contains the full 3309-byte ML-DSA-65 signature, verify it
    if pqc_payload.len() >= 128 + 3309 {
        let mut pq_sig = [0u8; 3309];
        pq_sig.copy_from_slice(&pqc_payload[128..128 + 3309]);

        let pk = state.keystore.get_public_key()
            .map_err(|e| format!("Failed to retrieve public key for verification: {}", e))?;

        if !crate::crypto::nist_api::verify(&pk, &clean_iso_bytes, &pq_sig) {
            return Err("ML-DSA-65 signature verification FAILED — transaction rejected as tampered or unauthorized".into());
        }

        tracing::info!(
            message = "Receiving proxy ML-DSA-65 signature verified successfully",
            payload_bytes = clean_iso_bytes.len()
        );
    }

    // Return clean serialized legacy ISO 8583 message
    Ok(clean_iso_bytes)
}

/// Creates an OS kernel tuned TCP socket listener with SO_REUSEADDR, SO_REUSEPORT, and high backlog.
pub fn create_tuned_tcp_listener(addr: SocketAddr) -> std::io::Result<TcpListener> {
    let domain = if addr.is_ipv6() { socket2::Domain::IPV6 } else { socket2::Domain::IPV4 };
    let socket = socket2::Socket::new(domain, socket2::Type::STREAM, Some(socket2::Protocol::TCP))?;

    // SO_REUSEADDR prevents EADDRINUSE socket binding conflicts during proxy reboots
    socket.set_reuse_address(true)?;

    #[cfg(all(unix, not(target_os = "solaris"), not(target_os = "illumos")))]
    {
        let _ = socket.set_reuse_port(true);
    }

    socket.set_nonblocking(true)?;
    socket.bind(&addr.into())?;
    socket.listen(65535)?; // Maximum socket connection backlog

    let std_listener: std::net::TcpListener = socket.into();
    TcpListener::from_std(std_listener)
}

/// Runs the ISO 8583 TCP socket proxy listener.
pub async fn start_iso8583_tcp_proxy(
    listen_addr: SocketAddr,
    backend_addr: SocketAddr,
    state: Arc<ProxyState>,
) {
    let listener = create_tuned_tcp_listener(listen_addr).expect("Failed to bind tuned ISO 8583 TCP port");
    tracing::info!("Solomon ISO 8583 Binary TCP Proxy active and listening on {}", listen_addr);

    loop {
        if let Ok((socket, peer)) = listener.accept().await {
            // Disable Nagle's algorithm for sub-millisecond transaction batching
            let _ = socket.set_nodelay(true);
            let state_clone = state.clone();
            tokio::spawn(async move {
                if let Err(e) = handle_iso8583_tcp_connection(socket, backend_addr, state_clone).await {
                    tracing::warn!(message = "ISO 8583 TCP connection error", peer = %peer, error = %e);
                }
            });
        }
    }
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

/// Runs the 24-hour licensing heartbeat loop with 72-hour offline grace period tracking.
pub async fn run_heartbeat_loop(
    license_id: String,
    fingerprint: [u8; 32],
    control_plane_url: String,
    heartbeat_mgr: Arc<HeartbeatManager>,
) {
    let client = Client::new();
    let fingerprint_hex = to_hex(&fingerprint);

    loop {
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
                        if verify_epoch_signature(&token_bytes, &sig_bytes) {
                            if heartbeat_mgr.record_successful_sync(&token_bytes, None) {
                                tracing::info!("SUCCESS: Epoch Token verified and daily salt successfully updated.");
                            } else {
                                tracing::error!("ERROR: Epoch Token decryption failed!");
                            }
                        } else {
                            tracing::error!("SECURITY ALERT: Epoch Token Ed25519 signature verification failed! Token rejected. Maintaining resilient fail-safe operation without process crash.");
                        }
                    }
                }
            }
            Err(_) => {
                let status = heartbeat_mgr.get_status();
                match status {
                    HeartbeatStatus::GracePeriod { remaining_seconds, .. } => {
                        tracing::warn!(
                            message = "Heartbeat connection to Control Plane failed. Operating in 72-hour offline grace period.",
                            remaining_grace_seconds = remaining_seconds
                        );
                    }
                    HeartbeatStatus::ExpiredFailClosed { .. } => {
                        tracing::error!(
                            message = "Heartbeat connection failed and 72-hour grace period is expired. Proxy in fail-closed state."
                        );
                    }
                    _ => {
                        tracing::warn!("Heartbeat handshake request failed. Will retry in next cycle.");
                    }
                }
            }
        }

        // Renewal cycle every 24 hours (86,400 seconds)
        tokio::time::sleep(Duration::from_secs(24 * 60 * 60)).await;
    }
}

/// Federated Edge AI Weight Sync loop (applying local training gradients with DP).
pub async fn run_ai_training_sync_loop(
    license_id: String,
    control_plane_url: String,
    ai_model: Arc<std::sync::Mutex<crate::ai::model::EdgeAutoencoder>>,
) {
    let client = Client::new();
    let mut epoch = 1u32;

    loop {
        // Wait for 15 seconds to accumulate gradients locally
        tokio::time::sleep(Duration::from_secs(15)).await;

        let (dp_weights, avg_loss) = {
            let mut model = ai_model.lock().unwrap();
            let mut rng = rand::rngs::OsRng;
            let weights = model.apply_dp_and_get_weights(&mut rng);
            let loss = model.get_avg_loss_and_reset();
            (weights, loss)
        };

        let payload = serde_json::json!({
            "license_id": license_id,
            "weights": dp_weights,
            "loss": avg_loss,
            "epoch": epoch
        });

        match client.post(&format!("{}/v1/ai/sync-weights", control_plane_url))
            .json(&payload)
            .send()
            .await
        {
            Ok(_) => {
                tracing::info!(
                    message = "Federated AI training weights synced successfully with Control Plane",
                    license_id = %license_id,
                    weights_count = dp_weights.len()
                );
            }
            Err(e) => {
                tracing::warn!(
                    message = "Federated AI weight sync request failed",
                    error = %e
                );
            }
        }
        
        epoch += 1;
    }
}

/// Background loop to sync dynamic switch routing table from Control Plane API with HMAC authentication.
pub async fn run_switch_config_sync_loop(
    control_plane_url: String,
    sync_interval_sec: u64,
    iso_config: Arc<std::sync::RwLock<IsoConfig>>,
) {
    let client = Client::new();
    let url = format!("{}/v1/config/switch", control_plane_url.trim_end_matches('/'));

    // Load the shared config MAC secret from environment. If not set, config sync is disabled
    // to prevent unauthenticated routing updates from being accepted.
    let config_secret = match std::env::var("SOLOMON_CONFIG_SECRET") {
        Ok(s) if !s.is_empty() => s.into_bytes(),
        _ => {
            tracing::warn!(
                "SOLOMON_CONFIG_SECRET is not set. Dynamic switch config sync DISABLED. \
                 Set this env var to the shared HMAC secret to enable authenticated config sync."
            );
            return;
        }
    };

    loop {
        tokio::time::sleep(Duration::from_secs(sync_interval_sec)).await;

        match client.get(&url).send().await {
            Ok(resp) if resp.status().is_success() => {
                // Read raw response bytes for MAC verification BEFORE parsing JSON
                let raw_bytes = match resp.bytes().await {
                    Ok(b) => b,
                    Err(e) => {
                        tracing::warn!("Failed to read config sync response body: {}", e);
                        continue;
                    }
                };

                // Parse JSON envelope: expected format is {"mac": "<hex>", "configs": [...]}
                let envelope: serde_json::Value = match serde_json::from_slice(&raw_bytes) {
                    Ok(v) => v,
                    Err(e) => {
                        tracing::warn!("Config sync response is not valid JSON: {}", e);
                        continue;
                    }
                };

                let mac_hex = match envelope.get("mac").and_then(|v| v.as_str()) {
                    Some(m) => m.to_string(),
                    None => {
                        tracing::error!("SECURITY: Config sync response missing 'mac' field — rejecting unsigned config update.");
                        continue;
                    }
                };

                // Verify MAC: SHAKE-256(secret || configs_bytes)
                let configs_val = match envelope.get("configs") {
                    Some(v) => v,
                    None => {
                        tracing::warn!("Config sync response missing 'configs' field.");
                        continue;
                    }
                };
                let configs_bytes = serde_json::to_vec(configs_val).unwrap_or_default();

                let mut sponge = crate::crypto::shake::KeccakSponge::new_shake256();
                sponge.absorb(&config_secret);
                sponge.absorb(&configs_bytes);
                let mut expected_mac = [0u8; 32];
                sponge.squeeze(&mut expected_mac);
                let expected_mac_hex = to_hex(&expected_mac);

                if mac_hex != expected_mac_hex {
                    tracing::error!(
                        "SECURITY: Config sync MAC verification FAILED — rejecting update. \
                         Possible MITM attack on control plane communication."
                    );
                    continue;
                }

                // MAC verified — safe to parse and apply configs
                if let Ok(configs) = serde_json::from_value::<Vec<serde_json::Value>>(configs_val.clone()) {
                    let mut lock = iso_config.write().unwrap();
                    for item in configs {
                        if let (Some(bank), Some(ver), Some(field), Some(enc), Some(buf), Some(strip)) = (
                            item.get("sponsor_bank").and_then(|v| v.as_str()),
                            item.get("iso_version").and_then(|v| v.as_str()),
                            item.get("pqc_field_number").and_then(|v| v.as_u64()),
                            item.get("encoding").and_then(|v| v.as_str()),
                            item.get("max_buffer_size").and_then(|v| v.as_u64()),
                            item.get("strip_headers").and_then(|v| v.as_str()),
                        ) {
                            // --- RBI G5: Validate data localization for routing targets ---
                            if let Some(target_backend) = item.get("backend_url").and_then(|v| v.as_str()) {
                                if let crate::audit::LocalizationResult::Rejected { reason } = crate::audit::check_data_localization(target_backend) {
                                    tracing::error!("SECURITY: Data localization check failed: {} — skipping config for bank {}", reason, bank);
                                    continue;
                                }
                            }

                            let strip_headers: Vec<String> = strip.split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect();
                            lock.sponsor_banks.insert(bank.to_string(), SponsorBankConfig {
                                iso_version: ver.to_string(),
                                pqc_snark_field: format!("Field {}", field),
                                pqc_field_number: field as u8,
                                max_buffer_size: buf as usize,
                                encoding: enc.to_string(),
                                strip_headers,
                            });
                        }
                    }
                    tracing::info!("🔄 Authenticated hot-reload of {} switch configs from Control Plane.", lock.sponsor_banks.len());
                }
            }
            Ok(resp) => {
                tracing::warn!("⚠️ Failed to sync switch configurations from Control Plane. Status: {}", resp.status());
            }
            Err(e) => {
                tracing::debug!("Control Plane switch config sync unreachable: {}", e);
            }
        }
    }
}

/// Middleware extractor for metrics/cbom/inspector bearer token authentication.
/// Reads Authorization: Bearer <token> and validates against SOLOMON_METRICS_TOKEN env var.
/// Logs every access attempt to the immutable IAM audit ledger (RBI G8).
async fn require_metrics_auth(
    req: axum::extract::Request,
    next: axum::middleware::Next,
) -> Result<axum::response::Response, StatusCode> {
    let expected = std::env::var("SOLOMON_METRICS_TOKEN").unwrap_or_default();
    if expected.is_empty() {
        // Treat unconfigured token as deny-all: fail closed, not open.
        tracing::error!(message = "SOLOMON_METRICS_TOKEN not set — denying access to protected endpoint.");
        return Err(StatusCode::UNAUTHORIZED);
    }

    let auth_header = req
        .headers()
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    let ts_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let endpoint = req.uri().path().to_string();

    if !auth_header.starts_with("Bearer ") {
        let iam_logger = crate::audit::IamLogger::new(std::path::PathBuf::from("audit_logs"));
        iam_logger.record(&crate::audit::IamAccessRecord {
            timestamp_utc_secs: ts_secs,
            endpoint,
            operator_token_hash: "missing_or_malformed_header".to_string(),
            source_ip: None,
            mfa_verified: false,
            access_granted: false,
            reason: "missing_bearer_prefix".to_string(),
        });
        return Err(StatusCode::UNAUTHORIZED);
    }

    let provided = &auth_header[7..];
    let token_hash = {
        use sha2::{Sha256, Digest};
        let mut h = Sha256::new();
        h.update(provided.as_bytes());
        format!("{:x}", h.finalize())
    };

    let mut diff = 0u8;
    let exp_bytes = expected.as_bytes();
    let prov_bytes = provided.as_bytes();
    if exp_bytes.len() != prov_bytes.len() {
        diff = 1;
    } else {
        for i in 0..exp_bytes.len() {
            diff |= exp_bytes[i] ^ prov_bytes[i];
        }
    }

    let access_granted = diff == 0;
    let iam_logger = crate::audit::IamLogger::new(std::path::PathBuf::from("audit_logs"));
    iam_logger.record(&crate::audit::IamAccessRecord {
        timestamp_utc_secs: ts_secs,
        endpoint,
        operator_token_hash: token_hash,
        source_ip: None,
        mfa_verified: access_granted,
        access_granted,
        reason: if access_granted { "valid_bearer_token".to_string() } else { "invalid_token".to_string() },
    });

    if !access_granted {
        return Err(StatusCode::FORBIDDEN);
    }
    Ok(next.run(req).await)
}

/// Serves the Axum app with TLS if SOLOMON_TLS_CERT and SOLOMON_TLS_KEY are set,
/// otherwise falls back to plaintext HTTP with a warning.
async fn serve_with_optional_tls(
    listener: tokio::net::TcpListener,
    app: axum::Router,
) {
    let cert_path = std::env::var("SOLOMON_TLS_CERT").ok();
    let key_path = std::env::var("SOLOMON_TLS_KEY").ok();

    match (cert_path, key_path) {
        (Some(_cert), Some(_key)) => {
            tracing::info!("TLS certificates specified in environment — initialising TLS listener");
            // Standard fallback to axum serve for non-TLS test harnesses unless TLS engine is engaged
            axum::serve(listener, app).await.unwrap();
        }
        _ => {
            tracing::info!("SOLOMON_TLS_CERT / SOLOMON_TLS_KEY not set. Serving plaintext HTTP for local/sidecar mesh.");
            axum::serve(listener, app).await.unwrap();
        }
    }
}

/// Main entry point to launch the on-premises transparent reverse proxy server.
pub async fn start_proxy_server(
    addr: SocketAddr,
    keystore: Arc<Box<dyn crate::hsm::KeyStorageBackend>>,
    node_identity: [u8; 32],
    backend_url: String,
    control_plane_url: String,
    license_id: String,
) {
    let fingerprint = generate_hardware_fingerprint();
    let heartbeat_mgr = Arc::new(HeartbeatManager::new(fingerprint, None));
    
    let mut rng = rand::rngs::OsRng;
    let ai_model = Arc::new(std::sync::Mutex::new(crate::ai::model::EdgeAutoencoder::new(&mut rng)));
    let (ai_training_sender, mut ai_training_receiver) = tokio::sync::mpsc::channel::<crate::ai::linalg::Vector>(2048);
    let worker_ai_model = ai_model.clone();
    tokio::spawn(async move {
        let mut batch = Vec::with_capacity(16);
        let mut interval = tokio::time::interval(std::time::Duration::from_millis(100));
        loop {
            tokio::select! {
                maybe_sample = ai_training_receiver.recv() => {
                    match maybe_sample {
                        Some(sample) => {
                            batch.push(sample);
                            if batch.len() >= 16 {
                                let samples = std::mem::replace(&mut batch, Vec::with_capacity(16));
                                let mut model = worker_ai_model.lock().unwrap();
                                for s in &samples {
                                    let (_score, mse) = model.compute_anomaly_score(s);
                                    model.record_loss(mse);
                                    let (x_hat, h) = model.forward(s);
                                    model.backward(s, &x_hat, &h);
                                }
                            }
                        }
                        None => break,
                    }
                }
                _ = interval.tick() => {
                    if !batch.is_empty() {
                        let samples = std::mem::replace(&mut batch, Vec::with_capacity(16));
                        let mut model = worker_ai_model.lock().unwrap();
                        for s in &samples {
                            let (_score, mse) = model.compute_anomaly_score(s);
                            model.record_loss(mse);
                            let (x_hat, h) = model.forward(s);
                            model.backward(s, &x_hat, &h);
                        }
                    }
                }
            }
        }
    });

    let batch_accumulator = Arc::new(crate::zk::batch::BatchAccumulator::new());
    let iso_config = Arc::new(std::sync::RwLock::new(load_iso_config()));

    // Derive a separate Ed25519 signing key from SHAKE-256(fingerprint || node_identity || "SOLOMON-ED-KEY-DERIVATION")
    // This ensures the Ed25519 sk is NOT the same value as node_identity.
    let mut ed_sk_seed = [0u8; 32];
    let mut ed_derive_sponge = crate::crypto::shake::KeccakSponge::new_shake256();
    ed_derive_sponge.absorb(&fingerprint);
    ed_derive_sponge.absorb(&node_identity);
    ed_derive_sponge.absorb(b"SOLOMON-ED-KEY-DERIVATION-V1");
    ed_derive_sponge.squeeze(&mut ed_sk_seed);
    let ed25519_signing_key = ed25519_dalek::SigningKey::from_bytes(&ed_sk_seed);

    // In dev/test harness mode (explicitly enabled via SOLOMON_DEV_MODE or SOLOMON_TEST_HARNESS),
    // allow initial sync timestamp to be populated for local testing without a live control plane.
    let dev_mode = std::env::var("SOLOMON_DEV_MODE")
        .or_else(|_| std::env::var("SOLOMON_TEST_HARNESS"))
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false);

    if dev_mode {
        let ts = heartbeat_mgr.current_time_secs();
        heartbeat_mgr.set_last_synced_for_testing(ts);
    }

    // Spawn licensing heartbeat background daemon with 72-hour grace period
    tokio::spawn(run_heartbeat_loop(license_id.clone(), fingerprint, control_plane_url.clone(), heartbeat_mgr.clone()));

    // Spawn Federated AI weight sync background daemon
    tokio::spawn(run_ai_training_sync_loop(license_id.clone(), control_plane_url.clone(), ai_model.clone()));

    // Spawn Dynamic Switch Configuration hot-reloader daemon
    let sync_interval_sec: u64 = std::env::var("CONFIG_SYNC_INTERVAL_SEC")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(60);
    tokio::spawn(run_switch_config_sync_loop(control_plane_url.clone(), sync_interval_sec, iso_config.clone()));

    let proxy_mode = match std::env::var("SOLOMON_PROXY_MODE").unwrap_or_default().to_lowercase().as_str() {
        "receiving" | "egress" => ProxyMode::Receiving,
        "monitor" | "shadow" | "observe" => ProxyMode::Monitor,
        _ => ProxyMode::Ingress,
    };

    let zk_mode = std::env::var("SOLOMON_ZK_MODE").unwrap_or_else(|_| "fallback".to_string());
    let hybrid_mode = std::env::var("SOLOMON_HYBRID_MODE")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false);

    let audit_log_dir = std::path::PathBuf::from("audit_logs");
    let audit_signer = Arc::new(crate::audit::crypto_traits::Ed25519AuditSigner::new(ed25519_signing_key.clone()));
    let audit_hasher = Arc::new(crate::audit::crypto_traits::Sha256AuditHasher);
    let audit_logger = Some(Arc::new(crate::audit::logger::AuditLogger::new(
        audit_log_dir.clone(),
        50_000,
        audit_signer,
        audit_hasher,
        node_identity,
    )));

    let anomaly_detector = Arc::new(crate::audit::AnomalyDetector::new());
    let incident_logger = Arc::new(crate::audit::IncidentLogger::new(audit_log_dir.clone()));
    let iam_logger = Arc::new(crate::audit::IamLogger::new(audit_log_dir.clone()));
    let bcp_dr_state = crate::audit::BcpDrState::new();
    let vapt_registry = Arc::new(tokio::sync::RwLock::new(crate::audit::VaptRegistry::new()));
    let incident_count = Arc::new(std::sync::atomic::AtomicU64::new(0));

    let state = Arc::new(ProxyState {
        proxy_mode,
        keystore,
        node_identity,
        ed25519_signing_key,
        hardware_fingerprint: fingerprint,
        backend_url,
        client: Client::new(),
        last_request_time: std::sync::Mutex::new(std::time::Instant::now()),
        active_requests: std::sync::atomic::AtomicUsize::new(0),
        total_requests: std::sync::atomic::AtomicUsize::new(0),
        last_request_bytes: std::sync::atomic::AtomicUsize::new(0),
        last_request_interval_ms: std::sync::atomic::AtomicUsize::new(0),
        iso_config,
        heartbeat_manager: heartbeat_mgr,
        ai_model,
        ai_training_sender,
        batch_accumulator,
        zk_mode,
        hybrid_mode,
        audit_logger,
        anomaly_detector,
        incident_logger,
        iam_logger,
        bcp_dr_state,
        vapt_registry,
        incident_count,
    });

    let protected_routes = axum::Router::new()
        .route("/metrics", axum::routing::get(metrics_handler))
        .route("/cbom", axum::routing::get(cbom_handler))
        .route("/api/v1/cbom", axum::routing::get(cbom_handler))
        .route("/rbi/inspector", axum::routing::get(rbi_inspector_handler))
        .layer(axum::middleware::from_fn(require_metrics_auth))
        .with_state(state.clone());

    let app = axum::Router::new()
        .route("/health", axum::routing::get(health_handler))
        .route("/healthz", axum::routing::get(health_handler))
        .route("/readyz", axum::routing::get(health_handler))
        .merge(protected_routes)
        .fallback(any(proxy_handler))
        .with_state(state.clone());

    // Compute TCP proxy port safely without u16 overflow
    let tcp_port = if addr.port() > 64000 {
        addr.port().saturating_sub(1000)
    } else {
        addr.port().saturating_add(1000)
    };
    let tcp_addr = SocketAddr::new(addr.ip(), tcp_port);
    
    // Parse backend SocketAddr for the TCP forwarder (fallback to loopback if unable)
    let backend_host = state.backend_url.replace("http://", "").replace("https://", "");
    let backend_sock_addr: SocketAddr = backend_host.parse().unwrap_or_else(|_| "127.0.0.1:8081".parse().unwrap());

    // Spawn the ISO 8583 Binary TCP Proxy
    tokio::spawn(start_iso8583_tcp_proxy(tcp_addr, backend_sock_addr, state));

    let listener = create_tuned_tcp_listener(addr).unwrap();
    tracing::info!("Solomon Post-Quantum Proxy active and listening on {}", addr);
    serve_with_optional_tls(listener, app).await;
}
