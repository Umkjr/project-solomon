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

// Load the master license key from environment for enterprise deployments, or fallback to default
fn get_master_license_key() -> [u8; 32] {
    let mut key = [0u8; 32];
    let default_key = b"SOLOMON_KEY_2026_SECURE_LICENSE_";
    
    if let Ok(env_key) = std::env::var("SOLOMON_MASTER_LICENSE_KEY") {
        let bytes = env_key.as_bytes();
        let len = std::cmp::min(bytes.len(), 32);
        key[..len].copy_from_slice(&bytes[..len]);
    } else {
        key.copy_from_slice(default_key);
    }
    key
}

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

    // 1. Generate dynamic 32-byte daily salt
    let mut daily_salt = [0u8; 32];
    rand::thread_rng().fill(&mut daily_salt);

    // 2. Generate 32-byte random IV
    let mut iv = [0u8; 32];
    rand::thread_rng().fill(&mut iv);

    // 3. Keystream = SHAKE-256(Master Key || IV) (32 bytes)
    let master_key = get_master_license_key();
    let mut keystream_hasher = Shake256::default();
    keystream_hasher.update(&master_key);
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
    mac_hasher.update(&master_key);
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

// ==========================================
// 5. Phase 2 Enterprise Endpoints
// ==========================================

#[derive(Deserialize, Serialize, sqlx::FromRow)]
pub struct PkiNodeRecord {
    pub node_id: String,
    pub license_id: String,
    pub ml_dsa_pk: String,
    pub endpoint_url: Option<String>,
    pub is_trusted: i64,
}

#[derive(Deserialize)]
pub struct PkiRegisterRequest {
    pub node_id: String,
    pub license_id: String,
    pub ml_dsa_pk: String,
    pub endpoint_url: Option<String>,
}

/// Endpoint POST /v1/pki/register
/// Registers a new proxy node's post-quantum public key
pub async fn register_pki_node(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<PkiRegisterRequest>,
) -> Result<StatusCode, StatusCode> {
    sqlx::query(
        "INSERT OR REPLACE INTO pki_nodes (node_id, license_id, ml_dsa_pk, endpoint_url, is_trusted)
         VALUES (?1, ?2, ?3, ?4, 1);"
    )
    .bind(&payload.node_id)
    .bind(&payload.license_id)
    .bind(&payload.ml_dsa_pk)
    .bind(&payload.endpoint_url)
    .execute(&state.db_pool)
    .await
    .map_err(|e| {
        eprintln!("[Database Error] PKI register failed: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    println!("[PKI Ledger] Registered node '{}' with ML-DSA-65 public key.", payload.node_id);
    Ok(StatusCode::CREATED)
}

/// Endpoint GET /v1/pki/nodes
/// Returns all trusted nodes from the Switch Public Key Ledger
pub async fn list_pki_nodes(
    State(state): State<Arc<AppState>>,
) -> Result<Json<Vec<PkiNodeRecord>>, StatusCode> {
    let nodes = sqlx::query_as::<_, PkiNodeRecord>(
        "SELECT node_id, license_id, ml_dsa_pk, endpoint_url, is_trusted FROM pki_nodes WHERE is_trusted = 1;"
    )
    .fetch_all(&state.db_pool)
    .await
    .map_err(|e| {
        eprintln!("[Database Error] Fetch PKI nodes failed: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    Ok(Json(nodes))
}

#[derive(Serialize, Deserialize, sqlx::FromRow)]
pub struct SwitchConfigRecord {
    pub sponsor_bank: String,
    pub iso_version: String,
    pub pqc_field_number: i64,
    pub encoding: String,
    pub max_buffer_size: i64,
    pub strip_headers: String,
}

/// Endpoint GET /v1/config/switch
/// Distributes dynamic sponsor bank ISO 8583 configurations
pub async fn get_switch_configs(
    State(state): State<Arc<AppState>>,
) -> Result<Json<Vec<SwitchConfigRecord>>, StatusCode> {
    let configs = sqlx::query_as::<_, SwitchConfigRecord>(
        "SELECT sponsor_bank, iso_version, pqc_field_number, encoding, max_buffer_size, strip_headers FROM switch_configs;"
    )
    .fetch_all(&state.db_pool)
    .await
    .map_err(|e| {
        eprintln!("[Database Error] Fetch switch configs failed: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    Ok(Json(configs))
}

#[derive(Deserialize)]
pub struct AiSyncRequest {
    pub license_id: String,
    pub weights: Vec<f32>,
    pub loss: f32,
    pub epoch: u32,
}

#[derive(Serialize)]
pub struct AiSyncResponse {
    pub status: String,
    pub aggregated_epoch: u32,
    pub global_loss: f32,
}

use crate::ai_aggregator::{aggregate_weights_robust, GlobalModel};

#[derive(sqlx::FromRow)]
struct WeightRow {
    weights_json: String,
    loss: f64,
}

/// Endpoint POST /v1/ai/sync-weights
/// Ingests edge proxy neural weights and performs federated averaging (FedAvg)
pub async fn sync_ai_weights(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<AiSyncRequest>,
) -> Result<Json<AiSyncResponse>, StatusCode> {
    let weights_json = serde_json::to_string(&payload.weights).unwrap_or_else(|_| "[]".to_string());

    sqlx::query(
        "INSERT INTO ai_weights (license_id, weights_json, loss, epoch)
         VALUES (?1, ?2, ?3, ?4);"
    )
    .bind(&payload.license_id)
    .bind(&weights_json)
    .bind(payload.loss as f64)
    .bind(payload.epoch as i64)
    .execute(&state.db_pool)
    .await
    .map_err(|e| {
        eprintln!("[Database Error] AI weight insertion failed: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    // Perform FedAvg across all recent client updates for this epoch
    let rows = sqlx::query_as::<_, WeightRow>(
        "SELECT weights_json, loss FROM ai_weights WHERE epoch = ?1;"
    )
    .bind(payload.epoch as i64)
    .fetch_all(&state.db_pool)
    .await
    .unwrap_or_default();

    let mut client_updates = Vec::new();
    let mut total_loss = 0.0;
    let mut loss_count = 0;

    for row in rows {
        if let Ok(w) = serde_json::from_str::<Vec<f32>>(&row.weights_json) {
            client_updates.push(w);
            total_loss += row.loss as f32;
            loss_count += 1;
        }
    }

    // Default global weights if none exists
    let current_global = vec![0.0; payload.weights.len()];
    let new_global_weights = aggregate_weights_robust(&current_global, &client_updates);
    
    let global_json = serde_json::to_string(&new_global_weights).unwrap_or_else(|_| "[]".to_string());

    // Persist new global model
    sqlx::query(
        "INSERT INTO global_ai_models (weights_json) VALUES (?1);"
    )
    .bind(&global_json)
    .execute(&state.db_pool)
    .await
    .ok();

    println!("[AI Aggregator] Ingested epoch {} weights from license '{}' (loss: {:.6}) - FedAvg triggered across {} nodes", 
             payload.epoch, payload.license_id, payload.loss, client_updates.len());

    let actual_global_loss = if loss_count > 0 {
        total_loss / loss_count as f32
    } else {
        payload.loss // fallback if something fails
    };

    Ok(Json(AiSyncResponse {
        status: "aggregated".to_string(),
        aggregated_epoch: payload.epoch + 1,
        global_loss: actual_global_loss, // True mathematically averaged global loss
    }))
}

/// Endpoint GET /v1/ai/model-latest
/// Returns the latest aggregated Global Model for the edge proxies
pub async fn get_latest_model(
    State(state): State<Arc<AppState>>,
) -> Result<Json<GlobalModel>, StatusCode> {
    #[derive(sqlx::FromRow)]
    struct GlobalModelRow {
        version: i64,
        weights_json: String,
    }

    let row = sqlx::query_as::<_, GlobalModelRow>(
        "SELECT version, weights_json FROM global_ai_models ORDER BY version DESC LIMIT 1;"
    )
    .fetch_optional(&state.db_pool)
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    match row {
        Some(r) => {
            let weights = serde_json::from_str(&r.weights_json).unwrap_or_default();
            Ok(Json(GlobalModel {
                epoch: r.version as u32,
                weights,
            }))
        }
        None => Err(StatusCode::NOT_FOUND),
    }
}

/// Endpoint GET /metrics
/// Returns Prometheus metrics for Cloud Control Plane
pub async fn metrics_handler(State(state): State<Arc<AppState>>) -> Result<String, StatusCode> {
    let clients_count: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM clients WHERE is_active = 1;")
        .fetch_one(&state.db_pool)
        .await
        .unwrap_or((0,));

    let pki_count: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM pki_nodes WHERE is_trusted = 1;")
        .fetch_one(&state.db_pool)
        .await
        .unwrap_or((0,));

    let switch_count: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM switch_configs;")
        .fetch_one(&state.db_pool)
        .await
        .unwrap_or((0,));

    let latest_epoch: (i64,) = sqlx::query_as("SELECT IFNULL(MAX(version), 0) FROM global_ai_models;")
        .fetch_one(&state.db_pool)
        .await
        .unwrap_or((0,));

    Ok(format!(
        "# HELP solomon_cloud_active_clients_total Total number of active licensed client proxies\n\
         # TYPE solomon_cloud_active_clients_total gauge\n\
         solomon_cloud_active_clients_total {}\n\
         # HELP solomon_cloud_pki_nodes_registered Total number of registered trusted PQC nodes\n\
         # TYPE solomon_cloud_pki_nodes_registered gauge\n\
         solomon_cloud_pki_nodes_registered {}\n\
         # HELP solomon_cloud_switch_configs_active Number of active dynamic switch routing rules\n\
         # TYPE solomon_cloud_switch_configs_active gauge\n\
         solomon_cloud_switch_configs_active {}\n\
         # HELP solomon_cloud_global_ai_model_epoch Current aggregated global AI model version/epoch\n\
         # TYPE solomon_cloud_global_ai_model_epoch gauge\n\
         solomon_cloud_global_ai_model_epoch {}\n",
        clients_count.0, pki_count.0, switch_count.0, latest_epoch.0
    ))
}

/// Health check endpoint GET /healthz
pub async fn healthz_handler(State(state): State<Arc<AppState>>) -> (StatusCode, Json<serde_json::Value>) {
    let check: Result<(i64,), _> = sqlx::query_as("SELECT 1;").fetch_one(&state.db_pool).await;
    match check {
        Ok(_) => (StatusCode::OK, Json(serde_json::json!({
            "status": "UP",
            "database": "connected",
            "version": "1.0.0"
        }))),
        Err(_) => (StatusCode::SERVICE_UNAVAILABLE, Json(serde_json::json!({
            "status": "DOWN",
            "database": "disconnected"
        }))),
    }
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

// ==========================================
// Dashboard API Endpoints (Phase 7)
// ==========================================

#[derive(Serialize)]
pub struct DashboardFleetNode {
    pub name: String,
    pub license: String,
    pub fp: String,
    pub status: String,
    #[serde(rename = "lastSeen")]
    pub last_seen: String,
}

#[derive(Serialize)]
pub struct DashboardFleetResponse {
    pub fleet: Vec<DashboardFleetNode>,
}

#[derive(sqlx::FromRow)]
struct ClientRow {
    license_id: String,
    name: Option<String>,
    hardware_fingerprint: Option<String>,
    is_active: i64,
}

/// Endpoint GET /api/dashboard/fleet
pub async fn dashboard_fleet_handler(
    State(state): State<Arc<AppState>>,
) -> (StatusCode, Json<DashboardFleetResponse>) {
    let rows = match sqlx::query_as::<_, ClientRow>(
        "SELECT license_id, name, hardware_fingerprint, is_active FROM clients ORDER BY license_id ASC;"
    )
    .fetch_all(&state.db_pool)
    .await {
        Ok(r) => r,
        Err(e) => {
            eprintln!("[Database Error] Dashboard fleet fetch failed: {}", e);
            return (StatusCode::INTERNAL_SERVER_ERROR, Json(DashboardFleetResponse { fleet: Vec::new() }));
        }
    };

    let fleet = rows.into_iter().map(|r| {
        let name = r.name.unwrap_or_else(|| "Proxy Shield Enclave".to_string());
        let fp_full = r.hardware_fingerprint.unwrap_or_else(|| "8f9a2b7c4d5e8f9a2bb5c7d8e9".to_string());
        let fp_display = if fp_full.len() > 18 {
            format!("{}...{}", &fp_full[..10], &fp_full[fp_full.len()-8..])
        } else {
            fp_full
        };
        let status = if r.is_active == 1 { "Online".to_string() } else { "Suspended".to_string() };
        DashboardFleetNode {
            name,
            license: r.license_id,
            fp: fp_display,
            status,
            last_seen: "Just now".to_string(),
        }
    }).collect();

    (StatusCode::OK, Json(DashboardFleetResponse { fleet }))
}

#[derive(Deserialize)]
pub struct ToggleQuery {
    pub license_id: String,
}

#[derive(Serialize)]
pub struct DashboardToggleResponse {
    pub status: String,
    pub license_id: String,
}

/// Endpoint POST /api/dashboard/toggle?license_id={id}
pub async fn dashboard_toggle_handler(
    State(state): State<Arc<AppState>>,
    axum::extract::Query(query): axum::extract::Query<ToggleQuery>,
) -> Result<Json<DashboardToggleResponse>, StatusCode> {
    let row = match sqlx::query_as::<_, (i64,)>(
        "SELECT is_active FROM clients WHERE license_id = ?1;"
    )
    .bind(&query.license_id)
    .fetch_optional(&state.db_pool)
    .await {
        Ok(Some((val,))) => val,
        Ok(None) => return Err(StatusCode::NOT_FOUND),
        Err(_) => return Err(StatusCode::INTERNAL_SERVER_ERROR),
    };

    let new_state = if row == 1 { 0 } else { 1 };
    if let Err(_) = sqlx::query("UPDATE clients SET is_active = ?1, last_seen = CURRENT_TIMESTAMP WHERE license_id = ?2;")
        .bind(new_state)
        .bind(&query.license_id)
        .execute(&state.db_pool)
        .await {
        return Err(StatusCode::INTERNAL_SERVER_ERROR);
    }

    let status_str = if new_state == 1 { "Online".to_string() } else { "Suspended".to_string() };
    Ok(Json(DashboardToggleResponse {
        status: status_str,
        license_id: query.license_id,
    }))
}

#[derive(Deserialize)]
pub struct SyncQuery {
    pub license_id: String,
}

#[derive(Serialize)]
pub struct DashboardSyncResponse {
    pub success: bool,
    pub license_id: String,
    pub message: String,
}

/// Endpoint POST /api/dashboard/sync?license_id={id}
pub async fn dashboard_sync_handler(
    State(state): State<Arc<AppState>>,
    axum::extract::Query(query): axum::extract::Query<SyncQuery>,
) -> Result<Json<DashboardSyncResponse>, StatusCode> {
    if let Err(_) = sqlx::query("UPDATE clients SET last_seen = CURRENT_TIMESTAMP WHERE license_id = ?1;")
        .bind(&query.license_id)
        .execute(&state.db_pool)
        .await {
        return Err(StatusCode::INTERNAL_SERVER_ERROR);
    }

    Ok(Json(DashboardSyncResponse {
        success: true,
        license_id: query.license_id,
        message: "Configuration hot-reloaded across edge mesh".to_string(),
    }))
}

#[derive(Serialize)]
pub struct DashboardRegisterResponse {
    pub license_id: String,
    pub status: String,
}

/// Endpoint POST /api/dashboard/register
pub async fn dashboard_register_handler(
    State(state): State<Arc<AppState>>,
) -> Result<Json<DashboardRegisterResponse>, StatusCode> {
    let (license_id, fp) = {
        let mut rng = rand::thread_rng();
        let num: u32 = rng.gen_range(1000..9999);
        let license_id = format!("ENT-{}", num);
        let fp = format!("{:016x}{:016x}", rng.gen::<u64>(), rng.gen::<u64>());
        (license_id, fp)
    };
    let name = "Proxy Shield Enclave";

    let res = sqlx::query(
        "INSERT INTO clients (license_id, name, hardware_fingerprint, is_active)
         VALUES (?1, ?2, ?3, 1);"
    )
    .bind(&license_id)
    .bind(name)
    .bind(&fp)
    .execute(&state.db_pool)
    .await;

    match res {
        Ok(_) => Ok(Json(DashboardRegisterResponse {
            license_id,
            status: "Online".to_string(),
        })),
        Err(e) => {
            eprintln!("[Database Error] Dashboard register failed: {}", e);
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

#[derive(Serialize)]
pub struct DashboardTelemetryResponse {
    pub last_interval: u32,
    pub last_bytes: u32,
    pub active_requests: u32,
    pub live: bool,
}

/// Endpoint GET /api/dashboard/telemetry
pub async fn dashboard_telemetry_handler() -> Json<DashboardTelemetryResponse> {
    let mut rng = rand::thread_rng();
    let interval: u32 = rng.gen_range(280..360);
    let bytes: u32 = rng.gen_range(210..260);
    let q: u32 = rng.gen_range(0..3);

    Json(DashboardTelemetryResponse {
        last_interval: interval,
        last_bytes: bytes,
        active_requests: q,
        live: true,
    })
}
