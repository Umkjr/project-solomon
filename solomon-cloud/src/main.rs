// control_plane/src/main.rs
use axum::{
    routing::{get, post},
    Router,
};
use std::net::SocketAddr;
use std::sync::Arc;
use tower_http::trace::TraceLayer;

mod api;
mod crypto;
pub mod db;
pub mod ai_aggregator;

#[tokio::main]
async fn main() {
    println!("☁️ Starting Solomon Cloud Control Plane (Phase 4)...");

    // 1. Establish SQLite Connection Pool and run migration/seeding
    let database_url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "sqlite:solomon_control_plane.db".to_string());
    
    let db_pool = db::establish_connection_pool(&database_url).await;
    db::init_db(&db_pool).await;

    // 2. Initialize Master Ed25519 signer
    let signer = crypto::MasterSigner::load_or_init();

    // 3. Setup Shared App State
    let app_state = Arc::new(api::AppState { db_pool, signer });

    // 4. Assemble Axum Router with Trace Telemetry
    let app = Router::new()
        // Phase 4 base64 licensing schema route
        .route("/v1/epoch", post(api::verify_handshake))
        // Proxy client hex-encoded Keccak Epoch Token route
        .route("/licensing", post(api::verify_licensing))
        // Phase 2 Enterprise PKI Ledger routes
        .route("/v1/pki/register", post(api::register_pki_node))
        .route("/v1/pki/nodes", axum::routing::get(api::list_pki_nodes))
        // Phase 2 Dynamic Switch Configuration route
        .route("/v1/config/switch", get(api::get_switch_configs))
        // Phase 2 Federated AI Weight Aggregator route
        .route("/v1/ai/sync-weights", post(api::sync_ai_weights))
        .route("/v1/ai/model-latest", get(api::get_latest_model))
        // Observability and Health Probes
        .route("/metrics", get(api::metrics_handler))
        .route("/healthz", get(api::healthz_handler))
        .layer(TraceLayer::new_for_http())
        .with_state(app_state);

    // 5. Bind Server to network interface
    let port = std::env::var("CONTROL_PLANE_PORT")
        .or_else(|_| std::env::var("PORT"))
        .unwrap_or_else(|_| "9000".to_string())
        .parse::<u16>()
        .unwrap_or(9000);
    
    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .expect("Failed to bind TcpListener for Control Plane");

    println!("[Control Plane] Solomon Cloud Control Plane active and listening on {}", addr);
    axum::serve(listener, app)
        .await
        .expect("Failed to run Axum web server");
}
