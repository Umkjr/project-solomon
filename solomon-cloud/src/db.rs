// control_plane/src/db.rs
use sqlx::{sqlite::SqliteConnectOptions, SqlitePool};
use std::str::FromStr;

/// Establish connection pool to the SQLite database file
pub async fn establish_connection_pool(database_url: &str) -> SqlitePool {
    let opts = SqliteConnectOptions::from_str(database_url)
        .unwrap_or_else(|_| SqliteConnectOptions::new().filename("solomon_control_plane.db"))
        .create_if_missing(true);

    SqlitePool::connect_with(opts)
        .await
        .expect("Failed to connect to SQLite database")
}

/// Initialize SQLite schema and pre-seed active clients for testing
pub async fn init_db(pool: &SqlitePool) {
    // 1. Create clients table
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS clients (
            license_id TEXT PRIMARY KEY,
            hardware_fingerprint TEXT,
            is_active INTEGER NOT NULL DEFAULT 1,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
         );"
    )
    .execute(pool)
    .await
    .expect("Failed to execute clients schema migration");

    // 2. Create PKI ledger table
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS pki_nodes (
            node_id TEXT PRIMARY KEY,
            license_id TEXT NOT NULL,
            ml_dsa_pk TEXT NOT NULL,
            endpoint_url TEXT,
            is_trusted INTEGER NOT NULL DEFAULT 1,
            registered_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (license_id) REFERENCES clients(license_id)
         );"
    )
    .execute(pool)
    .await
    .expect("Failed to execute pki_nodes schema migration");

    // 3. Create Switch Routing Configs table
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS switch_configs (
            sponsor_bank TEXT PRIMARY KEY,
            iso_version TEXT NOT NULL,
            pqc_field_number INTEGER NOT NULL,
            encoding TEXT NOT NULL,
            max_buffer_size INTEGER NOT NULL,
            strip_headers TEXT NOT NULL
         );"
    )
    .execute(pool)
    .await
    .expect("Failed to execute switch_configs schema migration");

    // 4. Create Federated AI Model Weights table
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS ai_weights (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            license_id TEXT NOT NULL,
            weights_json TEXT NOT NULL,
            loss REAL NOT NULL,
            epoch INTEGER NOT NULL,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
         );"
    )
    .execute(pool)
    .await
    .expect("Failed to execute ai_weights schema migration");

    // 4b. Create Global AI Models table (Phase 3)
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS global_ai_models (
            version INTEGER PRIMARY KEY AUTOINCREMENT,
            weights_json TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
         );"
    )
    .execute(pool)
    .await
    .expect("Failed to execute global_ai_models schema migration");

    // 5. Pre-seed default ENT-5821 license and sponsor bank switch configurations
    sqlx::query(
        "INSERT OR IGNORE INTO clients (license_id, hardware_fingerprint, is_active)
         VALUES ('ENT-5821', NULL, 1);"
    )
    .execute(pool)
    .await
    .expect("Failed to seed default active license in SQLite db");

    sqlx::query(
        "INSERT OR IGNORE INTO switch_configs (sponsor_bank, iso_version, pqc_field_number, encoding, max_buffer_size, strip_headers)
         VALUES 
         ('bank_A_tcs_bancs', '1987', 112, 'EBCDIC', 256, 'X-PQC-Metadata,Fintech-Telemetry'),
         ('bank_B_finacle', '1993', 123, 'ASCII', 150, 'X-Signature-Raw');"
    )
    .execute(pool)
    .await
    .expect("Failed to seed switch configs");

    println!("[Database] Migration successfully applied. Pre-seeded license 'ENT-5821' and switch configurations active.");
}
