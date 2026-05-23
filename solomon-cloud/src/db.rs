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

    // 2. Pre-seed default ENT-5821 license for local E2E simulation (Trust-On-First-Use)
    sqlx::query(
        "INSERT OR IGNORE INTO clients (license_id, hardware_fingerprint, is_active)
         VALUES ('ENT-5821', NULL, 1);"
    )
    .execute(pool)
    .await
    .expect("Failed to seed default active license in SQLite db");

    println!("[Database] Migration successfully applied. Pre-seeded license 'ENT-5821' active.");
}
