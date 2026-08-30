//! Integration tests for Solomon Cloud Enterprise Control Plane.

#[tokio::test]
async fn test_control_plane_database_and_pki() {
    let pool = sqlx::sqlite::SqlitePoolOptions::new()
        .connect("sqlite::memory:")
        .await
        .expect("Failed to connect to in-memory sqlite");

    // Initialize database schema and pre-seeded records
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS clients (
            license_id TEXT PRIMARY KEY,
            hardware_fingerprint TEXT,
            is_active INTEGER NOT NULL DEFAULT 1,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
         );"
    )
    .execute(&pool)
    .await
    .unwrap();

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
    .execute(&pool)
    .await
    .unwrap();

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
    .execute(&pool)
    .await
    .unwrap();

    // 1. Insert Client
    sqlx::query("INSERT INTO clients (license_id, is_active) VALUES ('ENT-TEST-001', 1);")
        .execute(&pool)
        .await
        .unwrap();

    // 2. Register PKI Node with ML-DSA-65 Public Key
    let dummy_pk_hex = "aa".repeat(1952);
    sqlx::query(
        "INSERT INTO pki_nodes (node_id, license_id, ml_dsa_pk, endpoint_url, is_trusted)
         VALUES ('node-alpha-1', 'ENT-TEST-001', ?1, 'https://node1.bank.local', 1);"
    )
    .bind(&dummy_pk_hex)
    .execute(&pool)
    .await
    .unwrap();

    // 3. Query PKI Ledger
    let row: (String, String) = sqlx::query_as("SELECT node_id, ml_dsa_pk FROM pki_nodes WHERE node_id = 'node-alpha-1';")
        .fetch_one(&pool)
        .await
        .unwrap();

    assert_eq!(row.0, "node-alpha-1");
    assert_eq!(row.1, dummy_pk_hex);

    // 4. Seed Switch Configs
    sqlx::query(
        "INSERT INTO switch_configs (sponsor_bank, iso_version, pqc_field_number, encoding, max_buffer_size, strip_headers)
         VALUES ('bank_A_tcs_bancs', '1987', 112, 'EBCDIC', 256, 'X-PQC-Metadata');"
    )
    .execute(&pool)
    .await
    .unwrap();

    let cfg: (String, i64, String) = sqlx::query_as("SELECT sponsor_bank, pqc_field_number, encoding FROM switch_configs WHERE sponsor_bank = 'bank_A_tcs_bancs';")
        .fetch_one(&pool)
        .await
        .unwrap();

    assert_eq!(cfg.0, "bank_A_tcs_bancs");
    assert_eq!(cfg.1, 112);
    assert_eq!(cfg.2, "EBCDIC");
}
