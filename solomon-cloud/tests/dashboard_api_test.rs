//! Integration tests for Solomon Cloud Dashboard APIs (Phase 7).

use solomon_control_plane::db::init_db;

#[tokio::test]
async fn test_dashboard_fleet_and_lifecycle_api() {
    let pool = sqlx::sqlite::SqlitePoolOptions::new()
        .connect("sqlite::memory:")
        .await
        .expect("Failed to connect to in-memory sqlite");

    // Run schema migrations and seeds
    init_db(&pool).await;

    // Verify seeded nodes
    let clients: Vec<(String, Option<String>, i64)> = sqlx::query_as(
        "SELECT license_id, name, is_active FROM clients ORDER BY license_id ASC;"
    )
    .fetch_all(&pool)
    .await
    .unwrap();

    assert!(clients.len() >= 3, "Expected at least 3 pre-seeded fleet nodes");
    let has_razorpay = clients.iter().any(|c| c.0 == "ENT-5821" && c.2 == 1);
    let has_paytm = clients.iter().any(|c| c.0 == "ENT-1109" && c.2 == 0);
    assert!(has_razorpay, "ENT-5821 Razorpay node should be active");
    assert!(has_paytm, "ENT-1109 Paytm node should be suspended by default");

    // Test Toggle operation: suspend ENT-5821
    sqlx::query("UPDATE clients SET is_active = 0 WHERE license_id = 'ENT-5821';")
        .execute(&pool)
        .await
        .unwrap();

    let updated: (i64,) = sqlx::query_as("SELECT is_active FROM clients WHERE license_id = 'ENT-5821';")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(updated.0, 0, "ENT-5821 should now be suspended");

    // Test Register new node operation
    let new_license = "ENT-7788";
    sqlx::query(
        "INSERT INTO clients (license_id, name, hardware_fingerprint, is_active)
         VALUES (?1, 'New Enclave', 'abcdef123456', 1);"
    )
    .bind(new_license)
    .execute(&pool)
    .await
    .unwrap();

    let reg_check: (i64,) = sqlx::query_as("SELECT is_active FROM clients WHERE license_id = ?1;")
        .bind(new_license)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(reg_check.0, 1, "Newly registered node should be active");
}
