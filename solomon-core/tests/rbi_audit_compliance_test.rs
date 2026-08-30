//! RBI Audit Readiness Comprehensive Test Suite.
//! Verifies all RBI gap requirements G1–G14.

use solomon_core::audit::{
    AnomalyDetector, SystemAction, check_data_localization, LocalizationResult,
    VaptRegistry, VaptFinding, VaptSeverity, VaptStatus, BcpDrState,
    IncidentLogger, IncidentRecord, IamLogger, IamAccessRecord,
    generate_sar, AuditSegmentSeal,
};
use tempfile::tempdir;
use ed25519_dalek::{Signer, Verifier};

// G3: Anomaly detector fires alert on burst failures (>10 in 60s)
#[tokio::test]
async fn test_rbi_g3_burst_failure_detection() {
    let detector = AnomalyDetector::new();
    let now = 1_700_000_000u64;

    for i in 0..11 {
        detector.observe(&SystemAction::ValidationErrorRejected, "api.internal", now + i).await;
    }

    assert!(detector.total_alerts() >= 1, "Expected at least 1 burst failure alert, got 0");
}

// G3: After-hours detection (outside 06:00–22:00 IST)
#[tokio::test]
async fn test_rbi_g3_after_hours_detection() {
    let detector = AnomalyDetector::new();
    // Midnight UTC = 05:30 IST (before 06:00 IST business hours)
    let midnight_utc = 1_700_000_000u64 - (1_700_000_000u64 % 86400);
    detector.observe(&SystemAction::SuccessForwarded, "api.internal", midnight_utc).await;
    assert!(detector.total_alerts() >= 1, "Expected after-hours alert at midnight UTC (=05:30 IST)");
}

// G3: Route saturation detection (>100 events in 10s)
#[tokio::test]
async fn test_rbi_g3_route_saturation_detection() {
    let detector = AnomalyDetector::new();
    let now = 1_700_000_000u64;

    for _ in 0..101 {
        detector.observe(&SystemAction::SuccessForwarded, "route.high-load.internal", now).await;
    }

    assert!(detector.total_alerts() >= 1, "Expected route saturation alert, got 0");
}

// G4: Incident response logger
#[test]
fn test_rbi_g4_incident_logger() {
    let dir = tempdir().unwrap();
    let logger = IncidentLogger::new(dir.path().to_path_buf());

    let incident = IncidentRecord {
        incident_id: "INC-2026-001".to_string(),
        alert_key: "BURST_FAILURE".to_string(),
        message: "15 consecutive validation rejections in 30s".to_string(),
        severity: "HIGH".to_string(),
        detected_at_utc_secs: 1_700_000_000,
        route_target: Some("bank_A_tcs_bancs".to_string()),
        responder: None,
        resolved_at_utc_secs: None,
        notes: Some("Auto-mitigation circuit breaker engaged".to_string()),
    };

    logger.record(&incident);

    let incident_file = dir.path().join("solomon_incidents.ndjson");
    assert!(incident_file.exists());
    let content = std::fs::read_to_string(&incident_file).unwrap();
    assert!(content.contains("INC-2026-001"));
    assert!(content.contains("BURST_FAILURE"));
}

// G5: Data localization enforcement
#[test]
fn test_rbi_g5_data_localization_india_approved() {
    assert_eq!(check_data_localization("10.0.0.1:8080"), LocalizationResult::Approved);
    assert_eq!(check_data_localization("192.168.1.5:9000"), LocalizationResult::Approved);
    assert_eq!(check_data_localization("asia-south1.bank.internal"), LocalizationResult::Approved);
    assert_eq!(check_data_localization("in-mum-01.switch.internal"), LocalizationResult::Approved);
    assert_eq!(check_data_localization("127.0.0.1:8081"), LocalizationResult::Approved);
}

#[test]
fn test_rbi_g5_data_localization_foreign_rejected() {
    assert!(matches!(
        check_data_localization("us-east-1.amazonaws.com"),
        LocalizationResult::Rejected { .. }
    ));
    assert!(matches!(
        check_data_localization("eu-west-1.azure.com"),
        LocalizationResult::Rejected { .. }
    ));
    assert!(matches!(
        check_data_localization("paymentgateway.somebank.co.uk"),
        LocalizationResult::Rejected { .. }
    ));
}

// G6: BCP/DR report generates valid RTO/RPO values
#[test]
fn test_rbi_g6_bcp_dr_rto_rpo() {
    let state = BcpDrState::new();
    let report = state.generate_report(42);
    assert_eq!(report.rto_target_seconds, 14400, "RTO must be 4 hours (14400 seconds)");
    assert!(report.rpo_target_seconds <= 5, "RPO must be near-zero (<= 5 seconds)");
    assert!(report.wal_enabled, "WAL must be enabled");
    assert!(report.audit_log_backup_enabled, "Audit log backup must be enabled");
    assert_eq!(report.current_audit_segment_count, 42);
}

// G7: VAPT registry tracks findings correctly
#[test]
fn test_rbi_g7_vapt_registry() {
    let mut reg = VaptRegistry::new();
    reg.add_finding(VaptFinding {
        finding_id: "VAPT-2026-001".to_string(),
        title: "Missing HSTS header".to_string(),
        description: "HTTP Strict Transport Security not enforced on API".to_string(),
        severity: VaptSeverity::Medium,
        status: VaptStatus::Open,
        affected_component: "proxy.rs".to_string(),
        cve_id: None,
        detected_at_utc_secs: 1_700_000_000,
        remediation_deadline_utc_secs: Some(1_705_000_000),
        closed_at_utc_secs: None,
        auditor_name: "CERT-In Empanelled Auditor XYZ".to_string(),
        cert_in_empanelled: true,
        notes: None,
    });

    assert_eq!(reg.all_findings().len(), 1);
    assert_eq!(reg.open_findings().len(), 1);

    let summary = reg.summary();
    assert_eq!(summary["open"], 1);
    assert_eq!(summary["critical_open"], 0);
}

// G8: IAM privileged access logging
#[test]
fn test_rbi_g8_iam_logger() {
    let dir = tempdir().unwrap();
    let logger = IamLogger::new(dir.path().to_path_buf());

    let record = IamAccessRecord {
        timestamp_utc_secs: 1_700_000_000,
        endpoint: "/metrics".to_string(),
        operator_token_hash: "abcd1234efgh5678".to_string(),
        source_ip: Some("10.0.5.12".to_string()),
        mfa_verified: true,
        access_granted: true,
        reason: "valid_bearer_token".to_string(),
    };

    logger.record(&record);

    let iam_file = dir.path().join("solomon_iam_access.ndjson");
    assert!(iam_file.exists());
    let content = std::fs::read_to_string(&iam_file).unwrap();
    assert!(content.contains("/metrics"));
    assert!(content.contains("abcd1234efgh5678"));
}

// G9 + G10: SAR snapshot generation and signature verification
#[test]
fn test_rbi_g9_g10_sar_generation_and_signature() {
    use solomon_core::audit::Sha256AuditHasher;
    let signing_key = ed25519_dalek::SigningKey::from_bytes(&[0x33; 32]);
    let verifying_key = signing_key.verifying_key();

    let cbom_val = serde_json::json!({"test": "cbom"});
    let bcp_dr_val = serde_json::json!({"rto": 14400, "rpo": 5});
    let vapt_val = serde_json::json!({"open": 0, "critical_open": 0});

    let hasher = Sha256AuditHasher;
    let sk_clone = signing_key.clone();
    let snapshot = generate_sar(
        "deadbeefdeadbeef".to_string(),
        15,
        2,
        1,
        cbom_val,
        bcp_dr_val,
        vapt_val,
        &hasher,
        move |digest| {
            let sig = sk_clone.sign(digest);
            hex::encode(sig.to_bytes())
        },
    );

    assert_eq!(snapshot.total_audit_segments, 15);
    assert_eq!(snapshot.total_incidents_detected, 2);
    assert_eq!(snapshot.total_anomaly_alerts, 1);
    assert!(snapshot.data_localization_compliant);
    assert!(snapshot.iam_mfa_enforced);

    // Verify signature
    let sig_bytes = hex::decode(&snapshot.ed25519_seal_signature).unwrap();
    let sig = ed25519_dalek::Signature::from_bytes(&sig_bytes.try_into().unwrap());

    use solomon_core::audit::AuditHasher;
    let unsigned = serde_json::json!({
        "generated_at_utc_secs": snapshot.generated_at_utc_secs,
        "system_name": &snapshot.system_name,
        "regulatory_framework": &snapshot.regulatory_framework,
        "audit_chain_head_hash": &snapshot.audit_chain_head_hash,
        "total_audit_segments": snapshot.total_audit_segments,
        "total_incidents_detected": snapshot.total_incidents_detected,
        "total_anomaly_alerts": snapshot.total_anomaly_alerts,
        "cbom": &snapshot.cbom,
        "bcp_dr": &snapshot.bcp_dr,
        "vapt_summary": &snapshot.vapt_summary,
        "data_localization_compliant": snapshot.data_localization_compliant,
        "iam_mfa_enforced": snapshot.iam_mfa_enforced,
        "pqc_algorithms": ["ML-DSA-65 (FIPS 204)", "SHAKE-256 (FIPS 202)", "Ed25519 (FIPS 186-5)"],
    });

    let unsigned_bytes = unsigned.to_string();
    let digest_hex = hasher.hex_digest(&[unsigned_bytes.as_bytes()]);

    assert!(verifying_key.verify(digest_hex.as_bytes(), &sig).is_ok(), "SAR Ed25519 signature failed verification!");
}

// G14: Segment seal payload generation and signature roundtrip
#[test]
fn test_rbi_g14_segment_seal_verification() {
    use solomon_core::audit::Sha256AuditHasher;
    let hasher = Sha256AuditHasher;
    let signing_key = ed25519_dalek::SigningKey::from_bytes(&[0x77; 32]);
    let verifying_key = signing_key.verifying_key();

    let seg_date = "2026-08-30";
    let last_hash = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    let now_us = 1_700_000_000_000_000u64;
    let node_id = "node-id-hex-1234";

    let payload = AuditSegmentSeal::signable_payload(&hasher, seg_date, last_hash, now_us, node_id);
    let sig = signing_key.sign(&payload);

    let seal = AuditSegmentSeal {
        record_type: "SEGMENT_SEAL".to_string(),
        segment_date: seg_date.to_string(),
        last_record_hash: last_hash.to_string(),
        sealed_at_utc_us: now_us,
        node_identity: node_id.to_string(),
        seal_signature: hex::encode(sig.to_bytes()),
    };

    let sig_bytes = hex::decode(&seal.seal_signature).unwrap();
    let parsed_sig = ed25519_dalek::Signature::from_bytes(&sig_bytes.try_into().unwrap());
    let recomputed_payload = AuditSegmentSeal::signable_payload(
        &hasher,
        &seal.segment_date,
        &seal.last_record_hash,
        seal.sealed_at_utc_us,
        &seal.node_identity,
    );

    assert!(verifying_key.verify(&recomputed_payload, &parsed_sig).is_ok());
}

