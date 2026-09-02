use solomon_core::audit::{
    AuditLogger, AuditChain, CryptoAuditMeta, SystemAction,
    Sha256AuditHasher, Shake256AuditHasher, Ed25519AuditSigner
};
use std::sync::Arc;
use tempfile::tempdir;

#[tokio::test]
async fn test_audit_hash_chain_and_tamper_detection() {
    let dir = tempdir().unwrap();
    let signing_key = ed25519_dalek::SigningKey::from_bytes(&[0x42; 32]);
    let node_identity = [0x5A; 32];
    let signer = Arc::new(Ed25519AuditSigner::new(signing_key));
    let hasher = Arc::new(Sha256AuditHasher);
    let logger = AuditLogger::new(dir.path().to_path_buf(), 1000, signer, hasher.clone(), node_identity);

    let mut records = Vec::new();

    // 1. Emit 50 valid transactions
    for i in 0..50 {
        let meta = CryptoAuditMeta {
            algorithm_suite: "ML-DSA-65 + Ed25519".to_string(),
            hybrid_verified: true,
            starks_proven: true,
            proof_latency_ms: 0.841,
        };

        let record = logger.emit(
            format!("tx-uuid-{}", i),
            format!("api.gateway-{}.internal", i % 3),
            meta,
            "IN-MUM-01".to_string(),
            SystemAction::SuccessForwarded,
        ).await.unwrap();

        records.push(record);
    }

    logger.flush().await.unwrap();

    // 2. Verify pristine chain
    let pristine_verification = AuditChain::verify_chain(&records, hasher.as_ref());
    assert!(pristine_verification.is_ok(), "Pristine audit chain failed verification: {:?}", pristine_verification.err());

    // 3. Test Field Mutation Tamper Detection (Modify timestamp of record #25)
    let mut tampered_records = records.clone();
    tampered_records[25].timestamp_utc += 99999;
    
    let mutation_result = AuditChain::verify_chain(&tampered_records, hasher.as_ref());
    assert!(matches!(mutation_result, Err(solomon_core::audit::AuditChainError::RecordHashMismatch { index: 25, .. })),
        "Expected hash mismatch at index 25, got: {:?}", mutation_result);

    // 4. Test Broken Link Tamper Detection (Swap previous_hash pointer)
    let mut broken_records = records.clone();
    broken_records[10].previous_hash = "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef".to_string();

    let broken_result = AuditChain::verify_chain(&broken_records, hasher.as_ref());
    assert!(matches!(broken_result, Err(solomon_core::audit::AuditChainError::BrokenPreviousHash { index: 10, .. })),
        "Expected broken previous hash at index 10, got: {:?}", broken_result);

    // 5. Test Record Deletion Detection
    let mut deleted_records = records.clone();
    deleted_records.remove(15);

    let deletion_result = AuditChain::verify_chain(&deleted_records, hasher.as_ref());
    assert!(deletion_result.is_err(), "Expected audit chain verification to fail upon record deletion");
}

#[tokio::test]
async fn test_algorithm_agnosticism_shake256_audit_chain() {
    let dir = tempdir().unwrap();
    let signing_key = ed25519_dalek::SigningKey::from_bytes(&[0x99; 32]);
    let node_identity = [0xAA; 32];
    let signer = Arc::new(Ed25519AuditSigner::new(signing_key));
    let shake_hasher = Arc::new(Shake256AuditHasher);
    let logger = AuditLogger::new(dir.path().to_path_buf(), 100, signer, shake_hasher.clone(), node_identity);

    let mut records = Vec::new();
    for i in 0..10 {
        let meta = CryptoAuditMeta {
            algorithm_suite: "ML-DSA-65 (SHAKE-256)".to_string(),
            hybrid_verified: false,
            starks_proven: true,
            proof_latency_ms: 0.55,
        };

        let record = logger.emit(
            format!("tx-shake-{}", i),
            "asia-south1.switch.internal".to_string(),
            meta,
            "IN-MUM-01".to_string(),
            SystemAction::SuccessForwarded,
        ).await.unwrap();

        records.push(record);
    }

    logger.flush().await.unwrap();

    let verification = AuditChain::verify_chain(&records, shake_hasher.as_ref());
    assert!(verification.is_ok(), "SHAKE-256 audit chain verification failed: {:?}", verification.err());
}

#[tokio::test]
async fn test_audit_chain_continuity_across_reboots() {
    let dir = tempdir().unwrap();
    let signing_key = ed25519_dalek::SigningKey::from_bytes(&[0x77; 32]);
    let node_identity = [0xBB; 32];
    let signer = Arc::new(Ed25519AuditSigner::new(signing_key));
    let hasher = Arc::new(Sha256AuditHasher);

    let mut combined_records = Vec::new();

    // Session 1: Node boots, processes 10 transactions, shuts down
    {
        let logger1 = AuditLogger::new(
            dir.path().to_path_buf(),
            100,
            signer.clone(),
            hasher.clone(),
            node_identity,
        );

        for i in 0..10 {
            let meta = CryptoAuditMeta {
                algorithm_suite: "ML-DSA-65".to_string(),
                hybrid_verified: true,
                starks_proven: false,
                proof_latency_ms: 0.45,
            };
            let rec = logger1.emit(
                format!("session1-tx-{}", i),
                "in-mum-01.switch.internal".to_string(),
                meta,
                "IN-MUM-01".to_string(),
                SystemAction::SuccessForwarded,
            ).await.unwrap();
            combined_records.push(rec);
        }
        logger1.flush().await.unwrap();
    } // logger1 dropped

    // Session 2: Node reboots in the exact same directory, recovers last hash from disk
    {
        let logger2 = AuditLogger::new(
            dir.path().to_path_buf(),
            100,
            signer.clone(),
            hasher.clone(),
            node_identity,
        );

        for i in 10..20 {
            let meta = CryptoAuditMeta {
                algorithm_suite: "ML-DSA-65".to_string(),
                hybrid_verified: true,
                starks_proven: false,
                proof_latency_ms: 0.45,
            };
            let rec = logger2.emit(
                format!("session2-tx-{}", i),
                "in-mum-01.switch.internal".to_string(),
                meta,
                "IN-MUM-01".to_string(),
                SystemAction::SuccessForwarded,
            ).await.unwrap();
            combined_records.push(rec);
        }
        logger2.flush().await.unwrap();
    }

    assert_eq!(combined_records.len(), 20);

    // Verify unbroken chain from record 0 to 19 across the reboot boundary
    let chain_check = AuditChain::verify_chain(&combined_records, hasher.as_ref());
    assert!(
        chain_check.is_ok(),
        "Audit chain must remain unbroken across node reboots: {:?}",
        chain_check.err()
    );

    // Check specific linkage across the boundary: record 10's previous_hash must equal record 9's current_hash
    assert_eq!(
        combined_records[10].previous_hash,
        combined_records[9].current_hash,
        "Record #10 previous_hash must perfectly link to Record #9 current_hash"
    );
}

