#![cfg(feature = "proxy")]
//! Tests for Dual-Mode Ingress (Sign & Inject) and Egress / Receiving (Verify & Strip) Proxy Architecture.

use solomon_core::iso8583::Iso8583Message;
use solomon_core::proxy::{
    ProxyState, ProxyMode, ZkAuthorizationProof, IsoConfig, process_receiving_iso8583_message,
};
use solomon_core::heartbeat::HeartbeatManager;
use std::sync::Arc;

fn create_test_proxy_state(mode: ProxyMode) -> ProxyState {
    let seed = [0x11u8; 32];
    let software_keystore = solomon_core::hsm::SoftwarePinnedMemoryBackend::generate_new(&seed);
    let keystore: Arc<Box<dyn solomon_core::hsm::KeyStorageBackend>> = Arc::new(Box::new(software_keystore));

    let node_identity = [0x33u8; 32];
    let fingerprint = [0x44u8; 32];

    let mut sponsor_banks = std::collections::HashMap::new();
    sponsor_banks.insert(
        "test_bank".to_string(),
        solomon_core::proxy::SponsorBankConfig {
            iso_version: "1987".to_string(),
            pqc_snark_field: "Field 112".to_string(),
            pqc_field_number: 112,
            max_buffer_size: 4096,
            encoding: "ASCII".to_string(),
            strip_headers: vec![],
        },
    );

    let heartbeat_mgr = Arc::new(HeartbeatManager::new(fingerprint, None));
    heartbeat_mgr.set_last_synced_for_testing(heartbeat_mgr.current_time_secs());

    ProxyState {
        proxy_mode: mode,
        keystore,
        node_identity,
        ed25519_signing_key: ed25519_dalek::SigningKey::from_bytes(&[0x55u8; 32]),
        hardware_fingerprint: fingerprint,
        backend_url: "http://127.0.0.1:8081".to_string(),
        client: reqwest::Client::new(),
        last_request_time: std::sync::Mutex::new(std::time::Instant::now()),
        active_requests: std::sync::atomic::AtomicUsize::new(0),
        total_requests: std::sync::atomic::AtomicUsize::new(0),
        last_request_bytes: std::sync::atomic::AtomicUsize::new(0),
        last_request_interval_ms: std::sync::atomic::AtomicUsize::new(0),
        iso_config: Arc::new(std::sync::RwLock::new(IsoConfig { sponsor_banks })),
        heartbeat_manager: heartbeat_mgr,
        ai_model: Arc::new(std::sync::Mutex::new(solomon_core::ai::model::EdgeAutoencoder::new(&mut rand::rngs::OsRng))),
        batch_accumulator: Arc::new(solomon_core::zk::batch::BatchAccumulator::new()),
        zk_mode: "production".to_string(),
        hybrid_mode: false,
        audit_logger: None,
        anomaly_detector: Arc::new(solomon_core::audit::AnomalyDetector::new()),
        incident_logger: Arc::new(solomon_core::audit::IncidentLogger::new(std::path::PathBuf::from("target/test_audit_logs_recv"))),
        iam_logger: Arc::new(solomon_core::audit::IamLogger::new(std::path::PathBuf::from("target/test_audit_logs_recv"))),
        bcp_dr_state: solomon_core::audit::BcpDrState::new(),
        vapt_registry: Arc::new(tokio::sync::RwLock::new(solomon_core::audit::VaptRegistry::new())),
        incident_count: Arc::new(std::sync::atomic::AtomicU64::new(0)),
    }
}


#[test]
fn test_ingress_and_receiving_proxy_roundtrip() {
    let ingress_state = create_test_proxy_state(ProxyMode::Ingress);
    let receiving_state = create_test_proxy_state(ProxyMode::Receiving);

    // 1. Construct Original Legacy Financial Request (0200) from ATM/POS
    let mut original_msg = Iso8583Message::new(*b"0200");
    original_msg.set_field(2, b"4111111111111111".to_vec());  // PAN
    original_msg.set_field(3, b"000000".to_vec());            // Purchase
    original_msg.set_field(4, b"000000025000".to_vec());      // $250.00
    original_msg.set_field(11, b"102938".to_vec());           // STAN
    original_msg.set_field(41, b"ATM99001".to_vec());         // Terminal ID

    let original_bytes = original_msg.serialize();

    // 2. Ingress Proxy: Sign & Generate ZK Authorization Proof
    let signature = ingress_state.keystore.sign_payload(&original_bytes).unwrap();
    let sig_hash = {
        let mut sponge = solomon_core::crypto::shake::KeccakSponge::new_shake256();
        sponge.absorb(&signature);
        let mut hash = [0u8; 32];
        sponge.squeeze(&mut hash);
        hash
    };
    let zk_proof = ZkAuthorizationProof::generate(
        &ingress_state.node_identity,
        &ingress_state.hardware_fingerprint,
        &sig_hash,
    );

    // Pack compound proof + signature into Field 112 (National Data slot for TCS BaNCS)
    let mut proof_payload = Vec::with_capacity(128 + 3309);
    proof_payload.extend_from_slice(&zk_proof.identity_commitment);
    proof_payload.extend_from_slice(&zk_proof.attestation_hash);
    proof_payload.extend_from_slice(&zk_proof.state_commitment);
    proof_payload.extend_from_slice(&zk_proof.proof_elements);
    proof_payload.extend_from_slice(&signature);

    let mut enriched_msg = original_msg.clone();
    enriched_msg.inject_pqc_field(112, &proof_payload);

    assert!(enriched_msg.has_field(112));
    let enriched_wire_bytes = enriched_msg.serialize();

    // 3. Receiving Proxy: Verify & Strip Logic
    let clean_wire_bytes = process_receiving_iso8583_message(&enriched_wire_bytes, &receiving_state)
        .expect("Receiving proxy failed to verify and strip PQC field");

    // 4. Verify clean message matches original format and content exactly
    let clean_parsed = Iso8583Message::parse(&clean_wire_bytes).expect("Failed to parse clean message");
    assert_eq!(clean_parsed.mti, *b"0200");
    assert_eq!(clean_parsed.get_field_str(2), Some("4111111111111111"));
    assert_eq!(clean_parsed.get_field_str(3), Some("000000"));
    assert_eq!(clean_parsed.get_field_str(4), Some("000000025000"));
    assert_eq!(clean_parsed.get_field_str(11), Some("102938"));
    assert_eq!(clean_parsed.get_field_str(41), Some("ATM99001"));
    assert!(!clean_parsed.has_field(112)); // Field 112 must be stripped!

    assert_eq!(clean_wire_bytes, original_bytes);
}

#[test]
fn test_receiving_proxy_tamper_detection_fail_closed() {
    let ingress_state = create_test_proxy_state(ProxyMode::Ingress);
    let receiving_state = create_test_proxy_state(ProxyMode::Receiving);

    let mut msg = Iso8583Message::new(*b"0200");
    msg.set_field(2, b"4111111111111111".to_vec());
    msg.set_field(4, b"000000050000".to_vec());
    let original_bytes = msg.serialize();

    let signature = ingress_state.keystore.sign_payload(&original_bytes).unwrap();
    let sig_hash = {
        let mut sponge = solomon_core::crypto::shake::KeccakSponge::new_shake256();
        sponge.absorb(&signature);
        let mut hash = [0u8; 32];
        sponge.squeeze(&mut hash);
        hash
    };
    let zk_proof = ZkAuthorizationProof::generate(
        &ingress_state.node_identity,
        &ingress_state.hardware_fingerprint,
        &sig_hash,
    );

    let mut proof_payload = Vec::with_capacity(128 + 3309);
    proof_payload.extend_from_slice(&zk_proof.identity_commitment);
    proof_payload.extend_from_slice(&zk_proof.attestation_hash);
    proof_payload.extend_from_slice(&zk_proof.state_commitment);
    proof_payload.extend_from_slice(&zk_proof.proof_elements);
    proof_payload.extend_from_slice(&signature);

    // Tamper with proof elements
    proof_payload[100] ^= 0xFF;

    msg.inject_pqc_field(112, &proof_payload);
    let tampered_wire_bytes = msg.serialize();

    // Receiving proxy MUST detect tamper and reject frame fail-closed
    let result = process_receiving_iso8583_message(&tampered_wire_bytes, &receiving_state);
    assert!(result.is_err());
}
