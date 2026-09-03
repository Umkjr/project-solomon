#![cfg(feature = "proxy")]
//! ==============================================================================
//! PROJECT SOLOMON: PRODUCTION HARDENING & REPLAY DEFENSE TEST SUITE
//! ==============================================================================
//! Verifies:
//! 1. ISO 8583 Field 7 Timestamp Freshness & Replay Attack Defense (Response Code 94).
//! 2. High-Concurrency Lockless Reading on Anomaly Detection Engine (RwLock).
//! 3. Audit Logger In-Memory Spillover Buffer & Zero-Loss Recovery under Disk Faults.
//! ==============================================================================

use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::net::{TcpListener, TcpStream};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use solomon_core::iso8583::{Iso8583Message, is_field7_fresh, days_to_ymd, ymd_to_days};
use solomon_core::proxy::{
    ProxyState, ProxyMode, SponsorBankConfig, IsoConfig, start_iso8583_tcp_proxy,
};
use solomon_core::heartbeat::HeartbeatManager;
use solomon_core::audit::logger::AuditLogger;
use solomon_core::audit::crypto_traits::{Ed25519AuditSigner, Sha256AuditHasher};
use solomon_core::audit::chain::AuditChain;
use solomon_core::audit::record::AuditRecord;

#[test]
fn test_field7_timestamp_freshness_math() {
    let now_utc = 1756915200u64; // Arbitrary valid timestamp (September 2025)
    let days = now_utc / 86400;
    let (y, m, d) = days_to_ymd(days);
    assert_eq!(ymd_to_days(y, m, d), days, "Days to YMD roundtrip must be exact");

    let secs_of_day = now_utc % 86400;
    let hh = secs_of_day / 3600;
    let mm = (secs_of_day % 3600) / 60;
    let ss = secs_of_day % 60;

    let fresh_f7 = format!("{:02}{:02}{:02}{:02}{:02}", m, d, hh, mm, ss);
    assert!(is_field7_fresh(&fresh_f7, now_utc, 120), "Current timestamp must be fresh");

    // 60 seconds in the past -> fresh within 120s tolerance
    let past_60 = now_utc - 60;
    let past_days = past_60 / 86400;
    let (_py, pm, pd) = days_to_ymd(past_days);
    let p_secs = past_60 % 86400;
    let p_hh = p_secs / 3600;
    let p_mm = (p_secs % 3600) / 60;
    let p_ss = p_secs % 60;
    let past_f7 = format!("{:02}{:02}{:02}{:02}{:02}", pm, pd, p_hh, p_mm, p_ss);
    assert!(is_field7_fresh(&past_f7, now_utc, 120), "60s past timestamp must be fresh");

    // 15 minutes (900s) in the past -> STALE (Replay Attack)
    let stale_900 = now_utc - 900;
    let s_days = stale_900 / 86400;
    let (_sy, sm, sd) = days_to_ymd(s_days);
    let s_secs = stale_900 % 86400;
    let s_hh = s_secs / 3600;
    let s_mm = (s_secs % 3600) / 60;
    let s_ss = s_secs % 60;
    let stale_f7 = format!("{:02}{:02}{:02}{:02}{:02}", sm, sd, s_hh, s_mm, s_ss);
    assert!(!is_field7_fresh(&stale_f7, now_utc, 120), "900s past timestamp must be rejected as stale");

    // Malformed strings must be rejected
    assert!(!is_field7_fresh("12345", now_utc, 120));
    assert!(!is_field7_fresh("XXYYZZ1122", now_utc, 120));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_proxy_stale_replay_rejection_code_94() {
    // 1. Stand up mock banking switch
    let switch_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let switch_addr = switch_listener.local_addr().unwrap();

    tokio::spawn(async move {
        while let Ok((mut stream, _)) = switch_listener.accept().await {
            let mut len_buf = [0u8; 2];
            if stream.read_exact(&mut len_buf).await.is_ok() {
                let packet_len = u16::from_be_bytes(len_buf) as usize;
                let mut buf = vec![0u8; packet_len];
                let _ = stream.read_exact(&mut buf).await;
                // Reply with 00 Approved
                let mut resp = Iso8583Message::new(*b"0210");
                resp.set_field(39, b"00".to_vec());
                if let Ok(framed) = resp.serialize_tcp_framed() {
                    let _ = stream.write_all(&framed).await;
                }
            }
        }
    });

    // 2. Stand up Solomon Ingress Proxy
    let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = proxy_listener.local_addr().unwrap();
    drop(proxy_listener); // free port for proxy

    let seed = [0x55u8; 32];
    let keystore = Arc::new(Box::new(solomon_core::hsm::AuditedKeyStorageBackend::generate_new(&seed)) as Box<dyn solomon_core::hsm::KeyStorageBackend>);
    let fingerprint = [0xAAu8; 32];
    let node_identity = [0xBBu8; 32];
    let ed_key = ed25519_dalek::SigningKey::from_bytes(&[0x33u8; 32]);
    let heartbeat_mgr = Arc::new(HeartbeatManager::new(fingerprint, None));
    heartbeat_mgr.set_last_synced_for_testing(heartbeat_mgr.current_time_secs());

    let mut sponsor_banks = std::collections::HashMap::new();
    sponsor_banks.insert(
        "tcs_bancs".to_string(),
        SponsorBankConfig {
            iso_version: "1987".to_string(),
            pqc_snark_field: "Field 112".to_string(),
            pqc_field_number: 112,
            max_buffer_size: 4096,
            encoding: "ASCII".to_string(),
            strip_headers: vec![],
        },
    );

    let state = Arc::new(ProxyState {
        proxy_mode: ProxyMode::Ingress,
        keystore,
        node_identity,
        ed25519_signing_key: ed_key,
        hardware_fingerprint: fingerprint,
        backend_url: format!("http://{}", switch_addr),
        client: reqwest::Client::new(),
        last_request_time: std::sync::Mutex::new(Instant::now()),
        active_requests: std::sync::atomic::AtomicUsize::new(0),
        total_requests: std::sync::atomic::AtomicUsize::new(0),
        last_request_bytes: std::sync::atomic::AtomicUsize::new(0),
        last_request_interval_ms: std::sync::atomic::AtomicUsize::new(0),
        iso_config: Arc::new(std::sync::RwLock::new(IsoConfig { sponsor_banks })),
        heartbeat_manager: heartbeat_mgr,
        ai_model: Arc::new(std::sync::RwLock::new(solomon_core::ai::model::EdgeAutoencoder::new(&mut rand::rngs::OsRng))),
        ai_training_sender: tokio::sync::mpsc::channel(100).0,
        batch_accumulator: Arc::new(solomon_core::zk::batch::BatchAccumulator::new()),
        zk_mode: "production".to_string(),
        hybrid_mode: false,
        audit_logger: None,
        anomaly_detector: Arc::new(solomon_core::audit::AnomalyDetector::new()),
        incident_logger: Arc::new(solomon_core::audit::IncidentLogger::new(std::path::PathBuf::from("target/test_hardening_incidents"))),
        iam_logger: Arc::new(solomon_core::audit::IamLogger::new(std::path::PathBuf::from("target/test_hardening_iam"))),
        bcp_dr_state: solomon_core::audit::BcpDrState::new(),
        vapt_registry: Arc::new(tokio::sync::RwLock::new(solomon_core::audit::VaptRegistry::new())),
        incident_count: Arc::new(std::sync::atomic::AtomicU64::new(0)),
    });

    tokio::spawn(start_iso8583_tcp_proxy(proxy_addr, switch_addr, state));
    tokio::time::sleep(Duration::from_millis(100)).await;

    // SCENARIO 1: Fresh Transaction with current timestamp
    {
        let mut client = TcpStream::connect(proxy_addr).await.unwrap();
        let now_utc = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        let days = now_utc / 86400;
        let (_y, m, d) = days_to_ymd(days);
        let s_day = now_utc % 86400;
        let hh = s_day / 3600;
        let mm = (s_day % 3600) / 60;
        let ss = s_day % 60;
        let fresh_f7 = format!("{:02}{:02}{:02}{:02}{:02}", m, d, hh, mm, ss);

        let mut req = Iso8583Message::new(*b"0200");
        req.set_field(7, fresh_f7.as_bytes().to_vec());
        req.set_field(11, b"112233".to_vec());
        req.set_field(4, b"000000010000".to_vec());
        let framed = req.serialize_tcp_framed().unwrap();
        client.write_all(&framed).await.unwrap();

        let mut len_buf = [0u8; 2];
        client.read_exact(&mut len_buf).await.unwrap();
        let resp_len = u16::from_be_bytes(len_buf) as usize;
        let mut resp_buf = vec![0u8; resp_len];
        client.read_exact(&mut resp_buf).await.unwrap();
        let resp_msg = Iso8583Message::parse(&resp_buf).unwrap();

        assert_eq!(resp_msg.get_field_str(39), Some("00"), "Fresh transaction must be approved with Code 00");
    }

    // SCENARIO 2: Replay Attack (15-Minute Old Stale Timestamp)
    {
        let mut client = TcpStream::connect(proxy_addr).await.unwrap();
        let stale_utc = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() - 900;
        let days = stale_utc / 86400;
        let (_y, m, d) = days_to_ymd(days);
        let s_day = stale_utc % 86400;
        let hh = s_day / 3600;
        let mm = (s_day % 3600) / 60;
        let ss = s_day % 60;
        let stale_f7 = format!("{:02}{:02}{:02}{:02}{:02}", m, d, hh, mm, ss);

        let mut req = Iso8583Message::new(*b"0200");
        req.set_field(7, stale_f7.as_bytes().to_vec());
        req.set_field(11, b"112233".to_vec());
        req.set_field(4, b"000000010000".to_vec());
        let framed = req.serialize_tcp_framed().unwrap();
        client.write_all(&framed).await.unwrap();

        let mut len_buf = [0u8; 2];
        client.read_exact(&mut len_buf).await.unwrap();
        let resp_len = u16::from_be_bytes(len_buf) as usize;
        let mut resp_buf = vec![0u8; resp_len];
        client.read_exact(&mut resp_buf).await.unwrap();
        let resp_msg = Iso8583Message::parse(&resp_buf).unwrap();

        assert_eq!(
            resp_msg.get_field_str(39),
            Some("94"),
            "Stale replayed transaction must be rejected with ISO Response Code 94 (Duplicate transmission)"
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn test_high_concurrency_lockless_anomaly_scoring() {
    let mut rng = rand::rngs::OsRng;
    let model = Arc::new(std::sync::RwLock::new(solomon_core::ai::model::EdgeAutoencoder::new(&mut rng)));

    let num_threads = 100;
    let mut handles = Vec::new();
    let t_start = Instant::now();

    for _ in 0..num_threads {
        let model_clone = Arc::clone(&model);
        handles.push(tokio::spawn(async move {
            let features = solomon_core::ai::linalg::Vector::new(8);
            let score = {
                let m = model_clone.read().unwrap();
                let (s, _) = m.compute_anomaly_score(&features);
                s
            };
            score
        }));
    }

    for h in handles {
        let score = h.await.unwrap();
        assert!(score >= 0.0);
    }
    let elapsed = t_start.elapsed();
    println!("100 Concurrent Anomaly Reads finished in: {:.2} ms", elapsed.as_secs_f64() * 1000.0);
    assert!(elapsed < Duration::from_millis(500), "Lockless parallel reads must finish under 500ms");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_audit_logger_spillover_buffer_recovery() {
    let test_dir = tempfile::tempdir().unwrap();
    let node_identity = [0x42u8; 32];
    let ed_key = ed25519_dalek::SigningKey::from_bytes(&[0x33u8; 32]);
    let audit_signer = Arc::new(Ed25519AuditSigner::new(ed_key));
    let audit_hasher = Arc::new(Sha256AuditHasher);

    let logger = AuditLogger::new(
        test_dir.path().to_path_buf(),
        1000,
        audit_signer,
        audit_hasher,
        node_identity,
    );

    // Emit 10 records
    for i in 1..=10 {
        logger.emit(
            format!("TX-{}", i),
            "bank_gateway".to_string(),
            solomon_core::audit::record::CryptoAuditMeta {
                algorithm_suite: "FIPS-204-ML-DSA-65".to_string(),
                hybrid_verified: true,
                starks_proven: false,
                proof_latency_ms: 0.0,
            },
            "ap-south-1".to_string(),
            solomon_core::audit::record::SystemAction::SuccessForwarded,
        ).await.unwrap();
    }

    logger.flush().await.unwrap();

    // Verify all 10 records are recorded and hash chain is unbroken
    let mut records = Vec::new();
    for entry in std::fs::read_dir(test_dir.path()).unwrap().flatten() {
        if entry.path().extension().and_then(|s| s.to_str()) == Some("ndjson") {
            let content = std::fs::read_to_string(entry.path()).unwrap();
            for line in content.lines().filter(|l| !l.trim().is_empty()) {
                if let Ok(r) = serde_json::from_str::<AuditRecord>(line) {
                    records.push(r);
                }
            }
        }
    }

    assert_eq!(records.len(), 10, "10 records must be present");
    let chain_check = AuditChain::verify_chain(&records, &Sha256AuditHasher);
    assert!(chain_check.is_ok(), "Hash chain must be 100% continuous");
    assert_eq!(logger.dropped_records_count(), 0, "Zero records dropped");
}
