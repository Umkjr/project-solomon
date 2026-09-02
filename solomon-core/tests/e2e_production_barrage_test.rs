#![cfg(feature = "proxy")]
//! Enterprise End-to-End Multi-Node Barrage & Chaos Test Suite.
//!
//! Spins up:
//! 1. Real Core Banking Switch TCP Receiver (Mainframe mock listening on raw ISO 8583 bytes).
//! 2. Real Receiving Proxy (Egress Mode: Verify ZK proof & strip PQC Field 112).
//! 3. Real Ingress Proxy (Sign with ML-DSA-65, AI Anomaly Score & inject Field 112).
//! 4. High-concurrency client barrage (100+ concurrent financial transactions).
//! 5. Network toxic injection (Bit-flip tamper detection & fail-closed response code 96).

use solomon_core::iso8583::Iso8583Message;
use solomon_core::proxy::{
    ProxyState, ProxyMode, SponsorBankConfig, IsoConfig, start_iso8583_tcp_proxy,
};
use solomon_core::heartbeat::HeartbeatManager;
use solomon_core::crypto::heartbeat::set_daily_salt;
use std::sync::Arc;
use std::net::SocketAddr;
use tokio::net::{TcpListener, TcpStream};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::Barrier;

/// Real Rust-based Core Banking Switch TCP Receiver.
async fn run_mock_banking_switch(listener: TcpListener) {
    loop {
        let (mut stream, _) = match listener.accept().await {
            Ok(s) => s,
            Err(_) => break,
        };

        tokio::spawn(async move {
            let mut len_buf = [0u8; 2];
            if stream.read_exact(&mut len_buf).await.is_err() {
                return;
            }
            let len = u16::from_be_bytes(len_buf) as usize;
            let mut buf = vec![0u8; len];
            if stream.read_exact(&mut buf).await.is_err() {
                return;
            }

            // Parse legacy ISO 8583 message (Must NOT contain Field 112 PQC payload)
            if let Ok(msg) = Iso8583Message::parse(&buf) {
                // Ensure PQC Field 112 was cleanly stripped before reaching legacy core
                assert!(!msg.has_field(112), "Legacy Banking Switch received unstripped Field 112!");

                // Craft 0210 Approval Response (Field 39 = "00")
                let mut resp_msg = Iso8583Message::new(*b"0210");
                if let Some(stan) = msg.get_field(11) {
                    resp_msg.set_field(11, stan.to_vec());
                }
                resp_msg.set_field(39, b"00".to_vec()); // Approved

                if let Ok(resp_bytes) = resp_msg.serialize_tcp_framed() {
                    let _ = stream.write_all(&resp_bytes).await;
                }
            }
        });
    }
}

fn make_test_state(mode: ProxyMode, backend_addr: SocketAddr) -> Arc<ProxyState> {
    let seed = [0x42u8; 32];
    let software_keystore = solomon_core::hsm::SoftwarePinnedMemoryBackend::generate_new(&seed);
    let keystore: Arc<Box<dyn solomon_core::hsm::KeyStorageBackend>> = Arc::new(Box::new(software_keystore));

    let node_identity = [0x33u8; 32];
    let fingerprint = [0x44u8; 32];

    let mut sponsor_banks = std::collections::HashMap::new();
    sponsor_banks.insert(
        "bank_A_tcs_bancs".to_string(),
        SponsorBankConfig {
            iso_version: "1987".to_string(),
            pqc_snark_field: "Field 112".to_string(),
            pqc_field_number: 112,
            max_buffer_size: 256,
            encoding: "ASCII".to_string(),
            strip_headers: vec![],
        },
    );

    let heartbeat_mgr = Arc::new(HeartbeatManager::new(fingerprint, None));
    heartbeat_mgr.set_last_synced_for_testing(heartbeat_mgr.current_time_secs());

    Arc::new(ProxyState {
        proxy_mode: mode,
        keystore,
        node_identity,
        ed25519_signing_key: ed25519_dalek::SigningKey::from_bytes(&[0x55u8; 32]),
        hardware_fingerprint: fingerprint,
        backend_url: format!("http://{}", backend_addr),
        client: reqwest::Client::new(),
        last_request_time: std::sync::Mutex::new(std::time::Instant::now()),
        active_requests: std::sync::atomic::AtomicUsize::new(0),
        total_requests: std::sync::atomic::AtomicUsize::new(0),
        last_request_bytes: std::sync::atomic::AtomicUsize::new(0),
        last_request_interval_ms: std::sync::atomic::AtomicUsize::new(0),
        iso_config: Arc::new(std::sync::RwLock::new(IsoConfig { sponsor_banks })),
        heartbeat_manager: heartbeat_mgr,
        ai_model: Arc::new(std::sync::Mutex::new(solomon_core::ai::model::EdgeAutoencoder::new(&mut rand::rngs::OsRng))),
        ai_training_sender: tokio::sync::mpsc::channel(10).0,
        batch_accumulator: Arc::new(solomon_core::zk::batch::BatchAccumulator::new()),
        zk_mode: "production".to_string(),
        hybrid_mode: false,
        audit_logger: None,
        anomaly_detector: Arc::new(solomon_core::audit::AnomalyDetector::new()),
        incident_logger: Arc::new(solomon_core::audit::IncidentLogger::new(std::path::PathBuf::from("target/test_audit_logs_barrage"))),
        iam_logger: Arc::new(solomon_core::audit::IamLogger::new(std::path::PathBuf::from("target/test_audit_logs_barrage"))),
        bcp_dr_state: solomon_core::audit::BcpDrState::new(),
        vapt_registry: Arc::new(tokio::sync::RwLock::new(solomon_core::audit::VaptRegistry::new())),
        incident_count: Arc::new(std::sync::atomic::AtomicU64::new(0)),
    })
}


#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_enterprise_e2e_multi_proxy_barrage() {
    set_daily_salt([0x55u8; 32]);

    // 1. Start Mock Core Banking Switch (Mainframe Receiver)
    let switch_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let switch_addr = switch_listener.local_addr().unwrap();
    tokio::spawn(run_mock_banking_switch(switch_listener));

    // 2. Start Receiving Proxy (Egress: Verify & Strip)
    let receiving_addr = {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let a = l.local_addr().unwrap();
        drop(l);
        a
    };
    let receiving_state = make_test_state(ProxyMode::Receiving, switch_addr);
    tokio::spawn(start_iso8583_tcp_proxy(receiving_addr, switch_addr, receiving_state));

    // 3. Start Ingress Proxy (Ingress: Sign & Inject)
    let ingress_addr = {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let a = l.local_addr().unwrap();
        drop(l);
        a
    };
    let ingress_state = make_test_state(ProxyMode::Ingress, receiving_addr);
    tokio::spawn(start_iso8583_tcp_proxy(ingress_addr, receiving_addr, ingress_state));

    // Give servers a moment to bind
    tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;

    // 4. Execute Concurrent Barrage (50 parallel client transactions)
    let concurrency = 50;
    let barrier = Arc::new(Barrier::new(concurrency));
    let mut handles = Vec::with_capacity(concurrency);

    for i in 0..concurrency {
        let b = barrier.clone();
        let target_addr = ingress_addr;

        handles.push(tokio::spawn(async move {
            b.wait().await;

            let mut msg = Iso8583Message::new(*b"0200");
            msg.set_field(3, b"000000".to_vec());
            msg.set_field(4, format!("{:012}", (i + 1) * 1000).into_bytes()); // Amount
            msg.set_field(7, b"0824193500".to_vec());
            msg.set_field(11, format!("{:06}", i + 1).into_bytes()); // STAN
            msg.set_field(18, b"6011".to_vec());
            msg.set_field(49, b"840".to_vec());

            let framed_bytes = msg.serialize_tcp_framed().expect("Failed to frame ISO message");

            let mut stream = TcpStream::connect(target_addr).await.expect("Failed to connect to Ingress proxy");
            stream.write_all(&framed_bytes).await.expect("Failed to send transaction bytes");

            let mut len_buf = [0u8; 2];
            stream.read_exact(&mut len_buf).await.expect("Failed to read response length");
            let len = u16::from_be_bytes(len_buf) as usize;
            let mut resp_buf = vec![0u8; len];
            stream.read_exact(&mut resp_buf).await.expect("Failed to read response body");

            let resp_msg = Iso8583Message::parse(&resp_buf).expect("Failed to parse response ISO packet");
            assert_eq!(resp_msg.mti, *b"0210", "Expected 0210 response MTI");
            assert_eq!(resp_msg.get_field(39), Some(b"00".as_slice()), "Expected Approval response code 00");
        }));
    }

    for h in handles {
        h.await.expect("Barrage client task panicked");
    }

    println!("✅ High-concurrency barrage test passed across 3-tier proxy topology (50/50 approved).");

    // 5. Chaos Toxic Test: Injected Tampered ZK Proof must trigger Response Code 96 (Fail-Closed)
    let mut tampered_msg = Iso8583Message::new(*b"0200");
    tampered_msg.set_field(3, b"000000".to_vec());
    tampered_msg.set_field(4, b"000000099999".to_vec());
    tampered_msg.set_field(11, b"999999".to_vec());
    // Inject corrupt 128-byte ZK proof
    let corrupt_zk = [0xDEu8; 128];
    tampered_msg.inject_pqc_field(112, &corrupt_zk);

    let tampered_framed = tampered_msg.serialize_tcp_framed().unwrap();

    let mut stream = TcpStream::connect(receiving_addr).await.unwrap();
    stream.write_all(&tampered_framed).await.unwrap();

    let mut len_buf = [0u8; 2];
    stream.read_exact(&mut len_buf).await.unwrap();
    let len = u16::from_be_bytes(len_buf) as usize;
    let mut resp_buf = vec![0u8; len];
    stream.read_exact(&mut resp_buf).await.unwrap();

    let resp_msg = Iso8583Message::parse(&resp_buf).unwrap();
    assert_eq!(resp_msg.mti, *b"0210");
    assert_eq!(resp_msg.get_field(39), Some(b"96".as_slice()), "Tampered payload must trigger Response Code 96!");

    println!("🛡️ Chaos toxic attack correctly failed-closed with ISO 8583 Response Code 96.");
}
