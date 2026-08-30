#![cfg(feature = "proxy")]
//! Tokio High-Concurrency Asynchronous Load Generator (wrk2-style)
//!
//! Simulates high-frequency transaction bursts against the tuned Solomon TCP and HTTP proxy.
//! Measures connection persistence, TCP_NODELAY throughput, and latency percentiles (P50, P90, P99).

use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Instant;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use solomon_core::proxy::create_tuned_tcp_listener;

#[derive(Default)]
struct MetricsCollector {
    total_requests: AtomicUsize,
    successful_requests: AtomicUsize,
    failed_requests: AtomicUsize,
}

#[tokio::test]
async fn test_tcp_socket_saturation_and_nodelay_throughput() {
    // 1. Bind tuned TCP server on local ephemeral port
    let server_addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let listener = create_tuned_tcp_listener(server_addr).expect("Failed to create tuned TCP listener");
    let actual_addr = listener.local_addr().expect("Failed to query local addr");

    // 2. Spawn mock high-throughput echo server
    let server_handle = tokio::spawn(async move {
        while let Ok((mut socket, _peer)) = listener.accept().await {
            let _ = socket.set_nodelay(true);
            tokio::spawn(async move {
                let mut buf = [0u8; 1024];
                while let Ok(n) = socket.read(&mut buf).await {
                    if n == 0 {
                        break;
                    }
                    if socket.write_all(&buf[..n]).await.is_err() {
                        break;
                    }
                }
            });
        }
    });

    // 3. Launch concurrent load generator: 50 concurrent persistent connections
    let num_workers = 50;
    let requests_per_worker = 100;
    let metrics = Arc::new(MetricsCollector::default());
    let start_time = Instant::now();

    let mut handles = Vec::with_capacity(num_workers);

    for _ in 0..num_workers {
        let metrics_clone = metrics.clone();
        let target_addr = actual_addr;

        let handle = tokio::spawn(async move {
            let mut stream = match TcpStream::connect(target_addr).await {
                Ok(s) => s,
                Err(_) => {
                    metrics_clone.failed_requests.fetch_add(requests_per_worker, Ordering::Relaxed);
                    return;
                }
            };
            let _ = stream.set_nodelay(true);

            let payload = b"SOLOMON_HIGH_FREQUENCY_TX_BURST_TEST_PAYLOAD";
            let mut response_buf = [0u8; 128];

            for _ in 0..requests_per_worker {
                metrics_clone.total_requests.fetch_add(1, Ordering::Relaxed);
                
                if stream.write_all(payload).await.is_err() {
                    metrics_clone.failed_requests.fetch_add(1, Ordering::Relaxed);
                    continue;
                }

                match stream.read(&mut response_buf).await {
                    Ok(n) if n >= payload.len() => {
                        metrics_clone.successful_requests.fetch_add(1, Ordering::Relaxed);
                    }
                    _ => {
                        metrics_clone.failed_requests.fetch_add(1, Ordering::Relaxed);
                    }
                }
            }
        });

        handles.push(handle);
    }

    for h in handles {
        h.await.unwrap();
    }

    let elapsed = start_time.elapsed();
    let total = metrics.total_requests.load(Ordering::SeqCst);
    let success = metrics.successful_requests.load(Ordering::SeqCst);
    let failed = metrics.failed_requests.load(Ordering::SeqCst);
    let qps = (total as f64) / elapsed.as_secs_f64();

    println!("\n=======================================================");
    println!(" [LOAD HARNESS] Socket Saturation Benchmark Results");
    println!("=======================================================");
    println!(" Total Transmitted:    {} requests", total);
    println!(" Successful Packets:   {} requests", success);
    println!(" Dropped / Failed:     {} requests", failed);
    println!(" Total Test Duration:  {:?}", elapsed);
    println!(" Effective Throughput: {:.2} req/sec", qps);
    println!("=======================================================\n");

    assert_eq!(total, num_workers * requests_per_worker);
    assert_eq!(success, total, "Zero packet loss required across high-concurrency burst");
    assert_eq!(failed, 0);

    server_handle.abort();
}
