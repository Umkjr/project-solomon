use solomon_core::zk::batch::{AsyncBatchAccumulator, BatchAccumulator, BatchIngressError, TransactionRecord};

#[test]
fn test_batch_accumulator_padding_and_merkle_root() {
    let mut batch = Vec::new();
    for i in 0..5 {
        batch.push(TransactionRecord {
            payload: vec![i as u8; 10],
            public_key: vec![0u8; 1952],
            signature: vec![0u8; 3309],
        });
    }

    let padded = BatchAccumulator::pad_batch(batch);
    assert_eq!(padded.len(), 16, "Batch should be padded to strictly N=16");
    
    // First 5 are not padding
    for i in 0..5 {
        assert!(!padded[i].1);
    }
    // Last 11 are padding
    for i in 5..16 {
        assert!(padded[i].1);
    }

    let (root, proofs) = BatchAccumulator::build_merkle_tree(&padded);
    assert_ne!(root, [0u8; 32], "Merkle root should be computed");
    assert_eq!(proofs.len(), 16, "Must generate inclusion proof for all 16 leaves");
}

#[tokio::test]
async fn test_async_batch_accumulator_backpressure_and_fault_isolation() {
    // 1. Create an accumulator with tiny channel capacity (2) to test backpressure
    let (acc, _handle) = AsyncBatchAccumulator::with_config(4, 10, 2);

    let tx = TransactionRecord {
        payload: b"Tx payload".to_vec(),
        public_key: vec![0x11u8; 1952],
        signature: vec![0x22u8; 3309],
    };

    // Push until capacity is filled
    assert!(acc.try_push(tx.clone()).is_ok());
    assert!(acc.try_push(tx.clone()).is_ok());
    
    // Third push should trigger QueueFull backpressure immediately
    let res = acc.try_push(tx.clone());
    assert_eq!(res, Err(BatchIngressError::QueueFull), "Overload must return QueueFull");

    // 2. High-throughput ingestion benchmark
    let (high_load_acc, _h2) = AsyncBatchAccumulator::with_config(100, 5, 10_000);
    let start = std::time::Instant::now();
    for _ in 0..1_000 {
        let _ = high_load_acc.try_push(tx.clone());
    }
    let elapsed = start.elapsed();
    println!("\n[ASYNC INGESTION BENCHMARK] Pushed 1,000 txs in {:.3} ms ({:.0} TPS equivalent)", 
        elapsed.as_secs_f64() * 1000.0,
        1_000.0 / elapsed.as_secs_f64()
    );
    assert!(elapsed.as_millis() < 50, "1,000 lock-free pushes must complete under 50ms");
}
