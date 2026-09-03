use solomon_core::zk::batch::{AsyncBatchAccumulator, TransactionRecord, CONSECUTIVE_WORKER_PANICS};
use std::sync::atomic::Ordering;
use std::time::Duration;
use std::fs;
use std::io::Read;
use tokio::time::sleep;

#[cfg(debug_assertions)]
#[tokio::test]
async fn test_wal_failover_on_panic() {
    // 1. Setup the AsyncBatchAccumulator
    let (accumulator, _handle) = AsyncBatchAccumulator::with_config(2, 50, 100);

    // 2. Create a poison pill transaction that deterministically panics the worker
    let poison_tx = TransactionRecord {
        payload: b"POISON_PILL".to_vec(),
        public_key: vec![0u8; 1952],
        signature: vec![0u8; 3309],
    };
    
    let normal_tx = TransactionRecord {
        payload: b"NORMAL_TX".to_vec(),
        public_key: vec![0u8; 1952],
        signature: vec![0u8; 3309],
    };

    // 3. Inject transactions
    accumulator.try_push(poison_tx.clone()).unwrap();
    accumulator.try_push(normal_tx.clone()).unwrap();

    // 4. Wait for processing and panic to trigger WAL spooling
    sleep(Duration::from_millis(200)).await;

    // 5. Assert circuit breaker counter incremented
    let panics = CONSECUTIVE_WORKER_PANICS.load(Ordering::SeqCst);
    assert_eq!(panics, 1, "Worker should have recorded exactly 1 panic");

    // 6. Asynchronous polling loop to verify WAL file creation
    let mut found_wal = false;
    let mut wal_content = Vec::new();
    
    for _ in 0..40 { // poll every 50ms up to 2000ms
        let entries = fs::read_dir(".").unwrap();
        for entry in entries {
            let entry = entry.unwrap();
            let file_name = entry.file_name().into_string().unwrap();
            if file_name.starts_with("solomon_dlq_") && file_name.ends_with(".wal") {
                found_wal = true;
                let mut file = fs::File::open(entry.path()).unwrap();
                file.read_to_end(&mut wal_content).unwrap();
                
                // Clean up WAL file after reading
                fs::remove_file(entry.path()).unwrap();
                break;
            }
        }
        if found_wal {
            break;
        }
        sleep(Duration::from_millis(50)).await;
    }

    assert!(found_wal, "WAL file was not created within the timeout");

    // 7. Parse the 4-byte length prefix and deserialize
    assert!(wal_content.len() > 4, "WAL file too small to contain length prefix");
    
    let mut len_bytes = [0u8; 4];
    len_bytes.copy_from_slice(&wal_content[0..4]);
    let payload_len = u32::from_le_bytes(len_bytes) as usize;
    
    assert_eq!(payload_len, wal_content.len() - 4, "WAL framing length mismatch");

    let recovered_batch: Vec<TransactionRecord> = bincode::deserialize(&wal_content[4..]).unwrap();

    // 8. Mathematically prove zero data loss
    assert_eq!(recovered_batch.len(), 2, "Recovered batch size mismatch");
    assert_eq!(recovered_batch[0].payload, poison_tx.payload);
    assert_eq!(recovered_batch[1].payload, normal_tx.payload);
}
