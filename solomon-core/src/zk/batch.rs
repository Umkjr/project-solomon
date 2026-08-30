use crate::crypto::shake::KeccakSponge;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{SystemTime, UNIX_EPOCH, Duration};
use std::fs::OpenOptions;
use std::io::Write;
use tokio::sync::mpsc::{channel, Sender, Receiver, error::TrySendError};
use serde::{Serialize, Deserialize};

pub static CONSECUTIVE_WORKER_PANICS: AtomicUsize = AtomicUsize::new(0);

pub const DEFAULT_BATCH_SIZE: usize = 16;
pub const DEFAULT_BATCH_WINDOW_MS: u64 = 5;
pub const DEFAULT_CHANNEL_CAPACITY: usize = 10_000;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TransactionRecord {
    pub payload: Vec<u8>,
    pub public_key: Vec<u8>,
    pub signature: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BatchIngressError {
    QueueFull,
    WorkerDisconnected,
}

/// Asynchronous, lock-free batch accumulator with fault-isolated background worker.
pub struct AsyncBatchAccumulator {
    pub tx_sender: Sender<TransactionRecord>,
    pub target_size: usize,
    pub window_ms: u64,
    pub panics_total: Arc<AtomicUsize>,
    pub batches_processed: Arc<AtomicUsize>,
}

impl AsyncBatchAccumulator {
    /// Creates and starts an asynchronous batch accumulator with default parameters.
    pub fn new() -> (Self, tokio::task::JoinHandle<()>) {
        Self::with_config(DEFAULT_BATCH_SIZE, DEFAULT_BATCH_WINDOW_MS, DEFAULT_CHANNEL_CAPACITY)
    }

    /// Creates an accumulator with custom configuration and spawns the background worker.
    pub fn with_config(
        target_size: usize,
        window_ms: u64,
        channel_capacity: usize,
    ) -> (Self, tokio::task::JoinHandle<()>) {
        let (tx_sender, rx) = channel(channel_capacity);
        let panics_total = Arc::new(AtomicUsize::new(0));
        let batches_processed = Arc::new(AtomicUsize::new(0));

        let panics_clone = panics_total.clone();
        let batches_clone = batches_processed.clone();

        let handle = match tokio::runtime::Handle::try_current() {
            Ok(rt) => {
                rt.spawn(async move {
                    run_batch_worker(rx, target_size, window_ms, panics_clone, batches_clone).await;
                })
            }
            Err(_) => {
                let (jh_sender, jh_receiver) = std::sync::mpsc::channel();
                std::thread::spawn(move || {
                    if let Ok(rt) = tokio::runtime::Builder::new_current_thread().enable_all().build() {
                        let inner_handle = rt.spawn(async move {
                            run_batch_worker(rx, target_size, window_ms, panics_clone, batches_clone).await;
                        });
                        let _ = jh_sender.send(inner_handle);
                        rt.block_on(async {
                            loop {
                                tokio::time::sleep(Duration::from_secs(3600)).await;
                            }
                        });
                    }
                });
                jh_receiver.recv().unwrap_or_else(|_| {
                    let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
                    rt.spawn(async {})
                })
            }
        };

        let accumulator = Self {
            tx_sender,
            target_size,
            window_ms,
            panics_total,
            batches_processed,
        };

        (accumulator, handle)
    }

    /// Non-blocking push for HTTP ingress handlers.
    pub fn try_push(&self, tx: TransactionRecord) -> Result<(), BatchIngressError> {
        if CONSECUTIVE_WORKER_PANICS.load(Ordering::SeqCst) >= 5 {
            // Circuit Breaker: Halt ingestion, proxy should return HTTP 503 globally
            return Err(BatchIngressError::WorkerDisconnected);
        }
        match self.tx_sender.try_send(tx) {
            Ok(_) => Ok(()),
            Err(TrySendError::Full(_)) => Err(BatchIngressError::QueueFull),
            Err(TrySendError::Closed(_)) => Err(BatchIngressError::WorkerDisconnected),
        }
    }
}

/// Dedicated background worker loop with panic isolation and dead-letter failover.
async fn run_batch_worker(
    mut rx: Receiver<TransactionRecord>,
    target_size: usize,
    window_ms: u64,
    panics_total: Arc<AtomicUsize>,
    batches_processed: Arc<AtomicUsize>,
) {
    let mut in_flight_buffer: Vec<TransactionRecord> = Vec::with_capacity(target_size);
    let window_duration = Duration::from_millis(window_ms);

    loop {
        if CONSECUTIVE_WORKER_PANICS.load(Ordering::SeqCst) >= 5 {
            // Circuit breaker tripped; halt background processing.
            break;
        }

        let mut timeout_expired = false;
        tokio::select! {
            biased;
            maybe_tx = rx.recv() => {
                match maybe_tx {
                    Some(tx) => {
                        in_flight_buffer.push(tx);
                    }
                    None => {
                        // Channel closed (proxy shutdown)
                        break;
                    }
                }
            }
            _ = tokio::time::sleep(window_duration), if !in_flight_buffer.is_empty() => {
                timeout_expired = true;
            }
        }

        // Check if buffer should flush
        if in_flight_buffer.len() >= target_size || (timeout_expired && !in_flight_buffer.is_empty()) {
            let batch_to_process = std::mem::replace(&mut in_flight_buffer, Vec::with_capacity(target_size));

            // Execute batch Merkle aggregation inside panic isolation boundary
            let process_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let padded = BatchAccumulator::pad_batch(batch_to_process.clone());
                let (root, inclusion_proofs) = BatchAccumulator::build_merkle_tree(&padded);
                (root, inclusion_proofs)
            }));

            match process_result {
                Ok((root, _proofs)) => {
                    CONSECUTIVE_WORKER_PANICS.store(0, Ordering::SeqCst);
                    batches_processed.fetch_add(1, Ordering::SeqCst);
                    tracing::debug!(
                        message = "Async STARK Batch Merkle root computed successfully",
                        merkle_root = ?root
                    );
                }
                Err(_panic_err) => {
                    CONSECUTIVE_WORKER_PANICS.fetch_add(1, Ordering::SeqCst);
                    panics_total.fetch_add(1, Ordering::SeqCst);
                    
                    let timestamp_ms = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis();
                    let filename = format!("solomon_dlq_{}.wal", timestamp_ms);
                    
                    if let Ok(mut file) = OpenOptions::new().create(true).append(true).open(&filename) {
                        let serialized = bincode::serialize(&batch_to_process).unwrap_or_default();
                        let len_prefix = (serialized.len() as u32).to_le_bytes();
                        let _ = file.write_all(&len_prefix);
                        let _ = file.write_all(&serialized);
                        let _ = file.sync_all();
                    }
                    
                    tracing::error!("CRITICAL: Batch aggregator caught unhandled panic! Spooled to WAL and reset buffer.");
                }
            }
        }
    }
}

/// Backward-compatible synchronous wrapper and Merkle utility engine.
pub struct BatchAccumulator {
    pub async_engine: Arc<AsyncBatchAccumulator>,
}

impl BatchAccumulator {
    pub fn new() -> Self {
        let (async_engine, _handle) = AsyncBatchAccumulator::new();
        Self {
            async_engine: Arc::new(async_engine),
        }
    }

    pub fn with_config(target_size: usize, window_ms: u64) -> Self {
        let (async_engine, _handle) = AsyncBatchAccumulator::with_config(
            target_size,
            window_ms,
            DEFAULT_CHANNEL_CAPACITY,
        );
        Self {
            async_engine: Arc::new(async_engine),
        }
    }

    pub fn push(&self, tx: TransactionRecord) -> Option<Vec<TransactionRecord>> {
        let _ = self.async_engine.try_push(tx);
        None
    }

    /// Pads a batch with deterministic dummy transactions to reach the target power-of-2 size.
    pub fn pad_batch(mut batch: Vec<TransactionRecord>) -> Vec<(TransactionRecord, bool)> {
        let current_len = batch.len();
        let mut target_pow2 = 1;
        while target_pow2 < current_len.max(DEFAULT_BATCH_SIZE) {
            target_pow2 *= 2;
        }

        let mut padded = Vec::with_capacity(target_pow2);
        for tx in batch.drain(..) {
            padded.push((tx, false));
        }
        
        while padded.len() < target_pow2 {
            padded.push((
                TransactionRecord {
                    payload: vec![],
                    public_key: vec![0u8; 1952],
                    signature: vec![0u8; 3309],
                },
                true
            ));
        }
        padded
    }

    /// Computes the Merkle Root of a padded batch and generates inclusion proofs.
    pub fn build_merkle_tree(padded_batch: &[(TransactionRecord, bool)]) -> ([u8; 32], Vec<Vec<[u8; 32]>>) {
        let batch_size = padded_batch.len();
        let mut leaves = Vec::with_capacity(batch_size);
        for (i, (tx, is_padding)) in padded_batch.iter().enumerate() {
            if tx.payload == b"POISON_PILL" {
                panic!("Injected deterministic mathematical panic for WAL failover testing");
            }
            
            let mut sponge = KeccakSponge::new_shake256();
            if *is_padding {
                sponge.absorb(b"PADDING");
                sponge.absorb(&[i as u8]);
            } else {
                sponge.absorb(&tx.payload);
            }
            let mut hash = [0u8; 32];
            sponge.squeeze(&mut hash);
            leaves.push(hash);
        }

        let mut layers = vec![leaves.clone()];
        let mut current_layer = leaves;

        while current_layer.len() > 1 {
            let mut next_layer = Vec::with_capacity(current_layer.len() / 2);
            for chunk in current_layer.chunks(2) {
                let mut sponge = KeccakSponge::new_shake256();
                sponge.absorb(&chunk[0]);
                if chunk.len() > 1 {
                    sponge.absorb(&chunk[1]);
                } else {
                    sponge.absorb(&chunk[0]);
                }
                let mut parent = [0u8; 32];
                sponge.squeeze(&mut parent);
                next_layer.push(parent);
            }
            layers.push(next_layer.clone());
            current_layer = next_layer;
        }

        let root = current_layer[0];

        // Generate inclusion proofs
        let mut proofs = Vec::with_capacity(batch_size);
        for i in 0..batch_size {
            let mut proof = Vec::new();
            let mut idx = i;
            for layer in &layers[..layers.len() - 1] {
                let sibling_idx = if idx % 2 == 0 { idx + 1 } else { idx - 1 };
                if sibling_idx < layer.len() {
                    proof.push(layer[sibling_idx]);
                }
                idx /= 2;
            }
            proofs.push(proof);
        }

        (root, proofs)
    }
}
