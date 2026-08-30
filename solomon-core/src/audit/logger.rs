use crate::audit::record::{AuditRecord, AuditSegmentSeal, CryptoAuditMeta, SystemAction};
use crate::audit::chain::AuditChain;
use crate::audit::crypto_traits::{AuditHasher, AuditSigner};
use tokio::sync::mpsc::{self, Receiver, Sender};
use std::fs::{OpenOptions, create_dir_all};
use std::io::Write;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{SystemTime, UNIX_EPOCH, Duration};
use tokio::sync::Mutex;

pub struct AuditLogger {
    sender: Sender<AuditLogCommand>,
    last_hash: Arc<Mutex<String>>,
    signer: Arc<dyn AuditSigner>,
    hasher: Arc<dyn AuditHasher>,
    node_identity_hex: String,
    pub worker_healthy: Arc<AtomicBool>,
}

enum AuditLogCommand {
    LogEvent {
        event_id: String,
        route_target: String,
        crypto_profile: CryptoAuditMeta,
        localization_region: String,
        system_action: SystemAction,
        respond_to: tokio::sync::oneshot::Sender<AuditRecord>,
    },
    Flush(tokio::sync::oneshot::Sender<()>),
}

impl AuditLogger {
    pub fn new(
        log_dir: PathBuf,
        channel_capacity: usize,
        signer: Arc<dyn AuditSigner>,
        hasher: Arc<dyn AuditHasher>,
        node_identity: [u8; 32],
    ) -> Self {
        let (sender, receiver) = mpsc::channel(channel_capacity);
        let last_hash = Arc::new(Mutex::new(AuditChain::GENESIS_HASH.to_string()));
        let worker_last_hash = Arc::clone(&last_hash);
        let node_identity_hex = hex::encode(node_identity);
        let worker_signer = Arc::clone(&signer);
        let worker_hasher = Arc::clone(&hasher);
        let worker_node_identity = node_identity_hex.clone();
        let worker_healthy = Arc::new(AtomicBool::new(true));
        let worker_healthy_flag = Arc::clone(&worker_healthy);

        // Spawn background asynchronous worker task
        tokio::spawn(async move {
            Self::background_worker(
                receiver,
                log_dir,
                worker_last_hash,
                worker_signer,
                worker_hasher,
                worker_node_identity,
                worker_healthy_flag,
            ).await;
        });

        Self {
            sender,
            last_hash,
            signer,
            hasher,
            node_identity_hex,
            worker_healthy,
        }
    }

    pub async fn emit(
        &self,
        event_id: String,
        route_target: String,
        crypto_profile: CryptoAuditMeta,
        localization_region: String,
        system_action: SystemAction,
    ) -> Result<AuditRecord, &'static str> {
        let (tx, rx) = tokio::sync::oneshot::channel();
        let cmd = AuditLogCommand::LogEvent {
            event_id,
            route_target,
            crypto_profile,
            localization_region,
            system_action,
            respond_to: tx,
        };

        self.sender.send(cmd).await.map_err(|_| "Audit logger worker channel closed")?;
        rx.await.map_err(|_| "Audit logger response dropped")
    }

    pub async fn get_last_hash(&self) -> String {
        let lock = self.last_hash.lock().await;
        lock.clone()
    }

    pub async fn flush(&self) -> Result<(), &'static str> {
        let (tx, rx) = tokio::sync::oneshot::channel();
        self.sender.send(AuditLogCommand::Flush(tx)).await.map_err(|_| "Audit logger worker channel closed")?;
        rx.await.map_err(|_| "Audit flush response dropped")
    }

    pub fn signer(&self) -> &dyn AuditSigner {
        self.signer.as_ref()
    }

    pub fn hasher(&self) -> &dyn AuditHasher {
        self.hasher.as_ref()
    }

    pub fn node_identity_hex(&self) -> &str {
        &self.node_identity_hex
    }

    pub fn is_healthy(&self) -> bool {
        self.worker_healthy.load(Ordering::Relaxed)
    }

    /// Gregorian date helper (days since UNIX epoch -> (year, month, day))
    fn days_to_ymd(days: u64) -> (u64, u64, u64) {
        let z = days + 719468;
        let era = z / 146097;
        let doe = z % 146097;
        let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
        let y = yoe + era * 400;
        let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
        let mp = (5 * doy + 2) / 153;
        let d = doy - (153 * mp + 2) / 5 + 1;
        let m = if mp < 10 { mp + 3 } else { mp - 9 };
        let y = if m <= 2 { y + 1 } else { y };
        (y, m, d)
    }

    fn write_segment_metadata(log_dir: &PathBuf, segment_date: &str, timestamp_secs: u64) {
        let meta_path = log_dir.join(format!("solomon_audit_{}.meta.json", segment_date));
        let meta = serde_json::json!({
            "segment_date": segment_date,
            "region": "IN-MUM-01",
            "country_code": "IN",
            "data_classification": "HIGHLY_CONFIDENTIAL",
            "retention_class": "10_YEAR_RBI_MANDATORY",
            "data_localization_status": "INDIA_ONLY",
            "regulatory_basis": "RBI Master Direction IT Governance 2023 §15",
            "created_at_utc_secs": timestamp_secs,
        });
        if let Ok(meta_json) = serde_json::to_string_pretty(&meta) {
            let _ = std::fs::write(&meta_path, meta_json);
        }
    }

    fn try_open_file(path: &PathBuf, retries: usize) -> Option<std::fs::File> {
        for attempt in 0..=retries {
            match OpenOptions::new().create(true).append(true).open(path) {
                Ok(f) => return Some(f),
                Err(e) => {
                    tracing::warn!("Audit logger file open attempt {}/{} for {:?} failed: {:?}", attempt + 1, retries + 1, path, e);
                    if attempt < retries {
                        std::thread::sleep(Duration::from_millis(100));
                    }
                }
            }
        }
        None
    }

    async fn background_worker(
        mut rx: Receiver<AuditLogCommand>,
        log_dir: PathBuf,
        last_hash: Arc<Mutex<String>>,
        signer: Arc<dyn AuditSigner>,
        hasher: Arc<dyn AuditHasher>,
        node_identity_hex: String,
        worker_healthy: Arc<AtomicBool>,
    ) {
        if let Err(e) = create_dir_all(&log_dir) {
            tracing::error!("CRITICAL: Failed to create audit log directory {:?}: {:?}", log_dir, e);
            worker_healthy.store(false, Ordering::SeqCst);
            return;
        }

        let now_secs = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let days = now_secs / 86400;
        let (y, m, d) = Self::days_to_ymd(days);
        let today = format!("{:04}-{:02}-{:02}", y, m, d);

        let mut current_segment_date = today.clone();
        let log_path = log_dir.join(format!("solomon_audit_{}.ndjson", current_segment_date));
        Self::write_segment_metadata(&log_dir, &current_segment_date, now_secs);

        let mut file_opt = Self::try_open_file(&log_path, 3);
        if file_opt.is_none() {
            tracing::error!("CRITICAL: Failed to open initial audit log file {:?}", log_path);
            worker_healthy.store(false, Ordering::SeqCst);
        }

        while let Some(cmd) = rx.recv().await {
            match cmd {
                AuditLogCommand::LogEvent {
                    event_id,
                    route_target,
                    crypto_profile,
                    localization_region,
                    system_action,
                    respond_to,
                } => {
                    let now = SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap_or_default();
                    let timestamp_utc = now.as_micros() as u64;
                    let timestamp_secs = now.as_secs();

                    // --- RBI G1: Rotate segment file if day has changed ---
                    let days_now = timestamp_secs / 86400;
                    let (curr_y, curr_m, curr_d) = Self::days_to_ymd(days_now);
                    let today_str = format!("{:04}-{:02}-{:02}", curr_y, curr_m, curr_d);

                    if today_str != current_segment_date {
                        // 1. Append segment seal before closing
                        let prev = last_hash.lock().await.clone();
                        let payload = AuditSegmentSeal::signable_payload(
                            hasher.as_ref(),
                            &current_segment_date,
                            &prev,
                            timestamp_utc,
                            &node_identity_hex,
                        );
                        let sig_bytes = signer.sign_bytes(&payload);
                        let seal = AuditSegmentSeal {
                            record_type: "SEGMENT_SEAL".to_string(),
                            segment_date: current_segment_date.clone(),
                            last_record_hash: prev,
                            sealed_at_utc_us: timestamp_utc,
                            node_identity: node_identity_hex.clone(),
                            seal_signature: hex::encode(&sig_bytes),
                        };
                        if let Some(ref mut file) = file_opt {
                            if let Ok(seal_json) = serde_json::to_string(&seal) {
                                let _ = writeln!(file, "{}", seal_json);
                                let _ = file.flush();
                            }
                        }

                        // 2. RBI G2: Set previous segment file read-only (WORM lock)
                        let old_path = log_dir.join(format!("solomon_audit_{}.ndjson", current_segment_date));
                        if let Ok(metadata) = std::fs::metadata(&old_path) {
                            let mut perms = metadata.permissions();
                            perms.set_readonly(true);
                            let _ = std::fs::set_permissions(&old_path, perms);
                        }

                        // 3. RBI G1: Purge segments older than 3650 days (10-year retention cap)
                        if let Ok(entries) = std::fs::read_dir(&log_dir) {
                            let mut segments: Vec<_> = entries
                                .filter_map(|e| e.ok())
                                .filter(|e| e.file_name().to_string_lossy().starts_with("solomon_audit_") && e.file_name().to_string_lossy().ends_with(".ndjson"))
                                .collect();
                            segments.sort_by_key(|e| e.file_name());
                            while segments.len() > 3650 {
                                let oldest = segments.remove(0);
                                let p = oldest.path();
                                if let Ok(m) = std::fs::metadata(&p) {
                                    let mut perms = m.permissions();
                                    perms.set_readonly(false);
                                    let _ = std::fs::set_permissions(&p, perms);
                                }
                                let _ = std::fs::remove_file(&p);
                            }
                        }

                        // 4. Open new daily segment
                        current_segment_date = today_str;
                        let new_path = log_dir.join(format!("solomon_audit_{}.ndjson", current_segment_date));
                        Self::write_segment_metadata(&log_dir, &current_segment_date, timestamp_secs);

                        file_opt = Self::try_open_file(&new_path, 3);
                        if file_opt.is_none() {
                            tracing::error!("CRITICAL: Failed to open new audit segment {:?} after retries", new_path);
                            worker_healthy.store(false, Ordering::SeqCst);
                        } else {
                            worker_healthy.store(true, Ordering::SeqCst);
                        }
                    }

                    let prev_hash = {
                        let lock = last_hash.lock().await;
                        lock.clone()
                    };

                    let current_hash = AuditRecord::compute_hash(
                        hasher.as_ref(),
                        timestamp_utc,
                        &event_id,
                        &route_target,
                        &crypto_profile,
                        &localization_region,
                        &system_action,
                        &prev_hash,
                    );

                    let record = AuditRecord {
                        timestamp_utc,
                        event_id,
                        route_target,
                        crypto_profile,
                        localization_region,
                        system_action,
                        previous_hash: prev_hash,
                        current_hash: current_hash.clone(),
                    };

                    // Update last hash state
                    {
                        let mut lock = last_hash.lock().await;
                        *lock = current_hash;
                    }

                    // Serialize to NDJSON and write to disk if file available
                    if let Some(ref mut file) = file_opt {
                        if let Ok(serialized) = serde_json::to_string(&record) {
                            let _ = writeln!(file, "{}", serialized);
                            let _ = file.flush();
                        }
                    }

                    let _ = respond_to.send(record);
                }
                AuditLogCommand::Flush(respond_to) => {
                    if let Some(ref mut file) = file_opt {
                        let _ = file.flush();
                    }
                    let _ = respond_to.send(());
                }
            }
        }
    }
}

