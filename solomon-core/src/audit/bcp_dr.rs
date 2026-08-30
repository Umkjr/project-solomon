//! RBI G6: BCP/DR Status Report Generator.
//! Provides machine-readable export of recovery objectives and DR drill history.

use serde::{Serialize, Deserialize};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

/// RBI-required BCP/DR objectives and current measured status.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct BcpDrReport {
    pub generated_at_utc_secs: u64,
    pub system_name: String,
    pub rto_target_seconds: u64,     // 4 hours = 14400
    pub rpo_target_seconds: u64,     // Near-zero = 5 seconds (WAL-based)
    pub last_dr_drill_utc_secs: u64,
    pub last_dr_drill_outcome: String,  // "PASS" | "FAIL" | "PARTIAL" | "NEVER"
    pub last_wal_failover_utc_secs: u64,
    pub last_backup_verified_utc_secs: u64,
    pub next_scheduled_dr_drill_utc_secs: u64,
    pub wal_enabled: bool,
    pub audit_log_backup_enabled: bool,
    pub current_audit_segment_count: u64,
}

/// Shared DR state updated by the WAL failover and heartbeat subsystems.
pub struct BcpDrState {
    pub last_dr_drill_utc_secs: AtomicU64,
    pub last_dr_drill_passed: std::sync::atomic::AtomicBool,
    pub last_wal_failover_utc_secs: AtomicU64,
    pub last_backup_verified_utc_secs: AtomicU64,
}

impl BcpDrState {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            last_dr_drill_utc_secs: AtomicU64::new(0),
            last_dr_drill_passed: std::sync::atomic::AtomicBool::new(false),
            last_wal_failover_utc_secs: AtomicU64::new(0),
            last_backup_verified_utc_secs: AtomicU64::new(0),
        })
    }

    /// Generate the BCP/DR report for RBI Inspector API.
    pub fn generate_report(&self, audit_segment_count: u64) -> BcpDrReport {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let drill_utc = self.last_dr_drill_utc_secs.load(Ordering::SeqCst);
        let drill_passed = self.last_dr_drill_passed.load(Ordering::SeqCst);

        BcpDrReport {
            generated_at_utc_secs: now,
            system_name: "Project Solomon PQ Switch".to_string(),
            rto_target_seconds: 14400,   // 4 hours
            rpo_target_seconds: 5,        // Near-zero (WAL-backed)
            last_dr_drill_utc_secs: drill_utc,
            last_dr_drill_outcome: if drill_utc == 0 {
                "NEVER".to_string()
            } else if drill_passed {
                "PASS".to_string()
            } else {
                "FAIL".to_string()
            },
            last_wal_failover_utc_secs: self.last_wal_failover_utc_secs.load(Ordering::SeqCst),
            last_backup_verified_utc_secs: self.last_backup_verified_utc_secs.load(Ordering::SeqCst),
            next_scheduled_dr_drill_utc_secs: if drill_utc > 0 { drill_utc + (180 * 24 * 3600) } else { now + (180 * 24 * 3600) }, // biannual
            wal_enabled: true,
            audit_log_backup_enabled: true,
            current_audit_segment_count: audit_segment_count,
        }
    }
}
