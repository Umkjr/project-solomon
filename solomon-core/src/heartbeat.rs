//! 72-Hour Offline Grace Period Heartbeat & Licensing State Machine.
//!
//! Provides non-blocking heartbeat state checks, timestamped epoch tracking,
//! local tamper-resistant cache recovery across proxy restarts during network partitions,
//! and strict fail-closed enforcement when the 72-hour grace period is exceeded.

use std::sync::atomic::{AtomicU64, AtomicU8, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};
use std::path::Path;
use crate::crypto::shake::KeccakSponge;
use crate::crypto::heartbeat::verify_and_apply_epoch_token;

/// 24 Hours in Seconds (Standard License Renewal Cycle)
pub const ACTIVE_WINDOW_SECS: u64 = 24 * 60 * 60; // 86,400s

/// 72 Hours in Seconds (Offline Grace Period Window)
pub const GRACE_WINDOW_SECS: u64 = 72 * 60 * 60; // 259,200s

/// Total Operational Window = 24h Active + 72h Grace = 96h (345,600s)
pub const TOTAL_EXPIRY_SECS: u64 = ACTIVE_WINDOW_SECS + GRACE_WINDOW_SECS;

/// Heartbeat Operational State enum.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HeartbeatStatus {
    /// Licensed and actively renewed within the 24-hour cycle.
    Active {
        last_synced: u64,
        valid_until: u64,
    },
    /// Control plane unreachable or network partitioned, but within the 72-hour offline grace period.
    GracePeriod {
        last_synced: u64,
        grace_until: u64,
        remaining_seconds: u64,
    },
    /// Offline grace period has expired without a valid token renewal. Transactions fail-closed.
    ExpiredFailClosed {
        last_synced: u64,
        expired_at: u64,
    },
}

impl HeartbeatStatus {
    /// Returns true if the proxy is permitted to sign and process transactions.
    pub fn is_operational(&self) -> bool {
        match self {
            HeartbeatStatus::Active { .. } => true,
            HeartbeatStatus::GracePeriod { .. } => true,
            HeartbeatStatus::ExpiredFailClosed { .. } => false,
        }
    }
}

/// Thread-safe Heartbeat Manager tracking license state and offline grace periods.
pub struct HeartbeatManager {
    last_synced_epoch: AtomicU64,
    hardware_fingerprint: [u8; 32],
    cache_path: String,
    // 0 = Active, 1 = GracePeriod, 2 = ExpiredFailClosed
    state_code: AtomicU8,
}

impl HeartbeatManager {
    /// Creates a new HeartbeatManager with hardware fingerprint binding.
    pub fn new(hardware_fingerprint: [u8; 32], cache_path: Option<String>) -> Self {
        let path = cache_path.unwrap_or_else(|| "solomon_heartbeat.cache".to_string());
        let mgr = Self {
            last_synced_epoch: AtomicU64::new(0),
            hardware_fingerprint,
            cache_path: path,
            state_code: AtomicU8::new(2), // Starts in Expired until initialized/synced
        };
        // Attempt recovery from local cache
        mgr.recover_from_cache();
        mgr
    }

    /// Returns current Unix timestamp in seconds.
    pub fn current_time_secs(&self) -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    }

    /// Computes the current heartbeat operational status.
    pub fn get_status(&self) -> HeartbeatStatus {
        let last_synced = self.last_synced_epoch.load(Ordering::SeqCst);
        if last_synced == 0 {
            return HeartbeatStatus::ExpiredFailClosed {
                last_synced: 0,
                expired_at: 0,
            };
        }

        let now = self.current_time_secs();
        let valid_until = last_synced.saturating_add(ACTIVE_WINDOW_SECS);
        let grace_until = last_synced.saturating_add(TOTAL_EXPIRY_SECS);

        if now <= valid_until {
            self.state_code.store(0, Ordering::SeqCst);
            HeartbeatStatus::Active {
                last_synced,
                valid_until,
            }
        } else if now <= grace_until {
            self.state_code.store(1, Ordering::SeqCst);
            let remaining = grace_until.saturating_sub(now);
            HeartbeatStatus::GracePeriod {
                last_synced,
                grace_until,
                remaining_seconds: remaining,
            }
        } else {
            self.state_code.store(2, Ordering::SeqCst);
            HeartbeatStatus::ExpiredFailClosed {
                last_synced,
                expired_at: grace_until,
            }
        }
    }

    /// Fast non-blocking check for the transaction critical path.
    pub fn is_operational(&self) -> bool {
        self.get_status().is_operational()
    }

    /// Records a successful heartbeat handshake and persists the verified token to local cache.
    pub fn record_successful_sync(&self, token_bytes: &[u8; 80], timestamp: Option<u64>) -> bool {
        let ts = timestamp.unwrap_or_else(|| self.current_time_secs());

        // Apply daily salt to core cryptographic subsystem
        if verify_and_apply_epoch_token(token_bytes).is_err() {
            return false;
        }

        self.last_synced_epoch.store(ts, Ordering::SeqCst);
        self.state_code.store(0, Ordering::SeqCst);

        // Persist token and timestamp to local cache
        self.save_to_cache(token_bytes, ts);
        true
    }

    /// Manually sets the synced timestamp (intended only for test harnesses and time-travel simulations).
    /// DO NOT call from production proxy execution paths.
    #[doc(hidden)]
    pub fn set_last_synced_for_testing(&self, timestamp: u64) {
        self.last_synced_epoch.store(timestamp, Ordering::SeqCst);
    }

    /// Saves the epoch token to cache file with an integrity MAC tied to the hardware fingerprint.
    fn save_to_cache(&self, token_bytes: &[u8; 80], timestamp: u64) {
        let mut buf = Vec::with_capacity(128);
        buf.extend_from_slice(&timestamp.to_be_bytes()); // 8 bytes timestamp
        buf.extend_from_slice(token_bytes);             // 80 bytes token

        // Compute MAC: Keccak(Hardware Fingerprint || Timestamp || Token)
        let mut sponge = KeccakSponge::new_shake256();
        sponge.absorb(&self.hardware_fingerprint);
        sponge.absorb(&buf);
        let mut mac = [0u8; 32];
        sponge.squeeze(&mut mac);
        buf.extend_from_slice(&mac);                    // 32 bytes MAC (total = 120 bytes)

        let _ = std::fs::write(&self.cache_path, &buf);
    }

    /// Recovers state from local cache on startup.
    fn recover_from_cache(&self) {
        if !Path::new(&self.cache_path).exists() {
            return;
        }

        let Ok(data) = std::fs::read(&self.cache_path) else {
            return;
        };

        if data.len() != 120 {
            return;
        }

        let mut ts_bytes = [0u8; 8];
        ts_bytes.copy_from_slice(&data[0..8]);
        let timestamp = u64::from_be_bytes(ts_bytes);

        let mut token = [0u8; 80];
        token.copy_from_slice(&data[8..88]);

        let mut rec_mac = [0u8; 32];
        rec_mac.copy_from_slice(&data[88..120]);

        // Verify MAC
        let mut sponge = KeccakSponge::new_shake256();
        sponge.absorb(&self.hardware_fingerprint);
        sponge.absorb(&data[0..88]);
        let mut expected_mac = [0u8; 32];
        sponge.squeeze(&mut expected_mac);

        let mut diff = 0u8;
        for i in 0..32 {
            diff |= rec_mac[i] ^ expected_mac[i];
        }

        if diff != 0 {
            // Tampered cache file
            return;
        }

        let now = self.current_time_secs();
        let grace_until = timestamp.saturating_add(TOTAL_EXPIRY_SECS);

        if now <= grace_until {
            // Attempt to apply the token
            if verify_and_apply_epoch_token(&token).is_ok() {
                self.last_synced_epoch.store(timestamp, Ordering::SeqCst);
                self.get_status(); // Update state code
            }
        }
    }
}
