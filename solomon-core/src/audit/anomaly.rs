//! RBI G3 + G12: Real-time anomaly detection with alert dedup and rate-limiting.
//! Monitors the audit event stream for:
//!   1. Burst failure rate (>10 failures in 60 seconds)
//!   2. After-hours activity (transactions outside 06:00–22:00 IST = UTC+5:30)
//!   3. Rapid back-to-back events from the same route_target (>100 events in 10 seconds)

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tokio::sync::Mutex;
use crate::audit::record::SystemAction;

/// Maximum failure events in a rolling 60-second window before alert fires
const BURST_FAILURE_THRESHOLD: usize = 10;
const BURST_FAILURE_WINDOW_SECS: u64 = 60;
const MAX_FAILURE_TIMESTAMPS: usize = 1000;

/// Maximum events per route_target in a rolling 10-second window
const ROUTE_SATURATION_THRESHOLD: usize = 100;
const ROUTE_SATURATION_WINDOW_SECS: u64 = 10;
const MAX_TRACKED_ROUTES: usize = 1024;

/// Minimum seconds between repeated alerts for the same alert type (dedup / rate-limit)
const ALERT_DEDUP_WINDOW_SECS: u64 = 300; // 5 minutes

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum AlertType {
    BurstFailure,
    AfterHoursActivity { hour_utc: u8 },
    RouteSaturation { route_target: String },
}

pub struct AnomalyDetector {
    /// Ring buffer of failure timestamps (Unix seconds)
    failure_timestamps: Arc<Mutex<Vec<u64>>>,
    /// Per-route event timestamps
    route_timestamps: Arc<Mutex<HashMap<String, Vec<u64>>>>,
    /// Last alert fired time per alert type (dedup)
    last_alert_times: Arc<Mutex<HashMap<String, u64>>>,
    /// Total alert count
    alert_count: Arc<AtomicU64>,
}

impl AnomalyDetector {
    pub fn new() -> Self {
        Self {
            failure_timestamps: Arc::new(Mutex::new(Vec::new())),
            route_timestamps: Arc::new(Mutex::new(HashMap::new())),
            last_alert_times: Arc::new(Mutex::new(HashMap::new())),
            alert_count: Arc::new(AtomicU64::new(0)),
        }
    }

    /// Call this EVERY time an audit event is emitted. Pass the action, route, and current UTC timestamp in seconds.
    pub async fn observe(&self, action: &SystemAction, route_target: &str, timestamp_secs: u64) {
        // ── Check 1: Burst failure detection ──────────────────────────────────────
        if matches!(action, SystemAction::ValidationErrorRejected | SystemAction::FailClosedBypassed | SystemAction::CircuitBreakerTripped) {
            let mut failures = self.failure_timestamps.lock().await;
            failures.push(timestamp_secs);
            // Purge old entries outside the rolling window
            let cutoff = timestamp_secs.saturating_sub(BURST_FAILURE_WINDOW_SECS);
            failures.retain(|&t| t >= cutoff);

            if failures.len() > MAX_FAILURE_TIMESTAMPS {
                let excess = failures.len() - MAX_FAILURE_TIMESTAMPS;
                failures.drain(0..excess);
            }

            if failures.len() >= BURST_FAILURE_THRESHOLD {
                self.fire_alert(
                    "BURST_FAILURE",
                    &format!("RBI ALERT: {} failures in {}s — possible attack or system fault",
                        failures.len(), BURST_FAILURE_WINDOW_SECS),
                    timestamp_secs,
                ).await;
            }
        }

        // ── Check 2: After-hours activity (IST = UTC+5:30) ────────────────────────
        // IST offset = 5.5 hours = 19800 seconds
        let ist_secs = timestamp_secs.saturating_add(19800);
        let hour_ist = ((ist_secs % 86400) / 3600) as u8;
        if hour_ist < 6 || hour_ist >= 22 {
            self.fire_alert(
                &format!("AFTER_HOURS_{}", hour_ist),
                &format!("RBI ALERT: Transaction processed outside business hours at {:02}:xx IST on route '{}'",
                    hour_ist, route_target),
                timestamp_secs,
            ).await;
        }

        // ── Check 3: Route saturation ─────────────────────────────────────────────
        {
            let mut routes = self.route_timestamps.lock().await;
            if routes.len() >= MAX_TRACKED_ROUTES && !routes.contains_key(route_target) {
                // Find and evict the stalest route
                if let Some(oldest_key) = routes
                    .iter()
                    .min_by_key(|(_, v)| v.iter().copied().min().unwrap_or(u64::MAX))
                    .map(|(k, _)| k.clone())
                {
                    routes.remove(&oldest_key);
                }
            }

            let route_times = routes.entry(route_target.to_string()).or_insert_with(Vec::new);
            route_times.push(timestamp_secs);
            let cutoff = timestamp_secs.saturating_sub(ROUTE_SATURATION_WINDOW_SECS);
            route_times.retain(|&t| t >= cutoff);

            if route_times.len() >= ROUTE_SATURATION_THRESHOLD {
                self.fire_alert(
                    &format!("ROUTE_SAT_{}", route_target),
                    &format!("RBI ALERT: {} events in {}s on route '{}' — possible replay or DoS",
                        route_times.len(), ROUTE_SATURATION_WINDOW_SECS, route_target),
                    timestamp_secs,
                ).await;
            }
        }
    }


    /// Fires a deduplicated alert. Repeats are suppressed for ALERT_DEDUP_WINDOW_SECS.
    async fn fire_alert(&self, alert_key: &str, message: &str, now: u64) {
        let mut times = self.last_alert_times.lock().await;
        let last = times.get(alert_key).copied().unwrap_or(0);
        if now.saturating_sub(last) < ALERT_DEDUP_WINDOW_SECS {
            return; // Suppressed (dedup)
        }
        times.insert(alert_key.to_string(), now);
        self.alert_count.fetch_add(1, Ordering::Relaxed);

        // Primary alert output: structured JSON to stderr (syslog/SIEM can consume this)
        let alert_json = serde_json::json!({
            "alert_type": "RBI_COMPLIANCE_ALERT",
            "key": alert_key,
            "message": message,
            "timestamp_utc_secs": now,
            "severity": "HIGH",
            "system": "ProjectSolomon",
        });
        eprintln!("{}", alert_json);
    }

    /// Returns total alerts fired since startup.
    pub fn total_alerts(&self) -> u64 {
        self.alert_count.load(Ordering::Relaxed)
    }
}
