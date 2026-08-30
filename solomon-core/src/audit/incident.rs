//! RBI G4: Structured Incident Response Log.
//! Every security anomaly alert is persisted here as a separate NDJSON record
//! for use during RBI CSITE examination and forensic investigation.

use serde::{Serialize, Deserialize};
use std::fs::{OpenOptions, create_dir_all};
use std::io::Write;
use std::path::PathBuf;
use std::sync::Mutex;

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct IncidentRecord {
    pub incident_id: String,          // UUID / identifier
    pub alert_key: String,            // e.g. "BURST_FAILURE"
    pub message: String,
    pub severity: String,             // "LOW" | "MEDIUM" | "HIGH" | "CRITICAL"
    pub detected_at_utc_secs: u64,
    pub route_target: Option<String>,
    pub responder: Option<String>,    // Set if human acknowledged
    pub resolved_at_utc_secs: Option<u64>,
    pub notes: Option<String>,
}

pub struct IncidentLogger {
    file: Mutex<std::fs::File>,
}

impl IncidentLogger {
    pub fn new(log_dir: PathBuf) -> Self {
        create_dir_all(&log_dir).expect("Cannot create incident log directory");
        let path = log_dir.join("solomon_incidents.ndjson");
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .expect("Cannot open incident log file");
        Self { file: Mutex::new(file) }
    }

    /// Record a new detected incident.
    pub fn record(&self, incident: &IncidentRecord) {
        if let Ok(json) = serde_json::to_string(incident) {
            if let Ok(mut f) = self.file.lock() {
                let _ = writeln!(f, "{}", json);
                let _ = f.flush();
            }
        }
    }
}
