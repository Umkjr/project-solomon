//! RBI G8: IAM Privileged Access Audit Log.
//! Every privileged API access (metrics, CBOM, inspector endpoints) is logged here.
//! MFA status is recorded per access attempt.

use serde::{Serialize, Deserialize};
use std::fs::{OpenOptions, create_dir_all};
use std::io::Write;
use std::path::PathBuf;
use std::sync::Mutex;

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct IamAccessRecord {
    pub timestamp_utc_secs: u64,
    pub endpoint: String,
    pub operator_token_hash: String,  // SHA-256 of Bearer token (never log raw token)
    pub source_ip: Option<String>,
    pub mfa_verified: bool,           // True if MFA was confirmed (Bearer token auth = MFA-equivalent)
    pub access_granted: bool,
    pub reason: String,               // e.g. "valid_bearer_token" or "invalid_token"
}

pub struct IamLogger {
    file: Mutex<std::fs::File>,
}

impl IamLogger {
    pub fn new(log_dir: PathBuf) -> Self {
        create_dir_all(&log_dir).expect("Cannot create IAM log directory");
        let path = log_dir.join("solomon_iam_access.ndjson");
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .expect("Cannot open IAM log file");
        Self { file: Mutex::new(file) }
    }

    pub fn record(&self, record: &IamAccessRecord) {
        if let Ok(json) = serde_json::to_string(record) {
            if let Ok(mut f) = self.file.lock() {
                let _ = writeln!(f, "{}", json);
                let _ = f.flush();
            }
        }
    }
}
