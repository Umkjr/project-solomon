//! RBI G7: VAPT Finding Tracker.
//! Maintains a structured, append-only registry of security findings from
//! CERT-In empanelled auditors. Required for annual SAR submission.

use serde::{Serialize, Deserialize};

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub enum VaptSeverity { Critical, High, Medium, Low, Informational }

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub enum VaptStatus { Open, InRemediation, Closed, Accepted }

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct VaptFinding {
    pub finding_id: String,            // Auditor-assigned ID
    pub title: String,
    pub description: String,
    pub severity: VaptSeverity,
    pub status: VaptStatus,
    pub affected_component: String,
    pub cve_id: Option<String>,
    pub detected_at_utc_secs: u64,
    pub remediation_deadline_utc_secs: Option<u64>,
    pub closed_at_utc_secs: Option<u64>,
    pub auditor_name: String,          // CERT-In auditor firm name
    pub cert_in_empanelled: bool,
    pub notes: Option<String>,
}

/// In-memory VAPT registry.
pub struct VaptRegistry {
    findings: Vec<VaptFinding>,
}

impl Default for VaptRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl VaptRegistry {
    pub fn new() -> Self {
        Self { findings: Vec::new() }
    }

    pub fn add_finding(&mut self, finding: VaptFinding) {
        self.findings.push(finding);
    }

    pub fn open_findings(&self) -> Vec<&VaptFinding> {
        self.findings.iter()
            .filter(|f| f.status == VaptStatus::Open || f.status == VaptStatus::InRemediation)
            .collect()
    }

    pub fn all_findings(&self) -> &[VaptFinding] {
        &self.findings
    }

    pub fn summary(&self) -> serde_json::Value {
        let open = self.findings.iter().filter(|f| f.status == VaptStatus::Open).count();
        let in_rem = self.findings.iter().filter(|f| f.status == VaptStatus::InRemediation).count();
        let closed = self.findings.iter().filter(|f| f.status == VaptStatus::Closed).count();
        let critical_open = self.findings.iter()
            .filter(|f| f.severity == VaptSeverity::Critical && f.status == VaptStatus::Open)
            .count();
        serde_json::json!({
            "total": self.findings.len(),
            "open": open,
            "in_remediation": in_rem,
            "closed": closed,
            "critical_open": critical_open,
        })
    }
}
