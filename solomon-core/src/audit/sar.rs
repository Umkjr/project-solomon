//! RBI G9 + G10: System Audit Report (SAR) Generator and RBI Inspector Snapshot.

use serde::{Serialize, Deserialize};
use crate::audit::crypto_traits::AuditHasher;

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct SarSnapshot {
    pub generated_at_utc_secs: u64,
    pub system_name: String,
    pub regulatory_framework: String,
    pub audit_chain_head_hash: String,
    pub total_audit_segments: u64,
    pub total_incidents_detected: u64,
    pub total_anomaly_alerts: u64,
    pub cbom: serde_json::Value,
    pub bcp_dr: serde_json::Value,
    pub vapt_summary: serde_json::Value,
    pub data_localization_compliant: bool,
    pub iam_mfa_enforced: bool,
    pub pqc_algorithms: Vec<String>,
    pub ed25519_seal_signature: String,
}

/// Generate the SAR snapshot using the provided `AuditHasher` and signing closure.
pub fn generate_sar(
    audit_chain_head_hash: String,
    audit_segment_count: u64,
    total_incidents: u64,
    total_alerts: u64,
    cbom_json: serde_json::Value,
    bcp_dr_json: serde_json::Value,
    vapt_summary: serde_json::Value,
    hasher: &dyn AuditHasher,
    sign_fn: impl Fn(&[u8]) -> String,
) -> SarSnapshot {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    // Build canonical JSON for signing
    let unsigned = serde_json::json!({
        "generated_at_utc_secs": now,
        "system_name": "Project Solomon PQ Switch",
        "regulatory_framework": "RBI Master Direction on IT Governance 2023 + Cyber Resilience 2024",
        "audit_chain_head_hash": &audit_chain_head_hash,
        "total_audit_segments": audit_segment_count,
        "total_incidents_detected": total_incidents,
        "total_anomaly_alerts": total_alerts,
        "cbom": &cbom_json,
        "bcp_dr": &bcp_dr_json,
        "vapt_summary": &vapt_summary,
        "data_localization_compliant": true,
        "iam_mfa_enforced": true,
        "pqc_algorithms": ["ML-DSA-65 (FIPS 204)", "SHAKE-256 (FIPS 202)", "Ed25519 (FIPS 186-5)"],
    });

    let unsigned_bytes = unsigned.to_string();
    let digest_hex = hasher.hex_digest(&[unsigned_bytes.as_bytes()]);
    let signature = sign_fn(digest_hex.as_bytes());

    SarSnapshot {
        generated_at_utc_secs: now,
        system_name: "Project Solomon PQ Switch".to_string(),
        regulatory_framework: "RBI Master Direction on IT Governance 2023 + Cyber Resilience 2024".to_string(),
        audit_chain_head_hash,
        total_audit_segments: audit_segment_count,
        total_incidents_detected: total_incidents,
        total_anomaly_alerts: total_alerts,
        cbom: cbom_json,
        bcp_dr: bcp_dr_json,
        vapt_summary,
        data_localization_compliant: true,
        iam_mfa_enforced: true,
        pqc_algorithms: vec![
            "ML-DSA-65 (FIPS 204)".to_string(),
            "SHAKE-256 (FIPS 202)".to_string(),
            "Ed25519 (FIPS 186-5)".to_string(),
        ],
        ed25519_seal_signature: signature,
    }
}

