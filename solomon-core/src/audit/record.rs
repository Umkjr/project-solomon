use serde::{Serialize, Deserialize};
use crate::audit::crypto_traits::AuditHasher;

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct AuditRecord {
    pub timestamp_utc: u64,
    pub event_id: String,
    pub route_target: String,
    pub crypto_profile: CryptoAuditMeta,
    pub localization_region: String,
    pub system_action: SystemAction,
    pub previous_hash: String,
    pub current_hash: String,
}

/// RBI G14: Ed25519-signed segment seal footer record.
/// Appended as the last JSON line in a sealed segment.
/// Proves the segment was finalized at `sealed_at_utc_us` and not backdated.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct AuditSegmentSeal {
    pub record_type: String,          // Always "SEGMENT_SEAL"
    pub segment_date: String,         // "YYYY-MM-DD"
    pub last_record_hash: String,     // last current_hash in this segment
    pub sealed_at_utc_us: u64,        // microseconds since epoch
    pub node_identity: String,        // hex-encoded 32-byte node identity hash
    pub seal_signature: String,       // hex-encoded 64-byte Ed25519 signature
}

impl AuditSegmentSeal {
    /// Bytes that the signing key signs: seal_payload = Hash(SEGMENT_SEAL || segment_date || last_record_hash || sealed_at_utc_us_be_bytes || node_identity)
    pub fn signable_payload(
        hasher: &dyn AuditHasher,
        segment_date: &str,
        last_hash: &str,
        sealed_at: u64,
        node_identity: &str,
    ) -> Vec<u8> {
        let sealed_at_bytes = sealed_at.to_be_bytes();
        hasher.hex_digest(&[
            b"SEGMENT_SEAL",
            segment_date.as_bytes(),
            last_hash.as_bytes(),
            &sealed_at_bytes,
            node_identity.as_bytes(),
        ]).into_bytes()
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct CryptoAuditMeta {
    pub algorithm_suite: String,
    pub hybrid_verified: bool,
    pub starks_proven: bool,
    pub proof_latency_ms: f64,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub enum SystemAction {
    SuccessForwarded,
    FailClosedBypassed,
    CircuitBreakerTripped,
    ValidationErrorRejected,
}

impl AuditRecord {
    /// Computes hash of the record excluding its own `current_hash`, chained with `previous_hash`.
    pub fn compute_hash(
        hasher: &dyn AuditHasher,
        timestamp_utc: u64,
        event_id: &str,
        route_target: &str,
        crypto_profile: &CryptoAuditMeta,
        localization_region: &str,
        system_action: &SystemAction,
        previous_hash: &str,
    ) -> String {
        let ts_bytes = timestamp_utc.to_le_bytes();
        let crypto_json = serde_json::to_string(crypto_profile).unwrap_or_default();
        let action_json = serde_json::to_string(system_action).unwrap_or_default();

        hasher.hex_digest(&[
            previous_hash.as_bytes(),
            &ts_bytes,
            event_id.as_bytes(),
            route_target.as_bytes(),
            crypto_json.as_bytes(),
            localization_region.as_bytes(),
            action_json.as_bytes(),
        ])
    }
}

