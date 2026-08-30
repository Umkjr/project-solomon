//! RBI G5: Data Localization Enforcement.
//! Validates that all transaction routing stays within RBI-approved Indian datacenter regions.
//! Blocks any config update that routes to non-Indian endpoints.

/// Approved Indian cloud datacenter hostname suffixes or IP ranges.
const APPROVED_INDIA_REGIONS: &[&str] = &[
    // Mumbai datacenter patterns
    "in-mum", "asia-south1", "ap-south-1",
    // Approved internal private networks (RFC 1918)
    "10.", "192.168.", "172.16.", "172.17.", "172.18.", "172.19.",
    "172.20.", "172.21.", "172.22.", "172.23.", "172.24.", "172.25.",
    "172.26.", "172.27.", "172.28.", "172.29.", "172.30.", "172.31.",
    // Localhost (test only)
    "127.0.0.1", "localhost", "::1",
];

/// Non-Indian patterns that must never appear in routing targets.
/// Reject immediately if matched.
const BLOCKED_NON_INDIA_PATTERNS: &[&str] = &[
    "us-east", "us-west", "eu-west", "eu-central", "ap-northeast",
    "ap-southeast-2", "sa-east", "ca-central", "us-gov",
    "amazonaws.com", "azure.com", "googlecloud.com",
];

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum LocalizationResult {
    Approved,
    Rejected { reason: String },
}

/// Returns `Approved` if the given route_target URL/hostname/IP is permitted under RBI data localization rules.
/// Returns `Rejected` with a human-readable reason if it would route data outside India.
pub fn check_data_localization(route_target: &str) -> LocalizationResult {
    let route_lower = route_target.to_lowercase();

    // First: check for known blocked non-India patterns
    for pattern in BLOCKED_NON_INDIA_PATTERNS {
        if route_lower.contains(pattern) {
            return LocalizationResult::Rejected {
                reason: format!(
                    "RBI Data Localization Violation: route '{}' matches blocked non-India pattern '{}'",
                    route_target, pattern
                ),
            };
        }
    }

    // Second: check if it matches at least one approved India region
    for approved in APPROVED_INDIA_REGIONS {
        if route_lower.contains(approved) {
            return LocalizationResult::Approved;
        }
    }

    // Fallback: if neither approved nor explicitly blocked, default to REJECT (fail-closed for RBI)
    LocalizationResult::Rejected {
        reason: format!(
            "RBI Data Localization: route '{}' does not match any approved Indian datacenter pattern — rejected (fail-closed)",
            route_target
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_approved_india_routes() {
        assert_eq!(check_data_localization("10.0.1.5:8080"), LocalizationResult::Approved);
        assert_eq!(check_data_localization("192.168.1.100:9000"), LocalizationResult::Approved);
        assert_eq!(check_data_localization("127.0.0.1:8080"), LocalizationResult::Approved);
        assert_eq!(check_data_localization("asia-south1.internal.bank.in"), LocalizationResult::Approved);
    }

    #[test]
    fn test_blocked_non_india_routes() {
        assert!(matches!(check_data_localization("us-east-1.compute.amazonaws.com"), LocalizationResult::Rejected { .. }));
        assert!(matches!(check_data_localization("eu-west-1.azure.com"), LocalizationResult::Rejected { .. }));
        assert!(matches!(check_data_localization("api.example.co.uk"), LocalizationResult::Rejected { .. }));
    }
}
