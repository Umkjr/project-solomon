//! RBI G5: Data Localization Enforcement (RBI Circular DPSS.CO.OD.No.2785/06.11.001/2017-18).
//! Validates that all transaction routing stays strictly within RBI-approved Indian datacenter regions.
//! Permits Indian AWS, Azure, GCP regions and RFC 1918 private banking networks.
//! Blocks any routing to non-Indian endpoints or un-regionalized public cloud buckets.

/// Approved Indian cloud datacenter regions, on-prem DC prefixes, and RFC 1918 private IP ranges.
const APPROVED_INDIA_REGIONS: &[&str] = &[
    // AWS India
    "ap-south-1", "ap-south-2",
    // GCP India
    "asia-south1", "asia-south2",
    // Azure India
    "centralindia", "southindia", "westindia",
    // On-premises Indian datacenter naming conventions
    "in-mum", "in-del", "in-blr", "in-hyd", "in-chn",
    // Approved internal private networks (RFC 1918)
    "10.", "192.168.", "172.16.", "172.17.", "172.18.", "172.19.",
    "172.20.", "172.21.", "172.22.", "172.23.", "172.24.", "172.25.",
    "172.26.", "172.27.", "172.28.", "172.29.", "172.30.", "172.31.",
    // Localhost (test only)
    "127.0.0.1", "localhost", "::1",
];

/// Non-Indian regional patterns that must never appear in routing targets.
const BLOCKED_FOREIGN_REGIONS: &[&str] = &[
    "us-east", "us-west", "us-central", "eu-west", "eu-central", "eu-north",
    "ap-northeast", "ap-southeast-1", "ap-southeast-2", "ap-southeast-3", "ap-southeast-4",
    "sa-east", "ca-central", "me-central", "af-south", "us-gov",
    ".co.uk", ".de", ".fr", ".cn", ".ru", ".jp", ".au", ".sg",
];

/// Cloud provider domains requiring an explicit approved Indian region specifier.
const CLOUD_PROVIDERS: &[&str] = &[
    "amazonaws.com", "azure.com", "googlecloud.com", "googleapis.com",
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

    // 1. Reject immediately if it contains an explicit foreign region pattern
    for pattern in BLOCKED_FOREIGN_REGIONS {
        if route_lower.contains(pattern) {
            return LocalizationResult::Rejected {
                reason: format!(
                    "RBI Data Localization Violation: route '{}' matches blocked foreign region pattern '{}'",
                    route_target, pattern
                ),
            };
        }
    }

    // 2. Check if route targets a public cloud provider
    let is_cloud_provider = CLOUD_PROVIDERS.iter().any(|provider| route_lower.contains(provider));
    if is_cloud_provider {
        // Cloud routes MUST explicitly match an approved Indian cloud region
        for approved in APPROVED_INDIA_REGIONS {
            if route_lower.contains(approved) {
                return LocalizationResult::Approved;
            }
        }
        return LocalizationResult::Rejected {
            reason: format!(
                "RBI Data Localization Violation: cloud route '{}' does not specify an approved Indian region (e.g., ap-south-1, centralindia, asia-south1)",
                route_target
            ),
        };
    }

    // 3. For private IPs and on-premises routes, verify against approved Indian endpoints
    for approved in APPROVED_INDIA_REGIONS {
        if route_lower.contains(approved) {
            return LocalizationResult::Approved;
        }
    }

    // 4. Fail-closed default
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
        // AWS Mumbai, AWS Hyderabad, Azure Central India, GCP Mumbai
        assert_eq!(check_data_localization("s3.ap-south-1.amazonaws.com"), LocalizationResult::Approved);
        assert_eq!(check_data_localization("payment-switch.ap-south-2.amazonaws.com"), LocalizationResult::Approved);
        assert_eq!(check_data_localization("centralindia.cloudapp.azure.com"), LocalizationResult::Approved);
        assert_eq!(check_data_localization("asia-south1.gcp.googlecloud.com"), LocalizationResult::Approved);
    }

    #[test]
    fn test_blocked_non_india_routes() {
        assert!(matches!(check_data_localization("us-east-1.compute.amazonaws.com"), LocalizationResult::Rejected { .. }));
        assert!(matches!(check_data_localization("eu-west-1.azure.com"), LocalizationResult::Rejected { .. }));
        assert!(matches!(check_data_localization("api.example.co.uk"), LocalizationResult::Rejected { .. }));
        // Generic un-regionalized cloud endpoint must be rejected
        assert!(matches!(check_data_localization("s3.amazonaws.com"), LocalizationResult::Rejected { .. }));
    }
}
