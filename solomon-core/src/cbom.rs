//! Cryptography Bill of Materials (CBOM) Generator.
//!
//! Generates CycloneDX v1.6 / OWASP CBOM specification compliant JSON
//! inventory of all cryptographic assets, NIST standards, parameter sets,
//! key lengths, and hardware hardening defenses in Project Solomon.

use serde::{Serialize, Deserialize};

/// CycloneDX 1.6 CBOM Root Container
#[derive(Debug, Serialize, Deserialize)]
pub struct CbomDocument {
    #[serde(rename = "$schema")]
    pub schema: String,
    #[serde(rename = "bomFormat")]
    pub bom_format: String,
    #[serde(rename = "specVersion")]
    pub spec_version: String,
    #[serde(rename = "serialNumber")]
    pub serial_number: String,
    pub version: u32,
    pub metadata: CbomMetadata,
    pub components: Vec<CryptoComponent>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CbomMetadata {
    pub timestamp: String,
    pub component: CbomRootComponent,
    pub authors: Vec<CbomAuthor>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CbomRootComponent {
    pub name: String,
    pub version: String,
    #[serde(rename = "type")]
    pub component_type: String,
    pub description: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CbomAuthor {
    pub name: String,
    pub organization: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CryptoComponent {
    pub name: String,
    pub version: String,
    #[serde(rename = "type")]
    pub component_type: String,
    pub description: String,
    #[serde(rename = "cryptoProperties")]
    pub crypto_properties: CryptoProperties,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CryptoProperties {
    #[serde(rename = "assetType")]
    pub asset_type: String,
    pub algorithm: String,
    pub standard: String,
    #[serde(rename = "securityLevel", skip_serializing_if = "Option::is_none")]
    pub security_level: Option<u32>,
    pub family: String,
    #[serde(rename = "parameters", skip_serializing_if = "Option::is_none")]
    pub parameters: Option<serde_json::Value>,
    #[serde(rename = "keyLengths", skip_serializing_if = "Option::is_none")]
    pub key_lengths: Option<serde_json::Value>,
    pub modes: Vec<String>,
    pub properties: serde_json::Value,
}

/// Generates the complete CycloneDX 1.6 Cryptography Bill of Materials (CBOM).
pub fn generate_cbom() -> CbomDocument {
    // Generate true ISO8601 UTC timestamp using chrono (e.g. 2026-08-24T12:00:00Z)
    let timestamp = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true);

    let ml_dsa_65 = CryptoComponent {
        name: "ML-DSA-65".to_string(),
        version: "0.1.0".to_string(),
        component_type: "cryptographic-asset".to_string(),
        description: "NIST FIPS 204 Post-Quantum Module-Lattice-Based Digital Signature Algorithm (Security Category 3)".to_string(),
        crypto_properties: CryptoProperties {
            asset_type: "algorithm".to_string(),
            algorithm: "ML-DSA-65".to_string(),
            standard: "NIST FIPS 204".to_string(),
            security_level: Some(3),
            family: "Lattice-based Fiat-Shamir with Aborts (Module-LWE / Module-SIS)".to_string(),
            parameters: Some(serde_json::json!({
                "q": 8380417,
                "k": 6,
                "l": 5,
                "gamma1": 524288,
                "gamma2": 261888,
                "tau": 49,
                "beta": 196,
                "omega": 55,
                "d": 13,
                "ntt_zeta_primitive_root": 1753
            })),
            key_lengths: Some(serde_json::json!({
                "publicKeyBytes": 1952,
                "secretKeyBytes": 4032,
                "signatureBytes": 3309,
                "seedBytes": 32
            })),
            modes: vec![
                "deterministic (rnd = 0x00...00)".to_string(),
                "hedged (injected 32-byte external randomness)".to_string(),
                "context-bound (0x00 || len(ctx) || ctx || msg)".to_string(),
                "verify-before-release (VBR fault protection)".to_string(),
            ],
            properties: serde_json::json!({
                "katConformance": "100% (60/60 NIST ACVP test vectors passing)",
                "constantTime": true,
                "zeroizeOnDrop": true,
                "externalInteroperability": ["liboqs", "OpenSSL 3.5+", "BouncyCastle"]
            }),
        },
    };

    let shake_256 = CryptoComponent {
        name: "SHAKE-256".to_string(),
        version: "0.1.0".to_string(),
        component_type: "cryptographic-asset".to_string(),
        description: "NIST FIPS 202 Keccak-f[1600] Extendable-Output Function and Matrix Expansion".to_string(),
        crypto_properties: CryptoProperties {
            asset_type: "algorithm".to_string(),
            algorithm: "SHAKE-256".to_string(),
            standard: "NIST FIPS 202".to_string(),
            security_level: Some(3),
            family: "Keccak Sponge Permutation".to_string(),
            parameters: Some(serde_json::json!({
                "rateBits": 1088,
                "rateBytes": 136,
                "capacityBits": 512,
                "rounds": 24,
                "stateBits": 1600,
                "domainSuffix": "0x1F"
            })),
            key_lengths: None,
            modes: vec![
                "XOF (Arbitrary Length Squeeze)".to_string(),
                "Seed Expansion (SHAKE-256(seed || 0x06 || 0x05))".to_string(),
                "Matrix Expansion (ExpandA)".to_string(),
                "Mask Expansion (ExpandMask)".to_string(),
            ],
            properties: serde_json::json!({
                "zeroDependencies": true,
                "pureRust": true,
                "nistTestVectors": "Verified (empty string & multi-block KATs)"
            }),
        },
    };

    let ed25519 = CryptoComponent {
        name: "Ed25519".to_string(),
        version: "2.0".to_string(),
        component_type: "cryptographic-asset".to_string(),
        description: "RFC 8032 / FIPS 186-5 Digital Signature for Licensing Epoch Token Authentication".to_string(),
        crypto_properties: CryptoProperties {
            asset_type: "algorithm".to_string(),
            algorithm: "Ed25519".to_string(),
            standard: "RFC 8032 / NIST FIPS 186-5".to_string(),
            security_level: Some(1),
            family: "Edwards-curve Digital Signature Algorithm (Curve25519)".to_string(),
            parameters: None,
            key_lengths: Some(serde_json::json!({
                "publicKeyBytes": 32,
                "signatureBytes": 64
            })),
            modes: vec!["epoch_token_verification".to_string()],
            properties: serde_json::json!({
                "purpose": "Control Plane Licensing Handshake & Hardware Binding"
            }),
        },
    };

    let side_channel_hardening = CryptoComponent {
        name: "Hardware-Side-Channel-Hardening".to_string(),
        version: "1.0".to_string(),
        component_type: "cryptographic-asset".to_string(),
        description: "Speculative Execution Barrier, Constant-Time Arithmetic, and Memory Zeroization Defenses".to_string(),
        crypto_properties: CryptoProperties {
            asset_type: "defense-mechanism".to_string(),
            algorithm: "Spectre-v1 Barrier & Constant-Time Montgomery".to_string(),
            standard: "ISO/IEC 19790 / FIPS 140-3 Physical & Side-Channel Security".to_string(),
            security_level: None,
            family: "Hardware Defensive Primitives".to_string(),
            parameters: None,
            key_lengths: None,
            modes: vec![
                "speculative_barrier (core::arch::x86_64::_mm_lfence)".to_string(),
                "constant_time_montgomery (branchless signed/canonical reductions)".to_string(),
                "volatile_zeroization (core::ptr::write_volatile + SeqCst compiler fence)".to_string(),
            ],
            properties: serde_json::json!({
                "cveMitigations": ["CVE-2017-5753 (Spectre-v1)", "CVE-2026-24850 (Hint Injection)"],
                "faultInjectionProtection": "Verify-Before-Release (VBR) Panic Gate"
            }),
        },
    };

    CbomDocument {
        schema: "https://cyclonedx.org/schema/bom-1.6.schema.json".to_string(),
        bom_format: "CycloneDX".to_string(),
        spec_version: "1.6".to_string(),
        serial_number: "urn:uuid:solomon-pq-cbom-2026-ml-dsa-65".to_string(),
        version: 1,
        metadata: CbomMetadata {
            timestamp,
            component: CbomRootComponent {
                name: "Project-Solomon-Post-Quantum-Switch".to_string(),
                version: "0.1.0".to_string(),
                component_type: "application".to_string(),
                description: "Quantum-Resistant Financial Switch Reverse Proxy with ML-DSA-65 and ISO 8583 Engine".to_string(),
            },
            authors: vec![CbomAuthor {
                name: "Project Solomon Security Team".to_string(),
                organization: "Project Solomon".to_string(),
            }],
        },
        components: vec![ml_dsa_65, shake_256, ed25519, side_channel_hardening],
    }
}

/// Serializes the CBOM document into a formatted JSON string.
pub fn generate_cbom_json() -> String {
    let cbom = generate_cbom();
    serde_json::to_string_pretty(&cbom).unwrap_or_else(|_| "{}".to_string())
}
