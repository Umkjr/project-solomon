#![cfg(feature = "proxy")]
//! Automated Tests for CycloneDX 1.6 Cryptography Bill of Materials (CBOM) Generator.

use solomon_core::cbom::{generate_cbom, generate_cbom_json};

#[test]
fn test_cbom_schema_and_component_structure() {
    let cbom = generate_cbom();

    // Verify CycloneDX 1.6 Schema Properties
    assert_eq!(cbom.bom_format, "CycloneDX");
    assert_eq!(cbom.spec_version, "1.6");
    assert!(cbom.schema.contains("bom-1.6.schema.json"));
    assert_eq!(cbom.version, 1);

    // Verify Root Component
    assert_eq!(cbom.metadata.component.name, "Project-Solomon-Post-Quantum-Switch");
    assert_eq!(cbom.metadata.component.component_type, "application");

    // Verify Cryptographic Components
    let component_names: Vec<String> = cbom.components.iter().map(|c| c.name.clone()).collect();
    assert!(component_names.contains(&"ML-DSA-65".to_string()));
    assert!(component_names.contains(&"SHAKE-256".to_string()));
    assert!(component_names.contains(&"Ed25519".to_string()));
    assert!(component_names.contains(&"Hardware-Side-Channel-Hardening".to_string()));

    // Verify ML-DSA-65 Specifics
    let mldsa = cbom.components.iter().find(|c| c.name == "ML-DSA-65").unwrap();
    assert_eq!(mldsa.crypto_properties.standard, "NIST FIPS 204");
    assert_eq!(mldsa.crypto_properties.security_level, Some(3));
    let params = mldsa.crypto_properties.parameters.as_ref().unwrap();
    assert_eq!(params["q"], 8380417);
    assert_eq!(params["k"], 6);
    assert_eq!(params["l"], 5);
    assert_eq!(params["gamma1"], 524288);
    assert_eq!(params["gamma2"], 261888);
    assert_eq!(params["tau"], 49);

    let key_lengths = mldsa.crypto_properties.key_lengths.as_ref().unwrap();
    assert_eq!(key_lengths["publicKeyBytes"], 1952);
    assert_eq!(key_lengths["secretKeyBytes"], 4032);
    assert_eq!(key_lengths["signatureBytes"], 3309);
}

#[test]
fn test_cbom_json_serialization_validity() {
    let json_str = generate_cbom_json();
    assert!(!json_str.is_empty());

    let parsed: serde_json::Value = serde_json::from_str(&json_str).expect("CBOM JSON should be valid parseable JSON");
    assert_eq!(parsed["bomFormat"], "CycloneDX");
    assert_eq!(parsed["specVersion"], "1.6");
    assert!(parsed["components"].is_array());
    assert!(parsed["components"].as_array().unwrap().len() >= 4);
}
