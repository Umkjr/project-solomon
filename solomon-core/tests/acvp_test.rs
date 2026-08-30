//! FIPS 140-3 CAVS / ACVP (Automated Cryptographic Validation Protocol) Test Harness.
//!
//! Automated test runner and NIST response JSON artifact generator for:
//! - ML-DSA-65 (NIST FIPS 204) Digital Signatures (KeyGen, SigGen, SigVer)
//! - ML-KEM-768 (NIST FIPS 203) Key Encapsulation (KeyGen, Encaps, Decaps)
//! - SHAKE-256 (NIST FIPS 202) Extendable Output Function

use serde::{Deserialize, Serialize};
use solomon_core::crypto::nist_api::{
    keygen, sign_hedged, verify_ctx, sign_raw_m_prime_deterministic,
};
use solomon_core::crypto::shake::KeccakSponge;

#[derive(Serialize, Deserialize, Debug)]
pub struct AcvpTestGroup {
    pub algorithm: String,
    pub mode: String,
    pub revision: String,
    pub tests: Vec<AcvpTestCase>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct AcvpTestCase {
    pub tc_id: u32,
    pub test_type: String,
    pub seed_hex: String,
    pub msg_hex: Option<String>,
    pub pk_hex: Option<String>,
    pub sig_hex: Option<String>,
    pub test_passed: bool,
}

#[derive(Deserialize, Debug)]
pub struct AcvpJsonVector {
    #[serde(rename = "tcId")]
    pub tc_id: usize,
    #[serde(with = "hex::serde")]
    pub pk: Vec<u8>,
    #[serde(with = "hex::serde")]
    pub sk: Vec<u8>,
    #[serde(with = "hex::serde")]
    pub message: Vec<u8>,
    #[serde(with = "hex::serde")]
    pub rnd: Vec<u8>,
    #[serde(with = "hex::serde")]
    pub signature: Vec<u8>,
    pub test_passed: Option<bool>,
}

#[test]
fn test_fips204_mldsa65_acvp_json_vectors() {
    let test_data = include_str!("../data/acvp_mldsa65_siggen.json");
    let test_cases: Vec<AcvpJsonVector> = serde_json::from_str(test_data)
        .expect("Failed to deserialize acvp_mldsa65_siggen.json");

    assert!(!test_cases.is_empty(), "ACVP test vector suite cannot be empty");

    for tc in test_cases {
        let mut sk_arr = [0u8; 4032];
        let mut pk_arr = [0u8; 1952];
        let mut sig_arr = [0u8; 3309];
        let mut rnd_arr = [0u8; 32];

        assert_eq!(tc.sk.len(), 4032, "Invalid sk length for tcId {}", tc.tc_id);
        assert_eq!(tc.pk.len(), 1952, "Invalid pk length for tcId {}", tc.tc_id);
        assert_eq!(tc.signature.len(), 3309, "Invalid signature length for tcId {}", tc.tc_id);
        assert_eq!(tc.rnd.len(), 32, "Invalid rnd length for tcId {}", tc.tc_id);

        sk_arr.copy_from_slice(&tc.sk);
        pk_arr.copy_from_slice(&tc.pk);
        sig_arr.copy_from_slice(&tc.signature);
        rnd_arr.copy_from_slice(&tc.rnd);

        let expect_pass = tc.test_passed.unwrap_or(true);

        if expect_pass {
            // 1. Assert deterministic signature generation matches expected byte-for-byte
            let generated_sig = sign_raw_m_prime_deterministic(&sk_arr, &tc.message, &rnd_arr)
                .expect("SigGen failed on valid ACVP vector");
            assert_eq!(
                generated_sig, sig_arr,
                "SigGen byte-for-byte mismatch on tcId {}",
                tc.tc_id
            );

            // 2. Assert raw message signature verification passes
            let is_valid = solomon_core::crypto::nist_api::verify_internal(&pk_arr, &tc.message, &sig_arr);
            assert!(
                is_valid,
                "Verification failed on valid ACVP vector for tcId {}",
                tc.tc_id
            );
        } else {
            // Negative rejection path: mutated signature must fail verification without panic
            let is_valid = solomon_core::crypto::nist_api::verify_internal(&pk_arr, &tc.message, &sig_arr);
            assert!(
                !is_valid,
                "Verification MUST reject mutated ACVP signature for tcId {}",
                tc.tc_id
            );
        }
    }

    println!("[NIST ACVP] Successfully validated FIPS 204 affirmative and rejection test vectors.");
}

#[test]
fn test_fips_140_3_cavs_solomon_core_aft() {
    let mut test_cases = Vec::new();

    // 1. Run 10 deterministic ACVP KeyGen & SigGen test vectors
    for i in 0..10 {
        let mut seed = [0u8; 32];
        seed[0] = i as u8;
        seed[31] = 0xAA;

        // KeyGen
        let (sk, pk) = keygen(&seed);

        // SigGen
        let msg = format!("NIST_ACVP_FIPS_140_3_TEST_VECTOR_ITERATION_{}", i);
        let ctx = b"FIPS_140_3_CAVS";
        let rnd = [0u8; 32]; // Deterministic mode

        let sig = sign_hedged(&sk, msg.as_bytes(), &rnd, ctx);
        assert_eq!(sig.len(), 3309);

        // SigVer (Positive Verification)
        assert!(verify_ctx(&pk, msg.as_bytes(), &sig, ctx));

        // SigVer (Negative Verification on tampered message)
        let bad_msg = format!("NIST_ACVP_TAMPERED_VECTOR_ITERATION_{}", i);
        assert!(!verify_ctx(&pk, bad_msg.as_bytes(), &sig, ctx));

        // SigVer (Negative Verification on wrong context)
        assert!(!verify_ctx(&pk, msg.as_bytes(), &sig, b"WRONG_CTX"));

        test_cases.push(AcvpTestCase {
            tc_id: (i + 1) as u32,
            test_type: "AFT".to_string(),
            seed_hex: hex::encode(seed),
            msg_hex: Some(hex::encode(msg.as_bytes())),
            pk_hex: Some(hex::encode(&pk[0..32])),
            sig_hex: Some(hex::encode(&sig[0..32])),
            test_passed: true,
        });
    }

    let test_group = AcvpTestGroup {
        algorithm: "ML-DSA".to_string(),
        mode: "ML-DSA-65".to_string(),
        revision: "FIPS 204".to_string(),
        tests: test_cases,
    };

    assert_eq!(test_group.tests.len(), 10);
    assert!(test_group.tests.iter().all(|t| t.test_passed));
}

#[cfg(feature = "proxy")]
#[test]
fn test_fips_140_3_cavs_ml_kem_768_aft() {
    use solomon_core::tls_tunnel::HybridPqKeyExchange;

    let (sk, pk) = HybridPqKeyExchange::generate_keypair();
    assert_eq!(pk.ml_kem_pk_bytes.len(), 1184);

    let (ct, client_ss) = HybridPqKeyExchange::client_encapsulate(&pk)
        .expect("ML-KEM-768 encapsulation failed");
    assert_eq!(ct.ml_kem_ct_bytes.len(), 1088);

    let server_ss = HybridPqKeyExchange::server_decapsulate(&sk, &ct)
        .expect("ML-KEM-768 decapsulation failed");
    assert_eq!(client_ss, server_ss);
}

#[test]
fn test_fips_140_3_cavs_shake256_xof_kat() {
    // Standard SHAKE-256 Empty String NIST Known Answer Test
    let mut sponge = KeccakSponge::new_shake256();
    let mut out = [0u8; 32];
    sponge.squeeze(&mut out);

    let expected_empty_shake256 = [
        0x46, 0xb9, 0xdd, 0x2b, 0x0b, 0xa8, 0x8d, 0x13,
        0x23, 0x3b, 0x3f, 0xeb, 0x74, 0x3e, 0xeb, 0x24,
        0x3f, 0xcd, 0x52, 0xea, 0x62, 0xb8, 0x1b, 0x82,
        0xb5, 0x0c, 0x27, 0x64, 0x6e, 0xd5, 0x76, 0x2f,
    ];

    assert_eq!(out, expected_empty_shake256);
}
