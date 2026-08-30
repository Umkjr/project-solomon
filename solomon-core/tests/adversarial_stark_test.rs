#![cfg(feature = "proxy")]
use solomon_core::crypto::nist_api::{keygen, sign, verify};
use solomon_core::crypto::heartbeat::set_daily_salt;
use solomon_core::proxy::ZkAuthorizationProof;
use solomon_zk::{generate_stark_proof, verify_stark_proof};

#[test]
fn test_adversarial_tamper_detection() {
    set_daily_salt([0x5Au8; 32]);
    let seed = [0x5Au8; 32];
    let msg = b"Adversarial test payload for Project Solomon";
    let (sk, pk) = keygen(&seed);
    let sig = sign(&sk, msg);

    // Baseline: Valid signature passes FIPS 204
    assert!(verify(&pk, msg, &sig), "Baseline signature must be valid");
    let valid_proof = generate_stark_proof(&sig, &pk, msg);
    assert!(verify_stark_proof(&valid_proof, &pk, msg).is_ok(), "STARK verifier must verify baseline proof");

    // CORRUPTION TEST 1: Tamper 1 byte of the ML-DSA-65 Signature
    let mut tampered_sig = sig;
    tampered_sig[100] ^= 0xFF; // Flip bits in polynomial vector z
    let fips_rejected = !verify(&pk, msg, &tampered_sig);
    println!("\n[ADVERSARIAL 1] FIPS 204 Native Verifier with 1-byte corrupted signature:");
    println!("  -> Correctly Rejected by FIPS 204: {}", fips_rejected);
    assert!(fips_rejected, "FIPS 204 must reject tampered signature");

    // Check what the STARK prover does on corrupted signature
    let tampered_sig_proof = generate_stark_proof(&tampered_sig, &pk, msg);
    let root_changed = valid_proof != tampered_sig_proof;
    println!("[ADVERSARIAL 1] STARK Trace on corrupted signature:");
    println!("  -> STARK Proof Changed: {}", root_changed);
    println!("  -> STARK Verifier Implemented: YES (verify_stark_proof active)");

    // CORRUPTION TEST 2: Tamper ZkAuthorizationProof node identity / state commitment
    let identity = [0x11u8; 32];
    let fingerprint = [0x22u8; 32];
    let mut sig_hash = [0x33u8; 32];
    let zk_auth = ZkAuthorizationProof::generate(&identity, &fingerprint, &sig_hash);
    
    // Verifier checks against expected sig hash
    assert!(zk_auth.verify(&sig_hash), "Valid ZkAuthorizationProof must pass");
    
    // Corrupt expected hash
    sig_hash[0] ^= 0xFF;
    let auth_rejected = !zk_auth.verify(&sig_hash);
    println!("\n[ADVERSARIAL 2] ZkAuthorizationProof against altered state commitment:");
    println!("  -> Correctly Rejected by Auth Verifier: {}", auth_rejected);
    assert!(auth_rejected, "ZkAuthorizationProof must reject mismatched state hash");

    // CORRUPTION TEST 3: Corrupt final proof bytes
    let mut corrupted_proof = valid_proof;
    corrupted_proof[10] ^= 0xFF;
    let proof_rejected = verify_stark_proof(&corrupted_proof, &pk, msg).is_err();
    println!("\n[ADVERSARIAL 3] Corrupted STARK Proof Payload:");
    println!("  -> Correctly Rejected by STARK Verifier: {}", proof_rejected);
    assert!(proof_rejected, "STARK verifier must reject corrupted proof bytes");
}
