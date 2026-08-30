use solomon_core::crypto::hybrid::{
    hybrid_keygen, hybrid_sign, hybrid_verify, HybridPublicKey, HybridSignature,
    HYBRID_PUBLIC_KEY_SIZE, HYBRID_SIGNATURE_SIZE,
};
use solomon_core::crypto::heartbeat::set_daily_salt;

#[test]
fn test_hybrid_classical_pqc_signing_and_verification() {
    set_daily_salt([0x77u8; 32]);
    let seed = [0x42u8; 32];
    let (sk, pk) = hybrid_keygen(&seed);
    let msg = b"FinTech High-Value Hybrid Transfer INR 10,00,000 via Dual-Signature";

    // 1. Check Key Sizes
    let pk_bytes = pk.to_bytes();
    assert_eq!(pk_bytes.len(), HYBRID_PUBLIC_KEY_SIZE);
    assert_eq!(HYBRID_PUBLIC_KEY_SIZE, 32 + 1952);

    let reconstructed_pk = HybridPublicKey::from_bytes(&pk_bytes);
    assert_eq!(pk, reconstructed_pk);

    // 2. Sign message with mutual composite binding
    let start_sign = std::time::Instant::now();
    let sig = hybrid_sign(&sk, &pk, msg);
    let sign_latency = start_sign.elapsed();

    let sig_bytes = sig.to_bytes();
    assert_eq!(sig_bytes.len(), HYBRID_SIGNATURE_SIZE);
    assert_eq!(HYBRID_SIGNATURE_SIZE, 64 + 3309);

    let reconstructed_sig = HybridSignature::from_bytes(&sig_bytes);
    assert_eq!(sig, reconstructed_sig);

    // 3. Verify legitimate hybrid signature
    let start_verify = std::time::Instant::now();
    let is_valid = hybrid_verify(&pk, msg, &sig);
    let verify_latency = start_verify.elapsed();

    println!("\n=======================================================");
    println!("     Mutual Hybrid Classical (Ed25519) + PQC (ML-DSA)  ");
    println!("=======================================================");
    println!("  • Hybrid Keygen Size:     {} bytes (32 Ed + 1952 PQC)", HYBRID_PUBLIC_KEY_SIZE);
    println!("  • Hybrid Signature Size:  {} bytes (64 Ed + 3309 PQC)", HYBRID_SIGNATURE_SIZE);
    println!("  • Dual Signing Latency:   {:.3} ms", sign_latency.as_secs_f64() * 1000.0);
    println!("  • Dual Verify Latency:    {:.3} ms", verify_latency.as_secs_f64() * 1000.0);
    println!("  • Legitimate Verification: {}", is_valid);
    println!("=======================================================\n");

    assert!(is_valid, "Valid hybrid signature must pass verification");

    // 4. ADVERSARIAL: Corrupt Classical Ed25519 Signature
    let mut tampered_ed = sig;
    tampered_ed.ed25519_sig[10] ^= 0xFF;
    assert!(!hybrid_verify(&pk, msg, &tampered_ed), "Corrupted Ed25519 signature must fail");

    // 5. ADVERSARIAL: Corrupt Post-Quantum ML-DSA-65 Signature
    let mut tampered_pq = sig;
    tampered_pq.pq_sig[100] ^= 0xFF;
    assert!(!hybrid_verify(&pk, msg, &tampered_pq), "Corrupted ML-DSA-65 signature must fail");

    // 6. ADVERSARIAL: Anti-Stripping / Cross-PQC-Key Substitution Attack
    // An attacker replaces the PQC public key with an attacker-controlled key pk_pq_prime
    let seed_attacker = [0x99u8; 32];
    let (_sk_attacker, pk_attacker) = hybrid_keygen(&seed_attacker);
    let mut rogue_pk = pk;
    rogue_pk.pq_pk = pk_attacker.pq_pk; // Substituted PQC key
    assert!(
        !hybrid_verify(&rogue_pk, msg, &sig),
        "PQC key substitution attack must fail Ed25519 verification due to non-separable binding"
    );

    // 7. ADVERSARIAL: Anti-Stripping / Cross-Classical-Key Substitution Attack
    // An attacker replaces the Classical public key with pk_ed_prime
    let mut rogue_pk_ed = pk;
    rogue_pk_ed.ed25519_pk = pk_attacker.ed25519_pk; // Substituted Ed25519 key
    assert!(
        !hybrid_verify(&rogue_pk_ed, msg, &sig),
        "Classical key substitution attack must fail ML-DSA-65 verification due to non-separable binding"
    );

    // 8. ADVERSARIAL: Wrong Message Payload
    let wrong_msg = b"Tampered transaction payload";
    assert!(!hybrid_verify(&pk, wrong_msg, &sig), "Verification on wrong payload must fail");
}
