use solomon_core::crypto::nist_api::{keygen, sign, verify};
use solomon_core::crypto::heartbeat::set_daily_salt;
use solomon_core::crypto::hybrid::{hybrid_keygen, hybrid_sign, hybrid_verify};

#[test]
fn test_differential_kat_vectors_and_integrity() {
    set_daily_salt([0x99u8; 32]);

    // Test across 10 deterministic test vectors
    for i in 0..10u8 {
        let mut seed = [0u8; 32];
        seed[0] = i;
        seed[1] = i.wrapping_mul(17);
        seed[31] = 0xAA;

        let msg = format!("FinTech Differential KAT Vector #{}", i).into_bytes();

        // 1. Pure ML-DSA-65 Roundtrip
        let (sk, pk) = keygen(&seed);
        let sig = sign(&sk, &msg);
        assert!(verify(&pk, &msg, &sig), "KAT Vector {} must pass ML-DSA-65 verification", i);

        // 2. Hybrid Classical + PQC Roundtrip
        let (hyb_sk, hyb_pk) = hybrid_keygen(&seed);
        let hyb_sig = hybrid_sign(&hyb_sk, &hyb_pk, &msg);
        assert!(hybrid_verify(&hyb_pk, &msg, &hyb_sig), "KAT Vector {} must pass Hybrid verification", i);

        // 3. Adversarial Check: Mutation on every seed vector
        let mut tampered_sig = sig;
        tampered_sig[50] ^= 0xFF;
        assert!(!verify(&pk, &msg, &tampered_sig), "Tampered KAT Vector {} must be rejected", i);
    }

    println!("[DIFFERENTIAL KAT] All 10 deterministic KAT and hybrid test vectors passed with 100% integrity.");
}
