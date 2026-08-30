use solomon_core::crypto::nist_api::{keygen, sign, verify};
use solomon_zk::{generate_stark_proof, verify_stark_proof, StarkProof, GOLDILOCKS_PRIME};

#[test]
fn test_adversarial_comprehensive_suite() {
    let seed_a = [0x42u8; 32];
    let (sk_a, pk_a) = keygen(&seed_a);

    let seed_b = [0x99u8; 32];
    let (_sk_b, pk_b) = keygen(&seed_b);

    let msg = b"Transaction authorization payload: INR 2,50,000 to Account 9876543210".to_vec();
    let valid_sig = sign(&sk_a, &msg);

    // Baseline check
    assert!(verify(&pk_a, &msg, &valid_sig), "Baseline valid signature must verify");

    println!("\n=======================================================");
    println!("     Section 5: Comprehensive Adversarial Tamper       ");
    println!("=======================================================");

    // 5a. Signature corruption
    // Corrupt byte 0
    let mut sig_corrupt_0 = valid_sig;
    sig_corrupt_0[0] ^= 0xFF;
    let res_5a_0 = verify(&pk_a, &msg, &sig_corrupt_0);
    println!("5a. Corrupt Signature Byte 0:    verify() = {} (REJECTED: {})", res_5a_0, !res_5a_0);
    assert!(!res_5a_0);

    // Corrupt byte 1000
    let mut sig_corrupt_1000 = valid_sig;
    sig_corrupt_1000[1000] ^= 0xFF;
    let res_5a_1000 = verify(&pk_a, &msg, &sig_corrupt_1000);
    println!("5a. Corrupt Signature Byte 1000: verify() = {} (REJECTED: {})", res_5a_1000, !res_5a_1000);
    assert!(!res_5a_1000);

    // Corrupt byte 3308
    let mut sig_corrupt_3308 = valid_sig;
    sig_corrupt_3308[3308] ^= 0xFF;
    let res_5a_3308 = verify(&pk_a, &msg, &sig_corrupt_3308);
    println!("5a. Corrupt Signature Byte 3308: verify() = {} (REJECTED: {})", res_5a_3308, !res_5a_3308);
    assert!(!res_5a_3308);

    // 5b. Public key corruption
    // Corrupt byte 0
    let mut pk_corrupt_0 = pk_a;
    pk_corrupt_0[0] ^= 0xFF;
    let res_5b_0 = verify(&pk_corrupt_0, &msg, &valid_sig);
    println!("5b. Corrupt Public Key Byte 0:   verify() = {} (REJECTED: {})", res_5b_0, !res_5b_0);
    assert!(!res_5b_0);

    // Corrupt byte 500
    let mut pk_corrupt_500 = pk_a;
    pk_corrupt_500[500] ^= 0xFF;
    let res_5b_500 = verify(&pk_corrupt_500, &msg, &valid_sig);
    println!("5b. Corrupt Public Key Byte 500: verify() = {} (REJECTED: {})", res_5b_500, !res_5b_500);
    assert!(!res_5b_500);

    // 5c. Message corruption
    let mut msg_corrupt = msg.clone();
    msg_corrupt[5] ^= 0xFF;
    let res_5c = verify(&pk_a, &msg_corrupt, &valid_sig);
    println!("5c. Corrupt Message (1 byte):    verify() = {} (REJECTED: {})", res_5c, !res_5c);
    assert!(!res_5c);

    // 5d. STARK proof corruption
    let proof_bytes = generate_stark_proof(&valid_sig, &pk_a, &msg);
    let valid_stark_res = verify_stark_proof(&proof_bytes, &pk_a, &msg);
    println!("5d. Baseline STARK proof:        verify_stark_proof() = {:?}", valid_stark_res);
    assert_eq!(valid_stark_res, Ok(true));

    // Corrupt byte 0 of proof bytes
    let mut proof_corrupt_0 = proof_bytes.clone();
    proof_corrupt_0[0] ^= 0xFF;
    let res_5d_0 = verify_stark_proof(&proof_corrupt_0, &pk_a, &msg);
    println!("5d. Corrupt Proof Byte 0:        verify_stark_proof() = {:?} (REJECTED: {})", res_5d_0, res_5d_0.is_err());
    assert!(res_5d_0.is_err());

    // Corrupt Merkle root bytes in structured proof
    let mut stark_struct: StarkProof = serde_json::from_slice(&proof_bytes).unwrap();
    stark_struct.trace_root = [0u8; 32];
    let proof_corrupt_root = serde_json::to_vec(&stark_struct).unwrap();
    let res_5d_root = verify_stark_proof(&proof_corrupt_root, &pk_a, &msg);
    println!("5d. Nullified Merkle Root:       verify_stark_proof() = {:?} (REJECTED: {})", res_5d_root, res_5d_root.is_err());
    assert!(res_5d_root.is_err());

    // Corrupt FRI constant / final_poly
    let mut stark_struct_fri = stark_struct.clone();
    stark_struct_fri.trace_root = [0xAA; 32];
    stark_struct_fri.fri_proof.final_poly.0 = GOLDILOCKS_PRIME + 42;
    let proof_corrupt_fri = serde_json::to_vec(&stark_struct_fri).unwrap();
    let res_5d_fri = verify_stark_proof(&proof_corrupt_fri, &pk_a, &msg);
    println!("5d. Out-of-bounds FRI Poly:      verify_stark_proof() = {:?} (REJECTED: {})", res_5d_fri, res_5d_fri.is_err());
    assert!(res_5d_fri.is_err());

    // 5e. Cross-key attack
    let res_5e = verify(&pk_b, &msg, &valid_sig);
    println!("5e. Cross-Key Attack (Key B):    verify() = {} (REJECTED: {})", res_5e, !res_5e);
    assert!(!res_5e);

    println!("=======================================================\n");
}
