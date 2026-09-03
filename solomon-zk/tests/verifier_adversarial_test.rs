use solomon_zk::{generate_stark_proof, verify_stark_proof, StarkVerificationError, StarkProof, GOLDILOCKS_PRIME};

fn create_synthetic_signature() -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    let mut sig = vec![0u8; 3309];
    // Fill c_tilde challenge (first 32 bytes)
    for i in 0..32 {
        sig[i] = (i * 7 + 3) as u8;
    }
    // Fill polynomial vector z (3200 bytes)
    for i in 32..3232 {
        sig[i] = ((i * 13 + 5) % 256) as u8;
    }
    // Fill hint h (remaining 77 bytes)
    for i in 3232..3309 {
        sig[i] = (i % 2) as u8;
    }

    let mut pk = vec![0u8; 1952];
    for i in 0..pk.len() {
        pk[i] = ((i * 17 + 1) % 256) as u8;
    }

    let msg = b"FinTech high-frequency transaction payload INR 50,000".to_vec();

    (sig, pk, msg)
}

#[test]
fn test_stark_verifier_happy_path_and_latency() {
    let (sig, pk, msg) = create_synthetic_signature();

    // 1. Prover generates proof
    let start_prover = std::time::Instant::now();
    let proof = generate_stark_proof(&sig, &pk, &msg);
    let prover_latency = start_prover.elapsed();

    // 2. Verifier checks proof
    let start_verifier = std::time::Instant::now();
    let result = verify_stark_proof(&proof, &pk, &msg);
    let verifier_latency = start_verifier.elapsed();

    println!("\n=======================================================");
    println!("     Solomon STARK Verifier over Goldilocks Field      ");
    println!("=======================================================");
    println!("  • STARK Prover Latency:   {:.3} ms", prover_latency.as_secs_f64() * 1000.0);
    println!("  • STARK Verifier Latency: {:.3} ms ({:.1} µs)", verifier_latency.as_secs_f64() * 1000.0, verifier_latency.as_micros() as f64);
    println!("  • Proof Payload Size:     {} bytes", proof.len());
    println!("=======================================================\n");

    if let Err(ref e) = result {
        println!("Verifier failed with error: {:?}", e);
    }
    assert!(result.is_ok(), "Valid proof must pass verification, got: {:?}", result.err());
    assert!(result.unwrap(), "Verifier verdict must be true");
    let max_latency_us = if cfg!(debug_assertions) { 250_000 } else { 15_000 };
    assert!(verifier_latency.as_micros() < max_latency_us, "Verifier latency must be < {} µs", max_latency_us);
}

#[test]
fn test_stark_verifier_adversarial_tamper_rejections() {
    let (sig, pk, msg) = create_synthetic_signature();
    let valid_proof_bytes = generate_stark_proof(&sig, &pk, &msg);
    let valid_stark: StarkProof = serde_json::from_slice(&valid_proof_bytes).unwrap();

    // 1. ADVERSARIAL TEST: Tamper Trace Merkle Root (Nullification)
    let mut tampered_root = valid_stark.clone();
    tampered_root.trace_root = [0u8; 32];
    let proof1 = serde_json::to_vec(&tampered_root).unwrap();
    let res1 = verify_stark_proof(&proof1, &pk, &msg);
    assert!(res1.is_err(), "Nullified Merkle root must be rejected");
    assert_eq!(res1.unwrap_err(), StarkVerificationError::NullMerkleRoot);
    
    // 2. ADVERSARIAL TEST: Tamper FRI Queries (Empty)
    let mut empty_queries = valid_stark.clone();
    empty_queries.fri_proof.queries.clear();
    let proof2 = serde_json::to_vec(&empty_queries).unwrap();
    let res2 = verify_stark_proof(&proof2, &pk, &msg);
    assert!(res2.is_err(), "Empty FRI queries must be rejected");
    assert_eq!(res2.unwrap_err(), StarkVerificationError::InvalidProofPayload);
    
    // 3. ADVERSARIAL TEST: Tamper Colinearity (Empty trace evals)
    let mut tampered_evals = valid_stark.clone();
    tampered_evals.fri_proof.queries[0].trace_evals.clear();
    let proof3 = serde_json::to_vec(&tampered_evals).unwrap();
    let res3 = verify_stark_proof(&proof3, &pk, &msg);
    assert!(res3.is_err(), "Empty trace evals must trigger colinearity failure");
    assert_eq!(res3.unwrap_err(), StarkVerificationError::FriColinearityCheckFailed);

    // 4. ADVERSARIAL TEST: Invalid Field Element (>= p)
    let mut out_of_range = valid_stark.clone();
    out_of_range.fri_proof.final_poly.0 = GOLDILOCKS_PRIME + 10;
    let proof_range = serde_json::to_vec(&out_of_range).unwrap();
    let res_range = verify_stark_proof(&proof_range, &pk, &msg);
    assert_eq!(res_range.unwrap_err(), StarkVerificationError::InvalidFieldElement);

    // 5. ADVERSARIAL TEST: Corrupted Garbage / Null Payload
    let null_proof = vec![0u8; 32];
    let res5 = verify_stark_proof(&null_proof, &pk, &msg);
    assert!(res5.is_err(), "Invalid payload must be rejected");
    assert_eq!(res5.unwrap_err(), StarkVerificationError::InvalidProofPayload);

    println!("[ADVERSARIAL SUITE] All cryptographic Goldilocks tamper tests passed rejection verification.");
}

#[test]
fn test_fri_constant_on_corrupted_signature() {
    let (sig1, pk, msg) = create_synthetic_signature();
    let mut sig2 = sig1.clone();
    sig2[100] ^= 0xFF; // Corrupt byte 100

    let proof1_bytes = generate_stark_proof(&sig1, &pk, &msg);
    let proof2_bytes = generate_stark_proof(&sig2, &pk, &msg);

    let stark1: StarkProof = serde_json::from_slice(&proof1_bytes).unwrap();
    let stark2: StarkProof = serde_json::from_slice(&proof2_bytes).unwrap();

    let to_hex_str = |bytes: &[u8]| -> String {
        bytes.iter().map(|b| format!("{:02x}", b)).collect()
    };

    let root1_hex = to_hex_str(&stark1.trace_root);
    let root2_hex = to_hex_str(&stark2.trace_root);

    let fri_constant1 = stark1.fri_proof.final_poly.0;
    let fri_constant2 = stark2.fri_proof.final_poly.0;

    println!("\n=======================================================");
    println!("     FRI Constant & Trace Merkle Root Comparison       ");
    println!("=======================================================");
    println!("  • Signature 1 (Original) Trace Root: {}", root1_hex);
    println!("  • Signature 2 (Byte 100 ^ 0xFF) Trace Root: {}", root2_hex);
    println!("  • Signature 1 FRI Constant: 0x{:016x} ({})", fri_constant1, fri_constant1);
    println!("  • Signature 2 FRI Constant: 0x{:016x} ({})", fri_constant2, fri_constant2);
    println!("  • Roots are different: {}", stark1.trace_root != stark2.trace_root);
    println!("  • FRI constants are different: {}", fri_constant1 != fri_constant2);
    println!("=======================================================\n");

    assert_ne!(stark1.trace_root, stark2.trace_root, "Trace roots must differ");
    assert_ne!(fri_constant1, fri_constant2, "FRI constants must differ when signature changes");
}
