#![cfg(feature = "proxy")]
use solomon_core::crypto::nist_api::{keygen, sign, verify};
use solomon_core::iso8583::Iso8583Message;
use solomon_core::proxy::ZkAuthorizationProof;
use solomon_core::zk::batch::{BatchAccumulator, TransactionRecord};
use solomon_core::crypto::shake::KeccakSponge;

#[test]
fn test_e2e_realistic_pipeline() {
    println!("\n=== Starting End-to-End Realistic Pipeline Test ===");

    // 1. Generate ML-DSA-65 keys and sign a mock transaction payload
    println!("[Step 1] Generating ML-DSA-65 Keys...");
    let seed = [0x42u8; 32];
    let (sk, pk) = keygen(&seed);

    let transaction_data = b"0200|STAN:123456|AMT:150.00|USD";
    println!("[Step 1] Signing transaction data with ML-DSA-65...");
    let sig = sign(&sk, transaction_data);
    
    // Verify signature to ensure base cryptography is working
    assert!(verify(&pk, transaction_data, &sig), "Base ML-DSA signature failed verification!");

    // 2. Produce the 128-byte ZkAuthorizationProof commitment
    println!("[Step 2] Generating Cryptographic Commitment (128-bytes)...");
    let identity = [0x11u8; 32];
    let fingerprint = [0x22u8; 32];
    
    // Hash transaction state
    let mut state_sponge = KeccakSponge::new_shake256();
    state_sponge.absorb(transaction_data);
    state_sponge.absorb(&sig);
    let mut state_commitment = [0u8; 32];
    state_sponge.squeeze(&mut state_commitment);

    let auth_commitment = ZkAuthorizationProof::generate(&identity, &fingerprint, &state_commitment);
    assert!(auth_commitment.verify(&state_commitment), "Commitment verification failed");

    // 3. Batch it using BatchAccumulator
    println!("[Step 3] Pushing to BatchAccumulator Merkle Tree...");
    let tx_record = TransactionRecord {
        payload: transaction_data.to_vec(),
        public_key: pk.to_vec(),
        signature: sig.to_vec(),
    };

    // Force a flush by padding a manual batch
    let manual_batch = vec![tx_record.clone()];
    let padded_batch = BatchAccumulator::pad_batch(manual_batch);
    let (merkle_root, proofs) = BatchAccumulator::build_merkle_tree(&padded_batch);
    
    assert_eq!(padded_batch.len(), 16);
    assert_eq!(proofs.len(), 16);
    println!("         Merkle Root Generated: {:?}", &merkle_root[0..4]);

    // 4. Inject the commitment into an Iso8583Message (Field 112)
    println!("[Step 4] Framing into ISO 8583 and injecting into Field 112...");
    let mut iso_msg = Iso8583Message::new(*b"0200");
    iso_msg.set_field(3, b"000000".to_vec()); // Processing Code
    iso_msg.set_field(4, b"000000015000".to_vec()); // Amount
    
    // Serialize commitment to bytes
    let mut commitment_bytes = Vec::with_capacity(128);
    commitment_bytes.extend_from_slice(&auth_commitment.identity_commitment);
    commitment_bytes.extend_from_slice(&auth_commitment.attestation_hash);
    commitment_bytes.extend_from_slice(&auth_commitment.state_commitment);
    commitment_bytes.extend_from_slice(&auth_commitment.proof_elements);
    
    assert_eq!(commitment_bytes.len(), 128); // 4 * 32 bytes

    // Inject into PQC National Data field
    iso_msg.inject_pqc_field(112, &commitment_bytes);

    // 5. Serialize to binary framing
    println!("[Step 5] Serializing to TCP Binary Frame...");
    let binary_frame = iso_msg.serialize();

    // 6. Parse the binary frame, verify the signature & commitment
    println!("[Step 6] Parsing frame on Receiving Proxy and verifying...");
    let parsed_msg = Iso8583Message::parse(&binary_frame).expect("Failed to parse ISO frame");
    
    let extracted_pqc_bytes = parsed_msg.get_field(112).expect("Field 112 missing");
    
    let mut identity_commitment = [0u8; 32];
    identity_commitment.copy_from_slice(&extracted_pqc_bytes[0..32]);
    let mut attestation_hash = [0u8; 32];
    attestation_hash.copy_from_slice(&extracted_pqc_bytes[32..64]);
    let mut state_commitment_ext = [0u8; 32];
    state_commitment_ext.copy_from_slice(&extracted_pqc_bytes[64..96]);
    let mut proof_elements = [0u8; 32];
    proof_elements.copy_from_slice(&extracted_pqc_bytes[96..128]);

    let extracted_commitment = ZkAuthorizationProof {
        identity_commitment,
        attestation_hash,
        state_commitment: state_commitment_ext,
        proof_elements,
    };

    // Assert that the extracted commitment matches the original
    assert_eq!(extracted_commitment.proof_elements, auth_commitment.proof_elements);
    
    // Validate the commitment against the state hash
    assert!(extracted_commitment.verify(&state_commitment), "Receiving Proxy failed to verify the commitment");

    println!("✅ End-to-End Realistic Pipeline Test Passed Successfully!\n");
}
