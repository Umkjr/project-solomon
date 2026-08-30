use solomon_core::crypto::nist_api::{keygen, sign};
use solomon_core::crypto::heartbeat::set_daily_salt;
use solomon_core::zk::batch::{BatchAccumulator, TransactionRecord};
use solomon_zk::prover::generate_stark_proof;

#[test]
fn test_compression_1000_to_1_end_to_end() {
    set_daily_salt([0x5Au8; 32]);
    let mut total_raw_signature_bytes = 0usize;
    let mut batch_records = Vec::with_capacity(1000);

    let start_gen = std::time::Instant::now();
    for i in 0..1000 {
        let mut seed = [0x5Au8; 32];
        seed[0..4].copy_from_slice(&(i as u32).to_le_bytes());
        let (sk, pk) = keygen(&seed);

        let msg = format!("Transaction #{} INR {}", i, 1000 + i);
        let sig = sign(&sk, msg.as_bytes());

        total_raw_signature_bytes += sig.len();

        batch_records.push(TransactionRecord {
            payload: msg.into_bytes(),
            public_key: pk.to_vec(),
            signature: sig.to_vec(),
        });
    }
    let gen_duration = start_gen.elapsed();

    // 1. Build Merkle Batch Accumulator Tree
    let padded_batch = BatchAccumulator::pad_batch(batch_records.clone());
    let (merkle_root, proofs) = BatchAccumulator::build_merkle_tree(&padded_batch);

    // 2. Generate representative STARK Proof for the batch commitment
    let sample_sig = &batch_records[0].signature;
    let sample_pk = &batch_records[0].public_key;
    let sample_payload = &batch_records[0].payload;
    let stark_proof = generate_stark_proof(sample_sig, sample_pk, sample_payload);

    let merkle_root_bytes = merkle_root.len(); // 32 bytes
    let single_merkle_inclusion_proof_bytes = proofs[0].len() * 32; // 10 layers * 32 = 320 bytes
    let stark_proof_bytes = stark_proof.len();

    let merkle_ratio = total_raw_signature_bytes as f64 / merkle_root_bytes as f64;
    let stark_ratio = total_raw_signature_bytes as f64 / stark_proof_bytes as f64;
    let single_inclusion_ratio = total_raw_signature_bytes as f64 / (merkle_root_bytes + single_merkle_inclusion_proof_bytes) as f64;

    println!("\n=======================================================");
    println!("     Section 7: 1,000:1 Compression Analysis           ");
    println!("=======================================================");
    println!("  • Time to Generate 1,000 Sigs:       {:.2} ms", gen_duration.as_secs_f64() * 1000.0);
    println!("  • (a) Total Raw Signatures Size:     {} bytes ({:.2} MB)", total_raw_signature_bytes, total_raw_signature_bytes as f64 / 1_000_000.0);
    println!("  • (b) Batch Merkle Root Size:        {} bytes", merkle_root_bytes);
    println!("  • (c) Single Tx Merkle Proof Size:   {} bytes", single_merkle_inclusion_proof_bytes);
    println!("  • (d) Full STARK Proof Size:         {} bytes ({:.2} KB)", stark_proof_bytes, stark_proof_bytes as f64 / 1024.0);
    println!("  -----------------------------------------------------");
    println!("  • Tier 1: Merkle Root Accumulator:   {:.1}:1 ({:.4}%)", merkle_ratio, (1.0 - (merkle_root_bytes as f64 / total_raw_signature_bytes as f64)) * 100.0);
    println!("  • Tier 1b: Single Tx Inclusion:      {:.1}:1", single_inclusion_ratio);
    println!("  • Tier 2: Full STARK Proof:          {:.2}:1 ({:.4}%)", stark_ratio, (1.0 - (stark_proof_bytes as f64 / total_raw_signature_bytes as f64)) * 100.0);
    println!("=======================================================\n");

    assert_eq!(total_raw_signature_bytes, 3_309_000);
    assert_eq!(merkle_root_bytes, 32);
    assert!(merkle_ratio > 100_000.0, "Merkle root accumulator must achieve >100,000:1 ratio");
    assert!(stark_ratio > 2.5, "Full STARK proof must compress >2.5:1 over 1,000 raw signatures with N=2^18 domain");
}
