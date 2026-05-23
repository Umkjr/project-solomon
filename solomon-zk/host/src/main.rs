// solomon-zk/host/src/main.rs
use sp1_sdk::{ProverClient, SP1Stdin};

/// Mock RISC-V ELF binary bytes representing the Guest program for compilation offline
const GUEST_ELF: &[u8] = &[0x7F, 0x45, 0x4C, 0x46, 0x01, 0x01, 0x01, 0x00];

fn main() {
    println!("🛡️ Starting Solomon ZK Prover Host (Phase 5)...");

    // 1. Prepare input parameters for the ZK execution environment
    let mut stdin = SP1Stdin::new();
    
    let transaction_payload = b"{\"amount_usd\":15000.0,\"currency\":\"USD\"}".to_vec();
    let public_key = vec![0x99u8; 1952];
    let signature = vec![0xAAu8; 3309];

    stdin.write(&transaction_payload);
    stdin.write(&public_key);
    stdin.write(&signature);

    println!("[Host] Loaded Guest program ELF binary (size: {} bytes).", GUEST_ELF.len());

    // 2. Initialize high-performance ProverClient
    let client = ProverClient::new();
    let (pk, vk) = client.setup(GUEST_ELF);

    println!("[Host] Generating succinct SNARK proof from RISC-V zkVM execution trace...");
    // Generate proof using the setup keys and inputs
    let proof = client.prove(&pk, stdin)
        .run()
        .expect("ZK proving execution sequence failed");

    println!("[Host] Verifying generated SNARK proof against verification key locally...");
    client.verify(&proof, &vk)
        .expect("ZK verification of generated SNARK proof failed");

    // 3. Extract committed public values from SP1 public values journal
    let committed_hash = proof.public_values.read::<[u8; 32]>();

    println!("✅ Zero-Knowledge Proof successfully generated and verified!");
    println!("🔒 Sucint SNARK Proof commitment payload hash: {:?}", committed_hash);
}
