// control_plane/src/crypto.rs
use ed25519_dalek::{SigningKey, Signer};
use std::fs;
use std::path::Path;

const MASTER_KEY_FILE: &str = "master_key.der";

/// Master cryptographic signer state housing the Ed25519 keypair
pub struct MasterSigner {
    pub signing_key: SigningKey,
}

impl MasterSigner {
    /// Load existing master Ed25519 key from disk or initialize it on first boot
    pub fn load_or_init() -> Self {
        let key_path = Path::new(MASTER_KEY_FILE);

        let signing_key = if key_path.exists() {
            println!("[Crypto] Loading existing master Ed25519 key from disk...");
            let key_bytes = fs::read(key_path)
                .expect("Failed to read master Ed25519 key file");
            
            let mut seed = [0u8; 32];
            seed.copy_from_slice(&key_bytes[0..32]);
            SigningKey::from_bytes(&seed)
        } else {
            println!("[Crypto] First boot: Initializing Master Ed25519 key...");
            // Initialize with cryptographically secure random entropy
            let mut seed = [0u8; 32];
            rand::Rng::fill(&mut rand::thread_rng(), &mut seed);
            let signing_key = SigningKey::from_bytes(&seed);

            fs::write(key_path, signing_key.to_bytes())
                .expect("Failed to write master Ed25519 key to disk");

            println!("[Crypto] Master Ed25519 Key dynamically generated. Saved to {}", MASTER_KEY_FILE);
            signing_key
        };

        Self { signing_key }
    }

    /// Sign data utilizing the master Ed25519 private key
    pub fn sign(&self, data: &[u8]) -> Vec<u8> {
        let signature = self.signing_key.sign(data);
        signature.to_bytes().to_vec()
    }
}
