#[cfg(feature = "proxy")]
#[tokio::main]
async fn main() {
    // Check CLI arguments for CBOM export
    let args: Vec<String> = std::env::args().collect();
    if args.iter().any(|a| a == "--export-cbom" || a == "--cbom" || a == "cbom") {
        let cbom_json = solomon_core::cbom::generate_cbom_json();
        println!("{}", cbom_json);
        return;
    }

    // Initialize tracing subscriber for SIEM-compatible JSON logs
    tracing_subscriber::fmt()
        .json()
        .with_writer(std::io::stdout)
        .init();

    use std::sync::Arc;
    use rand_core::RngCore;
    use solomon_core::config::SolomonProxyConfig;
    use solomon_core::hsm::{KeyStorageBackend, EncryptedFileKeystoreBackend};
    use solomon_core::proxy::start_proxy_server;

    tracing::info!("Starting Solomon Post-Quantum Proxy Launcher...");

    // 1. Load 12-factor configuration
    let config = SolomonProxyConfig::from_env();

    // 2. Initialize Hardware Security Module (HSM) - Persistent AES-256-GCM Keystore with RAM Locking
    let keystore_backend = EncryptedFileKeystoreBackend::load_or_generate(
        &config.keystore_path,
        &config.keystore_passphrase,
        None,
    ).expect("Failed to initialize persistent encrypted keystore");

    let keystore: Arc<Box<dyn KeyStorageBackend>> = Arc::new(Box::new(keystore_backend));

    // 3. Generate dynamic node identity
    let mut rng = rand::rngs::OsRng;
    let mut node_identity = [0u8; 32];
    rng.fill_bytes(&mut node_identity);

    tracing::info!(
        message = "Configuration parsed successfully",
        listen_address = %config.proxy_bind_addr,
        backend_target = %config.control_plane_url,
        license_id = %config.license_id
    );

    // 4. Start Proxy Server
    start_proxy_server(
        config.proxy_bind_addr,
        keystore,
        node_identity,
        config.backend_url,
        config.control_plane_url,
        config.license_id,
    ).await;
}

#[cfg(not(feature = "proxy"))]
fn main() {
    eprintln!("Error: The Solomon Proxy requires the 'proxy' feature to be enabled during compilation.");
    eprintln!("Please build or run using: cargo run --features proxy");
    std::process::exit(1);
}
