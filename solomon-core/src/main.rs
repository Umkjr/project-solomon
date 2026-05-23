#[cfg(feature = "proxy")]
#[tokio::main]
async fn main() {
    use std::net::SocketAddr;
    use ml_dsa_65::crypto::heartbeat::set_daily_salt;
    use ml_dsa_65::crypto::nist_api::keygen;
    use ml_dsa_65::proxy::start_proxy_server;

    println!("🚀 Starting Solomon Post-Quantum Proxy Launcher...");

    // Initialize the daily salt matching mock_control_plane.py to allow valid signature verification
    set_daily_salt(*b"LOCAL_DEV_SALT_32_BYTES_LONG_000");

    // For local development and demonstration, generate a fresh ML-DSA-65 keypair.
    let seed = [0x42; 32];
    let (sk, pk) = keygen(&seed);
    
    // Node identity commitment
    let node_identity = [0x99; 32];

    // Parse runtime environment variables
    let listen_addr: SocketAddr = std::env::var("PROXY_LISTEN_ADDR")
        .unwrap_or_else(|_| "127.0.0.1:8080".to_string())
        .parse()
        .expect("Invalid PROXY_LISTEN_ADDR");

    let backend_url = std::env::var("BACKEND_URL")
        .unwrap_or_else(|_| "http://127.0.0.1:8081".to_string());

    let control_plane_url = std::env::var("CONTROL_PLANE_URL")
        .unwrap_or_else(|_| "http://127.0.0.1:9000".to_string());

    let license_id = std::env::var("LICENSE_ID")
        .unwrap_or_else(|_| "ENT-5821".to_string());

    println!("⚙️ Configuration:");
    println!("   - Listen Address:      {}", listen_addr);
    println!("   - Backend Target:      {}", backend_url);
    println!("   - Control Plane URL:   {}", control_plane_url);
    println!("   - License ID:          {}", license_id);

    start_proxy_server(
        listen_addr,
        sk,
        pk,
        node_identity,
        backend_url,
        control_plane_url,
        license_id,
    ).await;
}

#[cfg(not(feature = "proxy"))]
fn main() {
    eprintln!("Error: The Solomon Proxy requires the 'proxy' feature to be enabled during compilation.");
    eprintln!("Please build or run using: cargo run --features proxy");
    std::process::exit(1);
}
