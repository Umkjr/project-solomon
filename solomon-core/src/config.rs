// solomon-core/src/config.rs
//! 12-Factor App Dynamic Configuration for Solomon Enterprise Proxy.

use std::env;
use std::net::SocketAddr;

#[derive(Debug, Clone)]
pub struct SolomonProxyConfig {
    pub proxy_bind_addr: SocketAddr,
    pub proxy_http_port: u16,
    pub backend_url: String,
    pub receiving_proxy_port: u16,
    pub control_plane_url: String,
    pub config_sync_interval_sec: u64,
    pub license_id: String,
    pub metrics_enabled: bool,
    pub metrics_port: u16,
    pub keystore_path: std::path::PathBuf,
    pub keystore_passphrase: String,
}

impl SolomonProxyConfig {
    /// Load configuration strictly from environment variables, falling back to enterprise defaults.
    pub fn from_env() -> Self {
        let proxy_bind_addr: SocketAddr = env::var("SOLOMON_PROXY_BIND_ADDR")
            .unwrap_or_else(|_| "0.0.0.0:8080".to_string())
            .parse()
            .unwrap_or_else(|_| "0.0.0.0:8080".parse().unwrap());

        let proxy_http_port: u16 = env::var("SOLOMON_PROXY_HTTP_PORT")
            .ok()
            .and_then(|p| p.parse().ok())
            .unwrap_or(8081);

        let receiving_proxy_port: u16 = env::var("SOLOMON_RECEIVING_PROXY_PORT")
            .ok()
            .and_then(|p| p.parse().ok())
            .unwrap_or(8082);

        let backend_url = env::var("SOLOMON_BACKEND_URL")
            .or_else(|_| env::var("BACKEND_URL"))
            .unwrap_or_else(|_| format!("http://127.0.0.1:{}", receiving_proxy_port));

        let control_plane_url = env::var("SOLOMON_CONTROL_PLANE_URL")
            .unwrap_or_else(|_| "http://127.0.0.1:9000".to_string());

        let config_sync_interval_sec: u64 = env::var("CONFIG_SYNC_INTERVAL_SEC")
            .ok()
            .and_then(|i| i.parse().ok())
            .unwrap_or(60);

        let license_id = env::var("SOLOMON_LICENSE_ID")
            .unwrap_or_else(|_| "ENT-5821".to_string());

        let metrics_enabled = env::var("SOLOMON_METRICS_ENABLED")
            .map(|v| v != "0" && v.to_lowercase() != "false")
            .unwrap_or(true);

        let metrics_port: u16 = env::var("SOLOMON_METRICS_PORT")
            .ok()
            .and_then(|p| p.parse().ok())
            .unwrap_or(9100);

        let keystore_path = env::var("SOLOMON_KEYSTORE_PATH")
            .map(std::path::PathBuf::from)
            .unwrap_or_else(|_| std::path::PathBuf::from("keystore/solomon_keystore.bin"));

        let keystore_passphrase = env::var("SOLOMON_KEYSTORE_PASSPHRASE")
            .unwrap_or_else(|_| "SolomonEnterpriseDefaultKey2026!".to_string());

        Self {
            proxy_bind_addr,
            proxy_http_port,
            backend_url,
            receiving_proxy_port,
            control_plane_url,
            config_sync_interval_sec,
            license_id,
            metrics_enabled,
            metrics_port,
            keystore_path,
            keystore_passphrase,
        }
    }
}
