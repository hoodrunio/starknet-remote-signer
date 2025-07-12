use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub server: ServerConfig,
    pub tls: TlsConfig,
    pub keystore: KeystoreConfig,
    pub passphrase: Option<String>,
    #[serde(default)]
    pub security: SecurityConfig,
    #[serde(default)]
    pub audit: AuditConfig,
    #[serde(default)]
    pub logging: LoggingConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeystoreConfig {
    pub backend: String, // "software", "file", "environment", "os_keyring", "hsm"
    pub path: Option<String>, // For software backend
    pub dir: Option<String>, // For file backend
    pub env_var: Option<String>, // For environment backend
    pub device: Option<String>, // For HSM backend
    // OS keyring specific field
    pub key_name: Option<String>, // For OS keyring backend - like "validator", "alice", etc.
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    pub address: String,
    pub port: u16,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsConfig {
    pub enabled: bool,
    pub cert_file: Option<String>,
    pub key_file: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct SecurityConfig {
    /// Allowed chain IDs (e.g., "SN_MAIN", "SN_SEPOLIA")
    pub allowed_chain_ids: Vec<String>,
    /// Allowed IP addresses (empty = allow all)
    pub allowed_ips: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct AuditConfig {
    pub enabled: bool,
    pub log_path: String,
    pub rotate_daily: bool,
}

impl Default for AuditConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            log_path: "/var/log/starknet-signer/audit.log".to_string(),
            rotate_daily: true,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct LoggingConfig {
    pub level: String,
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            level: "info".to_string(),
        }
    }
}
