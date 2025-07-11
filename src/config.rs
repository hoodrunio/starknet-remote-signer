use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::fs;

use crate::errors::SignerError;
use crate::keystore::{BackendConfig, Keystore};
use crate::utils::get_passphrase_securely;

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

impl Config {
    pub fn load(cli: crate::StartArgs) -> Result<Self> {
        // Save CLI values to check for defaults later
        let cli_address = cli.address.clone();
        let cli_port = cli.port;

        // Start with CLI values
        let mut config = Self {
            server: ServerConfig {
                address: cli.address,
                port: cli.port,
            },
            tls: TlsConfig {
                enabled: cli.tls,
                cert_file: cli.tls_cert,
                key_file: cli.tls_key,
            },
            keystore: KeystoreConfig {
                backend: cli
                    .keystore_backend
                    .unwrap_or_else(|| "environment".to_string()),
                path: cli.keystore_path,
                dir: cli.keystore_dir,
                env_var: Some(
                    cli.env_var
                        .unwrap_or_else(|| "SIGNER_PRIVATE_KEY".to_string()),
                ),
                device: None,
                key_name: cli.key_name,
            },
            passphrase: cli.passphrase,
            security: SecurityConfig::default(),
            audit: AuditConfig::default(),
        };

        // Load from config file if provided
        if let Some(config_path) = cli.config {
            let config_content = fs::read_to_string(&config_path).map_err(|e| {
                SignerError::Config(format!("Failed to read config file {config_path}: {e}"))
            })?;

            let file_config: Config = toml::from_str(&config_content)
                .map_err(|e| SignerError::Config(format!("Failed to parse config file: {e}")))?;

            // Config file values override CLI defaults, but explicit CLI args override config file
            // For server config, use config file values if they match CLI defaults
            if cli_address == "0.0.0.0" {
                // CLI default
                config.server.address = file_config.server.address;
            }
            if cli_port == 3000 {
                // CLI default
                config.server.port = file_config.server.port;
            }

            // CLI values override config file values for keystore
            if config.keystore.backend == "environment"
                && file_config.keystore.backend != "environment"
            {
                config.keystore = file_config.keystore;
            }

            if config.passphrase.is_none() {
                config.passphrase = file_config.passphrase;
            }
            if !config.tls.enabled && file_config.tls.enabled {
                config.tls = file_config.tls;
            }

            // Always use config file values for security and audit (config file takes precedence)
            config.security = file_config.security;
            config.audit = file_config.audit;
        }

        Ok(config)
    }

    pub fn validate(&self) -> Result<(), SignerError> {
        // Validate keystore configuration
        match self.keystore.backend.as_str() {
            "software" => {
                if self.keystore.path.is_none() {
                    return Err(SignerError::Config(
                        "Keystore path is required for software backend".to_string(),
                    ));
                }
            }
            "file" => {
                if self.keystore.dir.is_none() {
                    return Err(SignerError::Config(
                        "Keystore directory is required for file backend".to_string(),
                    ));
                }
                tracing::info!("📁 File backend configured");
                tracing::info!(
                    "🔐 Keys will be stored as encrypted files in directory: '{}'",
                    self.keystore.dir.as_ref().unwrap()
                );
                if let Some(key_name) = &self.keystore.key_name {
                    tracing::info!("🔑 Will use key: '{}'", key_name);
                } else {
                    tracing::info!("🔑 Will use default/first available key");
                }
            }
            "environment" => {
                if self.keystore.env_var.is_none() {
                    return Err(SignerError::Config(
                        "Environment variable name is required for environment backend".to_string(),
                    ));
                }

                // Security warning for environment variable usage
                tracing::warn!("⚠️  SECURITY WARNING: Environment backend configured");
                tracing::warn!("⚠️  Private keys stored in environment variables are less secure");
                tracing::warn!(
                    "⚠️  Consider using 'software' backend with encrypted keystore for production"
                );
            }
            "os_keyring" => {
                if self.keystore.key_name.is_none() {
                    return Err(SignerError::Config(
                        "Key name is required for OS keyring backend".to_string(),
                    ));
                }

                // Platform check
                #[cfg(target_env = "musl")]
                {
                    tracing::warn!("⚠️  MUSL target detected: OS keyring functionality is limited");
                    tracing::warn!("⚠️  D-Bus integration is not available for static MUSL builds");
                    tracing::warn!("💡 Recommended alternatives for MUSL deployments:");
                    tracing::warn!("   - Use 'file' backend: backend = \"file\"");
                    tracing::warn!("   - Use 'software' backend: backend = \"software\"");
                    tracing::warn!("   - Use 'environment' backend: backend = \"environment\"");
                    
                    return Err(SignerError::Config(
                        "OS keyring backend is not available on MUSL targets due to D-Bus limitations. Use file, software, or environment backend instead.".to_string(),
                    ));
                }

                #[cfg(not(any(target_os = "linux", target_os = "macos")))]
                {
                    return Err(SignerError::Config(
                        "OS keyring backend is only supported on Linux and macOS".to_string(),
                    ));
                }

                #[cfg(all(target_os = "linux", not(target_env = "musl")))]
                {
                    tracing::info!("📱 OS keyring backend configured for Linux (with D-Bus support)");
                    tracing::info!(
                        "🔐 Keys will be stored in system keyring with key name: '{}'",
                        self.keystore.key_name.as_ref().unwrap()
                    );
                }

                #[cfg(target_os = "macos")]
                {
                    tracing::info!("📱 OS keyring backend configured for macOS");
                    tracing::info!(
                        "🔐 Keys will be stored in macOS Keychain with key name: '{}'",
                        self.keystore.key_name.as_ref().unwrap()
                    );
                }
            }
            "hsm" => {
                return Err(SignerError::Config(
                    "HSM backend not yet implemented".to_string(),
                ));
            }
            _ => {
                return Err(SignerError::Config(
                    format!("Unknown keystore backend: {}. Supported backends: software, file, environment, os_keyring, hsm", self.keystore.backend)
                ));
            }
        }

        // Validate TLS configuration
        if self.tls.enabled {
            if self.tls.cert_file.is_none() || self.tls.key_file.is_none() {
                return Err(SignerError::Config(
                    "TLS certificate and key files are required when TLS is enabled".to_string(),
                ));
            }

            if let Some(cert_file) = &self.tls.cert_file {
                if !std::path::Path::new(cert_file).exists() {
                    return Err(SignerError::Config(format!(
                        "TLS certificate file not found: {cert_file}"
                    )));
                }
            }

            if let Some(key_file) = &self.tls.key_file {
                if !std::path::Path::new(key_file).exists() {
                    return Err(SignerError::Config(format!(
                        "TLS key file not found: {key_file}"
                    )));
                }
            }
        }

        // Validate port range
        if self.server.port == 0 {
            return Err(SignerError::Config(
                "Invalid port number: must be between 1 and 65535".to_string(),
            ));
        }

        // Security validations
        if self.server.address == "0.0.0.0" && !self.tls.enabled {
            tracing::warn!("⚠️  SECURITY WARNING: Server binding to 0.0.0.0 without TLS");
            tracing::warn!("⚠️  This exposes the signer to all network interfaces unencrypted");
            tracing::warn!("⚠️  Consider enabling TLS or binding to a specific interface");
        }

        if self.keystore.backend == "environment" && self.tls.enabled {
            tracing::warn!("⚠️  SECURITY WARNING: Environment keystore with TLS enabled");
            tracing::warn!(
                "⚠️  While TLS encrypts network traffic, private keys are still in env vars"
            );
        }

        // Validate that if IP restrictions are empty, we at least have chain ID restrictions
        if self.security.allowed_ips.is_empty() && self.security.allowed_chain_ids.is_empty() {
            tracing::warn!("⚠️  SECURITY WARNING: No IP or chain ID restrictions configured");
            tracing::warn!(
                "⚠️  This allows any IP to sign for any chain - highly insecure for production"
            );
            tracing::warn!("⚠️  Configure 'allowed_ips' and 'allowed_chain_ids' in your config");
        }

        // Validate that we have at least one restriction if audit is disabled
        if !self.audit.enabled
            && self.security.allowed_ips.is_empty()
            && self.security.allowed_chain_ids.is_empty()
        {
            return Err(SignerError::Config(
                "Either audit logging must be enabled OR security restrictions must be configured (or both)".to_string()
            ));
        }

        Ok(())
    }

    /// Get passphrase securely for keystore operations
    pub fn get_keystore_passphrase(&self) -> Result<Option<String>, SignerError> {
        match self.keystore.backend.as_str() {
            "software" | "file" => {
                let passphrase =
                    get_passphrase_securely(self.passphrase.clone(), "Enter keystore passphrase: ")
                        .map_err(|e| {
                            SignerError::Config(format!("Failed to get passphrase: {e}"))
                        })?;
                Ok(Some(passphrase))
            }
            _ => Ok(None), // Other backends don't need passphrase
        }
    }

    /// Create keystore from configuration
    pub async fn create_keystore(&self) -> Result<Keystore, SignerError> {
        let backend = match self.keystore.backend.as_str() {
            "software" => {
                let path = self
                    .keystore
                    .path
                    .as_ref()
                    .ok_or_else(|| SignerError::Config("Keystore path not set".to_string()))?;
                BackendConfig::Software {
                    keystore_path: path.clone(),
                }
            }
            "file" => {
                let dir =
                    self.keystore.dir.as_ref().ok_or_else(|| {
                        SignerError::Config("Keystore directory not set".to_string())
                    })?;
                BackendConfig::File {
                    keystore_dir: dir.clone(),
                    key_name: self.keystore.key_name.clone(),
                }
            }
            "environment" => {
                let env_var = self.keystore.env_var.as_ref().ok_or_else(|| {
                    SignerError::Config("Environment variable not set".to_string())
                })?;
                BackendConfig::Environment {
                    var_name: env_var.clone(),
                }
            }
            "os_keyring" => {
                let key_name = self.keystore.key_name.as_ref().ok_or_else(|| {
                    SignerError::Config("Key name not set for OS keyring backend".to_string())
                })?;
                BackendConfig::OsKeyring {
                    key_name: key_name.clone(),
                }
            }
            "hsm" => {
                return Err(SignerError::Config(
                    "HSM backend not yet implemented".to_string(),
                ));
            }
            _ => {
                return Err(SignerError::Config(
                    format!("Unknown keystore backend: {}. Supported backends: software, file, environment, os_keyring, hsm", self.keystore.backend)
                ));
            }
        };

        Keystore::new(backend)
    }
}
