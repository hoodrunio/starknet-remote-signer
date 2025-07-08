use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::fs;

use crate::errors::SignerError;
use crate::keystore::{Keystore, KeystoreBackend};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub server: ServerConfig,
    pub tls: TlsConfig,
    pub keystore: KeystoreConfig,
    pub passphrase: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeystoreConfig {
    pub backend: String, // "software", "environment", "hsm"
    pub path: Option<String>, // For software backend
    pub env_var: Option<String>, // For environment backend
    pub device: Option<String>, // For HSM backend
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

impl Config {
    pub fn load(cli: crate::StartArgs) -> Result<Self> {
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
                backend: cli.keystore_backend.unwrap_or_else(|| "environment".to_string()),
                path: cli.keystore_path,
                env_var: Some(cli.env_var.unwrap_or_else(|| "SIGNER_PRIVATE_KEY".to_string())),
                device: None,
            },

            passphrase: cli.passphrase,
        };

        // Load from config file if provided
        if let Some(config_path) = cli.config {
            let config_content = fs::read_to_string(&config_path)
                .map_err(|e| SignerError::Config(format!("Failed to read config file {}: {}", config_path, e)))?;
            
            let file_config: Config = toml::from_str(&config_content)
                .map_err(|e| SignerError::Config(format!("Failed to parse config file: {}", e)))?;

            // CLI values override config file values  
            if config.keystore.backend == "environment" && file_config.keystore.backend != "environment" {
                config.keystore = file_config.keystore;
            }

            if config.passphrase.is_none() {
                config.passphrase = file_config.passphrase;
            }
            if !config.tls.enabled && file_config.tls.enabled {
                config.tls = file_config.tls;
            }
        }

        Ok(config)
    }

    pub fn validate(&self) -> Result<(), SignerError> {
        // Validate keystore configuration
        match self.keystore.backend.as_str() {
            "software" => {
                if self.keystore.path.is_none() {
                    return Err(SignerError::Config(
                        "Keystore path is required for software backend".to_string()
                    ));
                }
            }
            "environment" => {
                if self.keystore.env_var.is_none() {
                    return Err(SignerError::Config(
                        "Environment variable name is required for environment backend".to_string()
                    ));
                }
            }
            "hsm" => {
                return Err(SignerError::Config(
                    "HSM backend not yet implemented".to_string()
                ));
            }
            _ => {
                return Err(SignerError::Config(
                    format!("Unknown keystore backend: {}", self.keystore.backend)
                ));
            }
        }

        // Validate TLS configuration
        if self.tls.enabled {
            if self.tls.cert_file.is_none() || self.tls.key_file.is_none() {
                return Err(SignerError::Config(
                    "TLS certificate and key files are required when TLS is enabled".to_string()
                ));
            }

            if let Some(cert_file) = &self.tls.cert_file {
                if !std::path::Path::new(cert_file).exists() {
                    return Err(SignerError::Config(
                        format!("TLS certificate file not found: {}", cert_file)
                    ));
                }
            }

            if let Some(key_file) = &self.tls.key_file {
                if !std::path::Path::new(key_file).exists() {
                    return Err(SignerError::Config(
                        format!("TLS key file not found: {}", key_file)
                    ));
                }
            }
        }

        // Validate port range
        if self.server.port == 0 {
            return Err(SignerError::Config(
                "Invalid port number: must be between 1 and 65535".to_string()
            ));
        }

        Ok(())
    }

    /// Create keystore from configuration
    pub async fn create_keystore(&self) -> Result<Keystore, SignerError> {
        let backend = match self.keystore.backend.as_str() {
            "software" => {
                let path = self.keystore.path.as_ref().ok_or_else(|| {
                    SignerError::Config("Keystore path not set".to_string())
                })?;
                KeystoreBackend::Software {
                    keystore_path: path.clone(),
                }
            }
            "environment" => {
                let env_var = self.keystore.env_var.as_ref().ok_or_else(|| {
                    SignerError::Config("Environment variable not set".to_string())
                })?;
                KeystoreBackend::Environment {
                    var_name: env_var.clone(),
                }
            }
            "hsm" => {
                return Err(SignerError::Config(
                    "HSM backend not yet implemented".to_string()
                ));
            }
            _ => {
                return Err(SignerError::Config(
                    format!("Unknown keystore backend: {}", self.keystore.backend)
                ));
            }
        };

        Ok(Keystore::new(backend))
    }
} 