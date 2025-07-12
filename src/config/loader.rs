use anyhow::Result;
use std::fs;

use super::types::*;
use crate::cli::StartArgs;
use crate::errors::SignerError;

impl Config {
    /// Load configuration from CLI arguments and optional config file
    pub fn load(cli: StartArgs) -> Result<Self> {
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
            logging: LoggingConfig::default(),
        };

        // Load from config file if provided
        if let Some(config_path) = cli.config {
            let file_config = Self::load_from_file(&config_path)?;

            // Merge CLI and file configurations
            config = Self::merge_configurations(config, file_config, cli_address, cli_port);
        }

        Ok(config)
    }

    /// Load configuration from a TOML file
    fn load_from_file(config_path: &str) -> Result<Self, SignerError> {
        let config_content = fs::read_to_string(config_path).map_err(|e| {
            SignerError::Config(format!("Failed to read config file {config_path}: {e}"))
        })?;

        toml::from_str(&config_content)
            .map_err(|e| SignerError::Config(format!("Failed to parse config file: {e}")))
    }

    /// Merge CLI and file configurations with proper precedence
    fn merge_configurations(
        mut cli_config: Self,
        file_config: Self,
        cli_address: String,
        cli_port: u16,
    ) -> Self {
        // Config file values override CLI defaults, but explicit CLI args override config file
        // For server config, use config file values if they match CLI defaults
        if cli_address == "0.0.0.0" {
            // CLI default
            cli_config.server.address = file_config.server.address;
        }
        if cli_port == 3000 {
            // CLI default
            cli_config.server.port = file_config.server.port;
        }

        // CLI values override config file values for keystore
        if cli_config.keystore.backend == "environment"
            && file_config.keystore.backend != "environment"
        {
            cli_config.keystore = file_config.keystore;
        }

        if cli_config.passphrase.is_none() {
            cli_config.passphrase = file_config.passphrase;
        }
        if !cli_config.tls.enabled && file_config.tls.enabled {
            cli_config.tls = file_config.tls;
        }

        // Always use config file values for security, audit, and logging (config file takes precedence)
        cli_config.security = file_config.security;
        cli_config.audit = file_config.audit;
        cli_config.logging = file_config.logging;

        cli_config
    }
}
