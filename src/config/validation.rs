use tracing::warn;

use super::types::Config;
use crate::errors::SignerError;

impl Config {
    /// Validate the configuration settings
    pub fn validate(&self) -> Result<(), SignerError> {
        // Validate keystore configuration
        self.validate_keystore()?;

        // Validate TLS configuration
        self.validate_tls()?;

        // Validate server configuration
        self.validate_server()?;

        // Validate security configuration
        self.validate_security()?;

        Ok(())
    }

    /// Validate keystore configuration
    fn validate_keystore(&self) -> Result<(), SignerError> {
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
                tracing::debug!("📁 File backend configured");
                if let Some(dir) = &self.keystore.dir {
                    tracing::debug!(
                        "🔐 Keys will be stored as encrypted files in directory: '{}'",
                        dir
                    );
                }
                if let Some(key_name) = &self.keystore.key_name {
                    tracing::debug!("🔑 Will use key: '{}'", key_name);
                } else {
                    tracing::debug!("🔑 Will use default/first available key");
                }
            }
            "environment" => {
                if self.keystore.env_var.is_none() {
                    return Err(SignerError::Config(
                        "Environment variable name is required for environment backend".to_string(),
                    ));
                }

                // Security warning for environment variable usage
                warn!("⚠️  SECURITY WARNING: Environment backend configured");
                warn!("⚠️  Private keys stored in environment variables are less secure");
                warn!(
                    "⚠️  Consider using 'software' backend with encrypted keystore for production"
                );
            }
            "os_keyring" => {
                self.validate_os_keyring()?;
            }
            "hsm" => {
                return Err(SignerError::Config(
                    "HSM backend not yet implemented".to_string(),
                ));
            }
            _ => {
                tracing::debug!("Unknown keystore backend: {}. Supported backends: software, file, environment, os_keyring, hsm", self.keystore.backend);
                return Err(SignerError::Config(format!(
                    "Unknown keystore backend: '{}'",
                    self.keystore.backend
                )));
            }
        }

        Ok(())
    }

    /// Validate OS keyring configuration
    fn validate_os_keyring(&self) -> Result<(), SignerError> {
        if self.keystore.key_name.is_none() {
            return Err(SignerError::Config(
                "Key name is required for OS keyring backend".to_string(),
            ));
        }

        // Platform check
        #[cfg(target_env = "musl")]
        {
            warn!("⚠️  MUSL target detected: OS keyring functionality is limited");
            warn!("⚠️  D-Bus integration is not available for static MUSL builds");
            warn!("💡 Recommended alternatives for MUSL deployments:");
            warn!("   - Use 'file' backend: backend = \"file\"");
            warn!("   - Use 'software' backend: backend = \"software\"");
            warn!("   - Use 'environment' backend: backend = \"environment\"");

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
            tracing::debug!("📱 OS keyring backend configured for Linux (with D-Bus support)");
            if let Some(key_name) = &self.keystore.key_name {
                tracing::debug!(
                    "🔐 Keys will be stored in system keyring with key name: '{}'",
                    key_name
                );
            }
        }

        #[cfg(target_os = "macos")]
        {
            tracing::debug!("📱 OS keyring backend configured for macOS");
            if let Some(key_name) = &self.keystore.key_name {
                tracing::debug!(
                    "🔐 Keys will be stored in macOS Keychain with key name: '{}'",
                    key_name
                );
            }
        }

        Ok(())
    }

    /// Validate TLS configuration
    fn validate_tls(&self) -> Result<(), SignerError> {
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

        Ok(())
    }

    /// Validate server configuration
    fn validate_server(&self) -> Result<(), SignerError> {
        // Validate port range
        if self.server.port == 0 {
            return Err(SignerError::Config(
                "Invalid port number: must be between 1 and 65535".to_string(),
            ));
        }

        Ok(())
    }

    /// Validate security configuration and log warnings
    fn validate_security(&self) -> Result<(), SignerError> {
        // Security validations
        if self.server.address == "0.0.0.0" && !self.tls.enabled {
            warn!("⚠️  SECURITY WARNING: Server binding to 0.0.0.0 without TLS");
            warn!("⚠️  This exposes the signer to all network interfaces unencrypted");
            warn!("⚠️  Consider enabling TLS or binding to a specific interface");
        }

        if self.keystore.backend == "environment" && self.tls.enabled {
            warn!("⚠️  SECURITY WARNING: Environment keystore with TLS enabled");
            warn!("⚠️  While TLS encrypts network traffic, private keys are still in env vars");
        }

        // Validate that if IP restrictions are empty, we at least have chain ID restrictions
        if self.security.allowed_ips.is_empty() && self.security.allowed_chain_ids.is_empty() {
            warn!("⚠️  SECURITY WARNING: No IP or chain ID restrictions configured");
            warn!("⚠️  This allows any IP to sign for any chain - highly insecure for production");
            warn!("⚠️  Configure 'allowed_ips' and 'allowed_chain_ids' in your config");
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
}
