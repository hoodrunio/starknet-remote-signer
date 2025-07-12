use async_trait::async_trait;
use tracing::warn;

use crate::errors::SignerError;
use crate::keystore::backends::{BackendUtils, KeystoreBackend};
use crate::keystore::key_material::KeyMaterial;

/// Environment variable keystore backend (for development only)
#[derive(Debug)]
pub struct EnvironmentBackend {
    var_name: String,
    key_material: Option<KeyMaterial>,
}

impl EnvironmentBackend {
    /// Create a new environment backend
    pub fn new(var_name: String) -> Self {
        Self {
            var_name,
            key_material: None,
        }
    }

    /// Load key from environment variable
    fn load_environment_key(&mut self) -> Result<(), SignerError> {
        // Security warning for environment variable usage
        warn!("⚠️  SECURITY WARNING: Loading private key from environment variable");
        warn!("⚠️  Environment variables can be visible to other processes and may be logged");
        warn!("⚠️  This method is NOT recommended for production use");
        warn!("⚠️  Consider using the 'software' backend with encrypted keystore instead");

        let private_key_hex = std::env::var(&self.var_name).map_err(|_| {
            SignerError::Config(format!("Environment variable {} not set", self.var_name))
        })?;

        // Validate the private key format using common utilities
        BackendUtils::validate_private_key_hex(&private_key_hex)?;

        self.key_material = Some(KeyMaterial::from_hex(&private_key_hex)?);
        Ok(())
    }
}

#[async_trait]
impl KeystoreBackend for EnvironmentBackend {
    async fn init(&mut self, _config: Option<&str>) -> Result<(), SignerError> {
        self.load_environment_key()?;
        Ok(())
    }

    async fn store_key(&self, _key_material: &KeyMaterial) -> Result<(), SignerError> {
        Err(SignerError::Config(
            "Environment backend does not support key storage".to_string(),
        ))
    }

    async fn load_key(&self) -> Result<KeyMaterial, SignerError> {
        self.key_material
            .as_ref()
            .ok_or_else(|| SignerError::Config("Keystore not initialized".to_string()))
            .map(|km| KeyMaterial::from_bytes(*km.raw_bytes()))
    }

    fn is_available(&self) -> bool {
        std::env::var(&self.var_name).is_ok()
    }

    fn backend_type(&self) -> &'static str {
        "environment"
    }

    fn validate_config(&self) -> Result<(), SignerError> {
        if !self.is_available() {
            warn!("Environment variable {} is not set", self.var_name);
        }

        // Use common security warning utility
        BackendUtils::log_security_warnings("environment");

        Ok(())
    }
}
