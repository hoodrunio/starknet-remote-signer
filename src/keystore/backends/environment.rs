use async_trait::async_trait;
use tracing::warn;

use crate::errors::SignerError;
use crate::keystore::backends::KeystoreBackend;
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
        
        let private_key_hex = std::env::var(&self.var_name)
            .map_err(|_| SignerError::Config(format!("Environment variable {} not set", self.var_name)))?;

        // Validate the private key format
        if private_key_hex.is_empty() {
            return Err(SignerError::InvalidKey("Private key cannot be empty".to_string()));
        }

        // Ensure the key is properly formatted (hex string)
        if !private_key_hex.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(SignerError::InvalidKey("Private key must be a valid hex string".to_string()));
        }

        // Validate key length (64 hex characters = 32 bytes)
        if private_key_hex.len() != 64 {
            return Err(SignerError::InvalidKey("Private key must be exactly 64 hex characters (32 bytes)".to_string()));
        }

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
            "Environment backend does not support key storage".to_string()
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
        
        // Additional security warning during validation
        warn!("⚠️  SECURITY WARNING: Environment backend configured");
        warn!("⚠️  Private keys stored in environment variables are less secure");
        warn!("⚠️  Consider using 'software' backend with encrypted keystore for production");
        
        Ok(())
    }
} 