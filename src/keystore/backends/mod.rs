use async_trait::async_trait;
use crate::errors::SignerError;
use crate::keystore::key_material::KeyMaterial;

/// Trait for keystore backends that provide secure key storage and retrieval
#[async_trait]
pub trait KeystoreBackend: Send + Sync {
    /// Initialize the backend with optional configuration
    async fn init(&mut self, config: Option<&str>) -> Result<(), SignerError>;

    /// Store key material securely
    async fn store_key(&self, key_material: &KeyMaterial) -> Result<(), SignerError>;

    /// Load key material from secure storage
    async fn load_key(&self) -> Result<KeyMaterial, SignerError>;

    /// Check if the backend is available and properly configured
    fn is_available(&self) -> bool;

    /// Get a human-readable description of the backend
    fn backend_type(&self) -> &'static str;

    /// Validate backend-specific configuration
    fn validate_config(&self) -> Result<(), SignerError> {
        Ok(())
    }

    /// Delete key from secure storage (if supported)
    async fn delete_key(&self) -> Result<(), SignerError> {
        Err(SignerError::Config(
            format!("{} backend does not support key deletion", self.backend_type())
        ))
    }
}

/// Backend configuration enum
#[derive(Debug, Clone)]
pub enum BackendConfig {
    /// Software-based encrypted storage
    Software { 
        keystore_path: String,
    },
    /// Environment variable (less secure, for development)
    Environment { 
        var_name: String,
    },
    /// OS keyring integration
    OsKeyring { 
        key_name: String,
    },
    /// Hardware Security Module (future)
    #[allow(dead_code)]
    Hsm { 
        device_path: String,
    },
}

impl BackendConfig {
    /// Get the backend type as a string
    pub fn backend_type(&self) -> &'static str {
        match self {
            BackendConfig::Software { .. } => "software",
            BackendConfig::Environment { .. } => "environment", 
            BackendConfig::OsKeyring { .. } => "os_keyring",
            BackendConfig::Hsm { .. } => "hsm",
        }
    }
}

// Backend implementations
pub mod software;
pub mod environment;
pub mod os_keyring;

// Re-exports for convenience
pub use software::SoftwareBackend;
pub use environment::EnvironmentBackend;
pub use os_keyring::OsKeyringBackend; 