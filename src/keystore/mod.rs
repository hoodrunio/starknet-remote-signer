use starknet::signers::SigningKey;
use starknet_crypto::Felt;
use std::sync::Arc;
use tokio::sync::Mutex;
use tracing::info;

use crate::errors::SignerError;

// Re-export sub-modules
pub mod backends;
pub mod encryption;
pub mod key_material;

// Re-export commonly used types
pub use backends::{BackendConfig, KeystoreBackend};
pub use encryption::EncryptedKeystore;
pub use key_material::KeyMaterial;

// Re-export backend implementations
pub use backends::{EnvironmentBackend, FileBackend, OsKeyringBackend, SoftwareBackend};

/// Main keystore for managing validator keys using pluggable backends
#[derive(Debug)]
pub struct Keystore {
    backend: Box<dyn KeystoreBackend>,
}

impl Keystore {
    /// Create a new keystore with the specified backend
    pub fn new(config: BackendConfig) -> Result<Self, SignerError> {
        let backend: Box<dyn KeystoreBackend> = match config {
            BackendConfig::Software { keystore_path } => {
                Box::new(SoftwareBackend::new(keystore_path))
            }
            BackendConfig::File {
                keystore_dir,
                key_name,
            } => Box::new(FileBackend::new_with_key(keystore_dir, key_name)),
            BackendConfig::Environment { var_name } => Box::new(EnvironmentBackend::new(var_name)),
            BackendConfig::OsKeyring { key_name } => Box::new(OsKeyringBackend::new(key_name)),
            BackendConfig::Hsm { .. } => {
                return Err(SignerError::Config(
                    "HSM backend not yet implemented".to_string(),
                ));
            }
        };

        info!("Created keystore with backend: {}", backend.backend_type());

        Ok(Self { backend })
    }

    /// Initialize keystore and load/create keys
    pub async fn init(&mut self, config: Option<&str>) -> Result<(), SignerError> {
        info!(
            "Initializing keystore backend: {}",
            self.backend.backend_type()
        );

        // Validate backend configuration first
        self.backend.validate_config()?;

        // Initialize the backend
        self.backend.init(config).await?;

        info!("✅ Keystore initialized successfully");
        Ok(())
    }

    /// Get signing key (only available after init)
    pub async fn signing_key(&self) -> Result<SigningKey, SignerError> {
        let key_material = self.backend.load_key().await?;
        key_material.signing_key()
    }

    /// Get public key
    pub async fn public_key(&self) -> Result<Felt, SignerError> {
        let signing_key = self.signing_key().await?;
        Ok(signing_key.verifying_key().scalar())
    }

    /// Store a new key (if supported by backend)
    pub async fn store_key(&self, key_material: &KeyMaterial) -> Result<(), SignerError> {
        self.backend.store_key(key_material).await
    }

    /// Check if the keystore is available and properly configured
    pub fn is_available(&self) -> bool {
        self.backend.is_available()
    }

    /// Get the backend type as a string
    pub fn backend_type(&self) -> &'static str {
        self.backend.backend_type()
    }

    /// Create and save new encrypted keystore (software backend only)
    pub async fn create_keystore(
        keystore_path: &str,
        private_key_hex: &str,
        passphrase: &str,
    ) -> Result<(), SignerError> {
        SoftwareBackend::create_keystore(keystore_path, private_key_hex, passphrase).await
    }

    /// Validate keystore configuration without initializing
    pub fn validate_config(&self) -> Result<(), SignerError> {
        self.backend.validate_config()
    }

    /// Delete key from storage (if supported by backend)
    pub async fn delete_key(&self) -> Result<(), SignerError> {
        info!("Deleting key from {} backend", self.backend.backend_type());
        self.backend.delete_key().await
    }
}

/// Thread-safe keystore wrapper for use in async contexts
#[derive(Clone)]
pub struct SharedKeystore {
    inner: Arc<Mutex<Keystore>>,
}

impl SharedKeystore {
    /// Create a new shared keystore
    pub fn new(keystore: Keystore) -> Self {
        Self {
            inner: Arc::new(Mutex::new(keystore)),
        }
    }

    /// Initialize the keystore
    pub async fn init(&self, config: Option<&str>) -> Result<(), SignerError> {
        let mut keystore = self.inner.lock().await;
        keystore.init(config).await
    }

    /// Get signing key
    pub async fn signing_key(&self) -> Result<SigningKey, SignerError> {
        let keystore = self.inner.lock().await;
        keystore.signing_key().await
    }

    /// Get public key
    pub async fn public_key(&self) -> Result<Felt, SignerError> {
        let keystore = self.inner.lock().await;
        keystore.public_key().await
    }

    /// Check if available
    pub async fn is_available(&self) -> bool {
        let keystore = self.inner.lock().await;
        keystore.is_available()
    }

    /// Get backend type
    pub async fn backend_type(&self) -> String {
        let keystore = self.inner.lock().await;
        keystore.backend_type().to_string()
    }

    /// Delete key from storage
    pub async fn delete_key(&self) -> Result<(), SignerError> {
        let keystore = self.inner.lock().await;
        keystore.delete_key().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;

    #[tokio::test]
    async fn test_environment_keystore() {
        let private_key = "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef";
        std::env::set_var("TEST_PRIVATE_KEY", private_key);

        let config = BackendConfig::Environment {
            var_name: "TEST_PRIVATE_KEY".to_string(),
        };

        let mut keystore = Keystore::new(config).unwrap();
        assert_eq!(keystore.backend_type(), "environment");

        keystore.init(None).await.unwrap();

        let loaded_key = keystore.signing_key().await.unwrap();
        let expected_key = SigningKey::from_secret_scalar(Felt::from_hex(private_key).unwrap());

        assert_eq!(loaded_key.secret_scalar(), expected_key.secret_scalar());
    }

    #[tokio::test]
    async fn test_software_keystore() {
        let temp_file = NamedTempFile::new().unwrap();
        let keystore_path = temp_file.path().to_str().unwrap();
        let private_key = "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef";
        let passphrase = "test_password_123";

        // Create keystore
        Keystore::create_keystore(keystore_path, private_key, passphrase)
            .await
            .unwrap();

        // Load keystore
        let config = BackendConfig::Software {
            keystore_path: keystore_path.to_string(),
        };

        let mut keystore = Keystore::new(config).unwrap();
        assert_eq!(keystore.backend_type(), "software");

        keystore.init(Some(passphrase)).await.unwrap();

        let loaded_key = keystore.signing_key().await.unwrap();
        let expected_key = SigningKey::from_secret_scalar(Felt::from_hex(private_key).unwrap());

        assert_eq!(loaded_key.secret_scalar(), expected_key.secret_scalar());
    }

    #[test]
    fn test_keystore_backend_types() {
        let software_config = BackendConfig::Software {
            keystore_path: "/test/path".to_string(),
        };
        let keystore = Keystore::new(software_config).unwrap();
        assert_eq!(keystore.backend_type(), "software");

        let env_config = BackendConfig::Environment {
            var_name: "TEST_VAR".to_string(),
        };
        let keystore = Keystore::new(env_config).unwrap();
        assert_eq!(keystore.backend_type(), "environment");

        let keyring_config = BackendConfig::OsKeyring {
            key_name: "test-key".to_string(),
        };
        let keystore = Keystore::new(keyring_config).unwrap();
        assert_eq!(keystore.backend_type(), "os_keyring");
    }

    #[test]
    fn test_hsm_backend_not_implemented() {
        let hsm_config = BackendConfig::Hsm {
            device_path: "/dev/hsm0".to_string(),
        };

        let result = Keystore::new(hsm_config);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("not yet implemented"));
    }
}
