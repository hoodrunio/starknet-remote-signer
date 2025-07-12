use starknet::signers::SigningKey;
use starknet_crypto::Felt;
use tracing::info;

use crate::errors::SignerError;
use crate::keystore::backends::{BackendConfig, KeystoreBackend};
use crate::keystore::key_material::KeyMaterial;

// Re-export backend implementations
use crate::keystore::backends::{
    EnvironmentBackend, FileBackend, OsKeyringBackend, SoftwareBackend,
};

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
