use async_trait::async_trait;
use std::fs;
use std::path::Path;
use tracing::{info, warn};

use crate::errors::SignerError;
use crate::keystore::backends::KeystoreBackend;
use crate::keystore::key_material::KeyMaterial;
use crate::keystore::encryption::{encrypt_key, decrypt_key, EncryptedKeystore};

/// Software-based keystore backend using encrypted files
pub struct SoftwareBackend {
    keystore_path: String,
    key_material: Option<KeyMaterial>,
}

impl SoftwareBackend {
    /// Create a new software backend
    pub fn new(keystore_path: String) -> Self {
        Self {
            keystore_path,
            key_material: None,
        }
    }

    /// Create and save new encrypted keystore
    pub async fn create_keystore(
        keystore_path: &str,
        private_key_hex: &str,
        passphrase: &str,
    ) -> Result<(), SignerError> {
        let key_material = KeyMaterial::from_hex(private_key_hex)?;
        let encrypted_keystore = encrypt_key(key_material.raw_bytes(), passphrase)?;

        let serialized = serde_json::to_string_pretty(&encrypted_keystore)
            .map_err(|e| SignerError::Config(format!("Failed to serialize keystore: {}", e)))?;

        fs::write(keystore_path, serialized)
            .map_err(|e| SignerError::Config(format!("Failed to write keystore: {}", e)))?;

        // Set restrictive permissions (Unix only)
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = fs::metadata(keystore_path)
                .map_err(|e| SignerError::Config(format!("Failed to get keystore metadata: {}", e)))?
                .permissions();
            perms.set_mode(0o600); // rw-------
            fs::set_permissions(keystore_path, perms)
                .map_err(|e| SignerError::Config(format!("Failed to set keystore permissions: {}", e)))?;
        }

        info!("Created encrypted keystore at: {}", keystore_path);
        Ok(())
    }

    /// Load encrypted software key
    async fn load_software_key(&mut self, passphrase: &str) -> Result<(), SignerError> {
        let encrypted_data = fs::read(&self.keystore_path)
            .map_err(|e| SignerError::Config(format!("Failed to read keystore: {}", e)))?;

        let keystore: EncryptedKeystore = serde_json::from_slice(&encrypted_data)
            .map_err(|e| SignerError::Config(format!("Failed to parse keystore: {}", e)))?;

        let decrypted_key = decrypt_key(&keystore, passphrase)?;
        self.key_material = Some(KeyMaterial::from_bytes(decrypted_key));

        info!("Loaded encrypted keystore from: {}", self.keystore_path);
        Ok(())
    }
}

#[async_trait]
impl KeystoreBackend for SoftwareBackend {
    async fn init(&mut self, config: Option<&str>) -> Result<(), SignerError> {
        let passphrase = config.ok_or_else(|| {
            SignerError::Config("Passphrase required for encrypted keystore".to_string())
        })?;

        let path = Path::new(&self.keystore_path);
        
        if !path.exists() {
            return Err(SignerError::Config(format!(
                "Keystore file {} does not exist. Use 'init' command to create it.",
                self.keystore_path
            )));
        }

        self.load_software_key(passphrase).await?;
        Ok(())
    }

    async fn store_key(&self, _key_material: &KeyMaterial) -> Result<(), SignerError> {
        // For software backend, we don't support runtime key storage
        // Keys are created via the init command
        Err(SignerError::Config(
            "Software backend does not support runtime key storage. Use 'init' command to create keystore.".to_string()
        ))
    }

    async fn load_key(&self) -> Result<KeyMaterial, SignerError> {
        self.key_material
            .as_ref()
            .ok_or_else(|| SignerError::Config("Keystore not initialized".to_string()))
            .map(|km| KeyMaterial::from_bytes(*km.raw_bytes()))
    }

    fn is_available(&self) -> bool {
        Path::new(&self.keystore_path).exists()
    }

    fn backend_type(&self) -> &'static str {
        "software"
    }

    fn validate_config(&self) -> Result<(), SignerError> {
        let path = Path::new(&self.keystore_path);
        
        if !path.exists() {
            warn!("Keystore file does not exist: {}", self.keystore_path);
            return Ok(()); // Not an error during validation, will fail at init
        }

        // Check if file is readable
        fs::metadata(&self.keystore_path)
            .map_err(|e| SignerError::Config(format!("Cannot access keystore file: {}", e)))?;

        Ok(())
    }
} 