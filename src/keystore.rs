use anyhow::Result;
use rand::{RngCore, rngs::OsRng};
use serde::{Deserialize, Serialize};
use starknet::signers::SigningKey;
use starknet_crypto::Felt;
use std::path::Path;
use std::fs;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::errors::SignerError;

/// Key derivation parameters for PBKDF2
const PBKDF2_ITERATIONS: u32 = 100_000;
const SALT_SIZE: usize = 32;
const KEY_SIZE: usize = 32;

/// Encrypted key storage format
#[derive(Serialize, Deserialize)]
pub struct EncryptedKeystore {
    /// PBKDF2 salt
    pub salt: Vec<u8>,
    /// Encrypted private key
    pub encrypted_key: Vec<u8>,
    /// AES-GCM nonce
    pub nonce: Vec<u8>,
    /// Key derivation iterations
    pub iterations: u32,
    /// Version for future compatibility
    pub version: u8,
}

/// In-memory key material that gets zeroized on drop
#[derive(ZeroizeOnDrop)]
pub struct KeyMaterial {
    private_key: [u8; 32],
}

impl KeyMaterial {
    /// Create key material from a hex string
    pub fn from_hex(hex_key: &str) -> Result<Self, SignerError> {
        let key_felt = Felt::from_hex(hex_key)
                                .map_err(|e| SignerError::InvalidKey(format!("Invalid private key hex: {}", e)))?;
        
        let key_bytes = key_felt.to_bytes_be();
        
        Ok(Self {
            private_key: key_bytes,
        })
    }

    /// Create key material from bytes
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self {
            private_key: bytes,
        }
    }

    /// Get the signing key
    pub fn signing_key(&self) -> Result<SigningKey, SignerError> {
        let felt = Felt::from_bytes_be(&self.private_key);
        Ok(SigningKey::from_secret_scalar(felt))
    }

    /// Get the private key as Felt
    pub fn as_felt(&self) -> Felt {
        Felt::from_bytes_be(&self.private_key)
    }
}

/// Key storage backend types
#[derive(Debug, Clone)]
pub enum KeystoreBackend {
    /// Software-based encrypted storage
    Software { keystore_path: String },
    /// Environment variable (less secure, for development)
    Environment { var_name: String },
    /// Hardware Security Module (future)
    #[allow(dead_code)]
    Hsm { device_path: String },
}

/// Main keystore for managing validator keys
pub struct Keystore {
    backend: KeystoreBackend,
    key_material: Option<KeyMaterial>,
}

impl Keystore {
    /// Create a new keystore with the specified backend
    pub fn new(backend: KeystoreBackend) -> Self {
        Self {
            backend,
            key_material: None,
        }
    }

    /// Initialize keystore and load/create keys
    pub async fn init(&mut self, passphrase: Option<&str>) -> Result<(), SignerError> {
        let backend = self.backend.clone();
        match backend {
            KeystoreBackend::Software { keystore_path } => {
                self.load_or_create_software_key(&keystore_path, passphrase).await?;
            }
            KeystoreBackend::Environment { var_name } => {
                self.load_environment_key(&var_name)?;
            }
            KeystoreBackend::Hsm { .. } => {
                return Err(SignerError::Config(
                    "HSM backend not yet implemented".to_string()
                ));
            }
        }
        Ok(())
    }

    /// Get signing key (only available after init)
    pub fn signing_key(&self) -> Result<SigningKey, SignerError> {
        self.key_material
            .as_ref()
            .ok_or_else(|| SignerError::Config("Keystore not initialized".to_string()))?
            .signing_key()
    }

    /// Get public key
    pub fn public_key(&self) -> Result<Felt, SignerError> {
        let signing_key = self.signing_key()?;
        Ok(signing_key.verifying_key().scalar())
    }

    /// Load key from environment variable
    fn load_environment_key(&mut self, var_name: &str) -> Result<(), SignerError> {
        let private_key_hex = std::env::var(var_name)
            .map_err(|_| SignerError::Config(format!("Environment variable {} not set", var_name)))?;

        self.key_material = Some(KeyMaterial::from_hex(&private_key_hex)?);
        Ok(())
    }

    /// Load or create encrypted software key
    async fn load_or_create_software_key(
        &mut self, 
        keystore_path: &str, 
        passphrase: Option<&str>
    ) -> Result<(), SignerError> {
        let path = Path::new(keystore_path);
        
        if path.exists() {
            // Load existing keystore
            self.load_software_key(keystore_path, passphrase).await?;
        } else {
            // Create new keystore
            return Err(SignerError::Config(format!(
                "Keystore file {} does not exist. Use 'init' command to create it.",
                keystore_path
            )));
        }
        
        Ok(())
    }

    /// Load encrypted software key
    async fn load_software_key(
        &mut self, 
        keystore_path: &str, 
        passphrase: Option<&str>
    ) -> Result<(), SignerError> {
        let passphrase = passphrase.ok_or_else(|| {
            SignerError::Config("Passphrase required for encrypted keystore".to_string())
        })?;

        let encrypted_data = fs::read(keystore_path)
            .map_err(|e| SignerError::Config(format!("Failed to read keystore: {}", e)))?;

        let keystore: EncryptedKeystore = serde_json::from_slice(&encrypted_data)
            .map_err(|e| SignerError::Config(format!("Failed to parse keystore: {}", e)))?;

        let decrypted_key = decrypt_key(&keystore, passphrase)?;
        self.key_material = Some(KeyMaterial::from_bytes(decrypted_key));

        Ok(())
    }

    /// Create and save new encrypted keystore
    pub async fn create_keystore(
        keystore_path: &str,
        private_key_hex: &str,
        passphrase: &str,
    ) -> Result<(), SignerError> {
        let key_material = KeyMaterial::from_hex(private_key_hex)?;
        let encrypted_keystore = encrypt_key(&key_material.private_key, passphrase)?;

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

        Ok(())
    }
}

/// Encrypt private key using AES-256-GCM with PBKDF2 key derivation
fn encrypt_key(private_key: &[u8; 32], passphrase: &str) -> Result<EncryptedKeystore, SignerError> {
    use aes_gcm::{Aes256Gcm, KeyInit, aead::Aead};
    use pbkdf2::pbkdf2_hmac;
    use sha2::Sha256;

    // Generate random salt and nonce
    let mut salt = [0u8; SALT_SIZE];
    let mut nonce = [0u8; 12]; // GCM nonce is 12 bytes
    OsRng.fill_bytes(&mut salt);
    OsRng.fill_bytes(&mut nonce);

    // Derive key from passphrase
    let mut derived_key = [0u8; KEY_SIZE];
    pbkdf2_hmac::<Sha256>(passphrase.as_bytes(), &salt, PBKDF2_ITERATIONS, &mut derived_key);

    // Encrypt the private key
    let cipher = Aes256Gcm::new((&derived_key).into());
    let encrypted_key = cipher.encrypt((&nonce).into(), private_key.as_ref())
        .map_err(|e| SignerError::Crypto(format!("Encryption failed: {}", e)))?;

    // Zeroize sensitive data
    derived_key.zeroize();

    Ok(EncryptedKeystore {
        salt: salt.to_vec(),
        encrypted_key,
        nonce: nonce.to_vec(),
        iterations: PBKDF2_ITERATIONS,
        version: 1,
    })
}

/// Decrypt private key
fn decrypt_key(keystore: &EncryptedKeystore, passphrase: &str) -> Result<[u8; 32], SignerError> {
    use aes_gcm::{Aes256Gcm, KeyInit, aead::Aead};
    use pbkdf2::pbkdf2_hmac;
    use sha2::Sha256;

    // Derive key from passphrase
    let mut derived_key = [0u8; KEY_SIZE];
    pbkdf2_hmac::<Sha256>(
        passphrase.as_bytes(), 
        &keystore.salt, 
        keystore.iterations, 
        &mut derived_key
    );

    // Decrypt the private key
    let cipher = Aes256Gcm::new((&derived_key).into());
    let nonce_slice = keystore.nonce.as_slice();
    let decrypted = cipher.decrypt(nonce_slice.into(), keystore.encrypted_key.as_ref())
        .map_err(|e| SignerError::Crypto(format!("Decryption failed: {}", e)))?;

    // Zeroize sensitive data
    derived_key.zeroize();

    if decrypted.len() != 32 {
                        return Err(SignerError::InvalidKey("Invalid decrypted key length".to_string()));
    }

    let mut key = [0u8; 32];
    key.copy_from_slice(&decrypted);
    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;

    #[tokio::test]
    async fn test_keystore_create_and_load() {
        let temp_file = NamedTempFile::new().unwrap();
        let keystore_path = temp_file.path().to_str().unwrap();
        let private_key = "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef";
        let passphrase = "test_password_123";

        // Create keystore
        Keystore::create_keystore(keystore_path, private_key, passphrase)
            .await
            .unwrap();

        // Load keystore
        let mut keystore = Keystore::new(KeystoreBackend::Software {
            keystore_path: keystore_path.to_string(),
        });
        
        keystore.init(Some(passphrase)).await.unwrap();
        
        let loaded_key = keystore.signing_key().unwrap();
        let expected_key = SigningKey::from_secret_scalar(Felt::from_hex(private_key).unwrap());
        
        assert_eq!(loaded_key.secret_scalar(), expected_key.secret_scalar());
    }

    #[test]
    fn test_environment_keystore() {
        let private_key = "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef";
        std::env::set_var("TEST_PRIVATE_KEY", private_key);

        let mut keystore = Keystore::new(KeystoreBackend::Environment {
            var_name: "TEST_PRIVATE_KEY".to_string(),
        });

        keystore.load_environment_key("TEST_PRIVATE_KEY").unwrap();
        let signing_key = keystore.signing_key().unwrap();
        
        assert_eq!(
            signing_key.secret_scalar(),
            Felt::from_hex(private_key).unwrap()
        );
    }
} 