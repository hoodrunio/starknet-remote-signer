use async_trait::async_trait;
use std::fs;
use std::path::PathBuf;
use tracing::{info, warn};
use std::collections::HashMap;
use serde::{Deserialize, Serialize};

use crate::errors::SignerError;
use crate::keystore::backends::KeystoreBackend;
use crate::keystore::key_material::KeyMaterial;
use crate::keystore::encryption::{encrypt_key, decrypt_key};

/// File-based keystore backend using encrypted directory storage
/// Similar to Cosmos-SDK file keyring backend
#[derive(Debug)]
pub struct FileBackend {
    keystore_dir: PathBuf,
    selected_key_name: Option<String>,
    password: Option<String>,
    keys: HashMap<String, KeyMaterial>,
}

/// Metadata for the file keystore
#[derive(Serialize, Deserialize)]
struct KeystoreMetadata {
    /// Version for future compatibility
    pub version: u8,
    /// Created timestamp
    pub created: u64,
    /// Key names in this keystore
    pub keys: Vec<String>,
}

impl FileBackend {
    /// Create a new file backend
    pub fn new(keystore_dir: String) -> Self {
        Self {
            keystore_dir: PathBuf::from(keystore_dir),
            selected_key_name: None,
            password: None,
            keys: HashMap::new(),
        }
    }

    /// Create a new file backend with specific key name
    pub fn new_with_key(keystore_dir: String, key_name: Option<String>) -> Self {
        Self {
            keystore_dir: PathBuf::from(keystore_dir),
            selected_key_name: key_name,
            password: None,
            keys: HashMap::new(),
        }
    }

    /// Get the metadata file path
    fn metadata_path(&self) -> PathBuf {
        self.keystore_dir.join("keystore.json")
    }

    /// Get the key file path for a given key name
    fn key_file_path(&self, key_name: &str) -> PathBuf {
        self.keystore_dir.join(format!("{}.key", key_name))
    }

    /// Create keystore directory if it doesn't exist
    fn ensure_directory_exists(&self) -> Result<(), SignerError> {
        if !self.keystore_dir.exists() {
            fs::create_dir_all(&self.keystore_dir)
                .map_err(|e| SignerError::Config(format!("Failed to create keystore directory: {}", e)))?;
            
            // Set restrictive permissions (Unix only)
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let mut perms = fs::metadata(&self.keystore_dir)
                    .map_err(|e| SignerError::Config(format!("Failed to get directory metadata: {}", e)))?
                    .permissions();
                perms.set_mode(0o700); // rwx------
                fs::set_permissions(&self.keystore_dir, perms)
                    .map_err(|e| SignerError::Config(format!("Failed to set directory permissions: {}", e)))?;
            }
            
            info!("Created keystore directory: {}", self.keystore_dir.display());
        }
        Ok(())
    }

    /// Load or create metadata file
    fn load_metadata(&self) -> Result<KeystoreMetadata, SignerError> {
        let metadata_path = self.metadata_path();
        
        if metadata_path.exists() {
            let data = fs::read(&metadata_path)
                .map_err(|e| SignerError::Config(format!("Failed to read metadata: {}", e)))?;
            
            serde_json::from_slice(&data)
                .map_err(|e| SignerError::Config(format!("Failed to parse metadata: {}", e)))
        } else {
            // Create new metadata
            let metadata = KeystoreMetadata {
                version: 1,
                created: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs(),
                keys: Vec::new(),
            };
            Ok(metadata)
        }
    }

    /// Save metadata to file
    fn save_metadata(&self, metadata: &KeystoreMetadata) -> Result<(), SignerError> {
        let metadata_path = self.metadata_path();
        let data = serde_json::to_string_pretty(metadata)
            .map_err(|e| SignerError::Config(format!("Failed to serialize metadata: {}", e)))?;
        
        fs::write(&metadata_path, data)
            .map_err(|e| SignerError::Config(format!("Failed to write metadata: {}", e)))?;
        
        // Set restrictive permissions (Unix only)
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = fs::metadata(&metadata_path)
                .map_err(|e| SignerError::Config(format!("Failed to get metadata file metadata: {}", e)))?
                .permissions();
            perms.set_mode(0o600); // rw-------
            fs::set_permissions(&metadata_path, perms)
                .map_err(|e| SignerError::Config(format!("Failed to set metadata file permissions: {}", e)))?;
        }
        
        Ok(())
    }

    /// Load keys from the keystore directory (only selected key if specified, otherwise all)
    fn load_keys(&mut self, password: &str) -> Result<(), SignerError> {
        let metadata = self.load_metadata()?;
        
        if let Some(selected_key) = &self.selected_key_name {
            // Load only the selected key
            if metadata.keys.contains(selected_key) {
                let key_path = self.key_file_path(selected_key);
                if key_path.exists() {
                    let key_material = self.load_key_from_file(selected_key, password)?;
                    self.keys.insert(selected_key.clone(), key_material);
                    info!("Loaded selected key '{}' from file keystore", selected_key);
                } else {
                    return Err(SignerError::Config(format!(
                        "Selected key file '{}' not found at: {}",
                        selected_key,
                        key_path.display()
                    )));
                }
            } else {
                return Err(SignerError::Config(format!(
                    "Selected key '{}' not found in keystore metadata. Available keys: [{}]",
                    selected_key,
                    metadata.keys.join(", ")
                )));
            }
        } else {
            // Load all keys
            for key_name in &metadata.keys {
                let key_path = self.key_file_path(key_name);
                if key_path.exists() {
                    let key_material = self.load_key_from_file(key_name, password)?;
                    self.keys.insert(key_name.clone(), key_material);
                } else {
                    warn!("Key file not found: {}", key_path.display());
                }
            }
            info!("Loaded {} keys from file keystore", self.keys.len());
        }
        
        Ok(())
    }

    /// Load a specific key from file
    fn load_key_from_file(&self, key_name: &str, password: &str) -> Result<KeyMaterial, SignerError> {
        let key_path = self.key_file_path(key_name);
        
        let jwe_token = fs::read_to_string(&key_path)
            .map_err(|e| SignerError::Config(format!("Failed to read key file {}: {}", key_name, e)))?;

        let decrypted_key = decrypt_key(&jwe_token, password)?;
        Ok(KeyMaterial::from_bytes(decrypted_key))
    }

    /// Save a key to file
    fn save_key_to_file(&self, key_name: &str, key_material: &KeyMaterial, password: &str) -> Result<(), SignerError> {
        let key_path = self.key_file_path(key_name);
        
        let jwe_token = encrypt_key(key_material.raw_bytes(), password)?;

        fs::write(&key_path, &jwe_token)
            .map_err(|e| SignerError::Config(format!("Failed to write key file {}: {}", key_name, e)))?;

        // Set restrictive permissions (Unix only)
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = fs::metadata(&key_path)
                .map_err(|e| SignerError::Config(format!("Failed to get key file metadata: {}", e)))?
                .permissions();
            perms.set_mode(0o600); // rw-------
            fs::set_permissions(&key_path, perms)
                .map_err(|e| SignerError::Config(format!("Failed to set key file permissions: {}", e)))?;
        }

        info!("Saved key '{}' to file keystore", key_name);
        Ok(())
    }

    /// Add a key to the metadata
    fn add_key_to_metadata(&self, key_name: &str) -> Result<(), SignerError> {
        let mut metadata = self.load_metadata()?;
        
        if !metadata.keys.contains(&key_name.to_string()) {
            metadata.keys.push(key_name.to_string());
            self.save_metadata(&metadata)?;
        }
        
        Ok(())
    }

    /// Remove a key from the metadata
    fn remove_key_from_metadata(&self, key_name: &str) -> Result<(), SignerError> {
        let mut metadata = self.load_metadata()?;
        
        metadata.keys.retain(|k| k != key_name);
        self.save_metadata(&metadata)?;
        
        Ok(())
    }

    /// Create and save a new key
    pub async fn create_key(
        keystore_dir: &str,
        key_name: &str,
        private_key_hex: &str,
        password: &str,
    ) -> Result<(), SignerError> {
        let backend = FileBackend::new(keystore_dir.to_string());
        backend.ensure_directory_exists()?;
        
        let key_material = KeyMaterial::from_hex(private_key_hex)?;
        backend.save_key_to_file(key_name, &key_material, password)?;
        backend.add_key_to_metadata(key_name)?;
        
        info!("Created key '{}' in file keystore at: {}", key_name, keystore_dir);
        Ok(())
    }

    /// List all available keys
    pub fn list_keys(&self) -> Result<Vec<String>, SignerError> {
        let metadata = self.load_metadata()?;
        Ok(metadata.keys)
    }

    /// Check if a specific key exists
    pub fn has_key(&self, key_name: &str) -> bool {
        self.keys.contains_key(key_name) || self.key_file_path(key_name).exists()
    }

    /// Delete a specific key
    pub async fn delete_key(&self, key_name: &str) -> Result<(), SignerError> {
        let key_path = self.key_file_path(key_name);
        
        if key_path.exists() {
            fs::remove_file(&key_path)
                .map_err(|e| SignerError::Config(format!("Failed to delete key file {}: {}", key_name, e)))?;
        }
        
        self.remove_key_from_metadata(key_name)?;
        
        info!("Deleted key '{}' from file keystore", key_name);
        Ok(())
    }

    /// Get the key name to use (selected key or first available)
    fn get_active_key_name(&self) -> Result<String, SignerError> {
        if self.keys.is_empty() {
            return Err(SignerError::Config("No keys available in keystore".to_string()));
        }

        // If specific key name is selected, use it
        if let Some(selected_key) = &self.selected_key_name {
            if self.keys.contains_key(selected_key) {
                return Ok(selected_key.clone());
            } else {
                return Err(SignerError::Config(format!(
                    "Selected key '{}' not found in keystore. Available keys: [{}]",
                    selected_key,
                    self.keys.keys().cloned().collect::<Vec<_>>().join(", ")
                )));
            }
        }

        // Otherwise, return the first key
        Ok(self.keys.keys().next().unwrap().clone())
    }
}

#[async_trait]
impl KeystoreBackend for FileBackend {
    async fn init(&mut self, config: Option<&str>) -> Result<(), SignerError> {
        let password = config.ok_or_else(|| {
            SignerError::Config("Password required for file keystore".to_string())
        })?;

        self.ensure_directory_exists()?;
        
        // Check if keystore directory exists and has keys
        let metadata_path = self.metadata_path();
        if !metadata_path.exists() {
            warn!("File keystore not initialized at: {}", self.keystore_dir.display());
            warn!("Use 'create-key' command to add keys to the keystore");
            return Ok(()); // Not an error, just empty keystore
        }

        self.password = Some(password.to_string());
        self.load_keys(password)?;
        
        if self.keys.is_empty() {
            warn!("No keys found in file keystore: {}", self.keystore_dir.display());
        }
        
        Ok(())
    }

    async fn store_key(&self, key_material: &KeyMaterial) -> Result<(), SignerError> {
        let password = self.password.as_ref()
            .ok_or_else(|| SignerError::Config("File keystore not initialized".to_string()))?;

        // For this implementation, we'll use a default key name
        // In a full implementation, this would be configurable
        let key_name = "default";
        
        self.save_key_to_file(key_name, key_material, password)?;
        self.add_key_to_metadata(key_name)?;
        
        Ok(())
    }

    async fn load_key(&self) -> Result<KeyMaterial, SignerError> {
        if self.keys.is_empty() {
            return Err(SignerError::Config("No keys available in keystore".to_string()));
        }

        let key_name = self.get_active_key_name()?;
        self.keys.get(&key_name)
            .ok_or_else(|| SignerError::Config(format!("Key '{}' not found", key_name)))
            .map(|km| KeyMaterial::from_bytes(*km.raw_bytes()))
    }

    fn is_available(&self) -> bool {
        let metadata_path = self.metadata_path();
        metadata_path.exists() && !self.keys.is_empty()
    }

    fn backend_type(&self) -> &'static str {
        "file"
    }

    fn validate_config(&self) -> Result<(), SignerError> {
        // Check if directory exists or can be created
        if let Some(parent) = self.keystore_dir.parent() {
            if !parent.exists() {
                return Err(SignerError::Config(format!(
                    "Parent directory does not exist: {}", 
                    parent.display()
                )));
            }
        }

        // Check write permissions if directory exists
        if self.keystore_dir.exists() {
            let test_file = self.keystore_dir.join(".test_write");
            match fs::write(&test_file, "test") {
                Ok(()) => {
                    let _ = fs::remove_file(&test_file);
                }
                Err(e) => {
                    return Err(SignerError::Config(format!(
                        "Cannot write to keystore directory {}: {}", 
                        self.keystore_dir.display(), 
                        e
                    )));
                }
            }
        }

        Ok(())
    }

    async fn delete_key(&self) -> Result<(), SignerError> {
        if self.keys.is_empty() {
            return Err(SignerError::Config("No keys to delete".to_string()));
        }

        let key_name = self.get_active_key_name()?;
        self.delete_key(&key_name).await
    }
}

impl Drop for FileBackend {
    fn drop(&mut self) {
        // Clear sensitive data from memory
        self.password = None;
        self.keys.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[tokio::test]
    async fn test_file_backend_creation() {
        let temp_dir = TempDir::new().unwrap();
        let keystore_path = temp_dir.path().to_str().unwrap();
        
        let backend = FileBackend::new(keystore_path.to_string());
        assert_eq!(backend.backend_type(), "file");
        assert_eq!(backend.keystore_dir, PathBuf::from(keystore_path));
    }

    #[tokio::test]
    async fn test_create_and_load_key() {
        let temp_dir = TempDir::new().unwrap();
        let keystore_path = temp_dir.path().to_str().unwrap();
        let private_key = "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef";
        let password = "test_password_123";
        let key_name = "test_key";

        // Create key
        FileBackend::create_key(keystore_path, key_name, private_key, password)
            .await
            .unwrap();

        // Load keystore
        let mut backend = FileBackend::new(keystore_path.to_string());
        backend.init(Some(password)).await.unwrap();
        
        assert!(backend.is_available());
        assert!(backend.has_key(key_name));
        
        let loaded_key = backend.load_key().await.unwrap();
        assert_eq!(loaded_key.to_hex(), private_key);
    }

    #[tokio::test]
    async fn test_multiple_keys() {
        let temp_dir = TempDir::new().unwrap();
        let keystore_path = temp_dir.path().to_str().unwrap();
        let password = "test_password_123";

        // Create multiple keys
        FileBackend::create_key(
            keystore_path, 
            "key1", 
            "1111111111111111111111111111111111111111111111111111111111111111", 
            password
        ).await.unwrap();
        
        FileBackend::create_key(
            keystore_path, 
            "key2", 
            "2222222222222222222222222222222222222222222222222222222222222222", 
            password
        ).await.unwrap();

        // Load keystore
        let mut backend = FileBackend::new(keystore_path.to_string());
        backend.init(Some(password)).await.unwrap();
        
        let keys = backend.list_keys().unwrap();
        assert_eq!(keys.len(), 2);
        assert!(keys.contains(&"key1".to_string()));
        assert!(keys.contains(&"key2".to_string()));
    }

    #[test]
    fn test_validate_config() {
        let temp_dir = TempDir::new().unwrap();
        let keystore_path = temp_dir.path().to_str().unwrap();
        
        let backend = FileBackend::new(keystore_path.to_string());
        assert!(backend.validate_config().is_ok());
    }

    #[test]
    fn test_invalid_directory() {
        let backend = FileBackend::new("/nonexistent/parent/dir".to_string());
        assert!(backend.validate_config().is_err());
    }
} 