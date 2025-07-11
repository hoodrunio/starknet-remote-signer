use async_trait::async_trait;
use tracing::{info, warn};

use crate::errors::SignerError;
use crate::keystore::backends::KeystoreBackend;
use crate::keystore::key_material::KeyMaterial;

/// OS Keyring backend for secure system-level key storage
pub struct OsKeyringBackend {
    key_name: String,
    key_material: Option<KeyMaterial>,
}

impl OsKeyringBackend {
    /// Create a new OS keyring backend with a key name
    /// Service is always "starknet-signer"
    pub fn new(key_name: String) -> Self {
        Self {
            key_name,
            key_material: None,
        }
    }

    /// Get the service name (always "starknet-signer")
    fn service_name() -> &'static str {
        "starknet-signer"
    }

    /// Store key in OS keyring
    fn store_key_in_keyring(&self, private_key_hex: &str) -> Result<(), SignerError> {
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        {
            use keyring::Entry;
            
            info!("Creating keyring entry for service: '{}', account: '{}'", Self::service_name(), self.key_name);
            let entry = Entry::new(Self::service_name(), &self.key_name)
                .map_err(|e| SignerError::Config(format!("Failed to create keyring entry: {}", e)))?;
            
            info!("Storing key in keyring...");
            entry.set_password(private_key_hex)
                .map_err(|e| SignerError::Config(format!("Failed to store key in keyring: {}", e)))?;
            
            info!("✅ Stored private key '{}' in OS keyring", self.key_name);
            
            // Verify the key was stored by trying to retrieve it
            info!("Verifying key storage...");
            match entry.get_password() {
                Ok(retrieved) => {
                    if retrieved == private_key_hex {
                        info!("✅ Key verification successful");
                    } else {
                        warn!("⚠️  Key verification failed: retrieved key doesn't match stored key");
                    }
                }
                Err(e) => {
                    warn!("⚠️  Key verification failed: {}", e);
                }
            }
            
            Ok(())
        }
        
        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        {
            Err(SignerError::Config(
                "OS keyring backend is only supported on Linux and macOS".to_string()
            ))
        }
    }

    /// Load key from OS keyring
    fn load_key_from_keyring(&mut self) -> Result<(), SignerError> {
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        {
            use keyring::Entry;
            
            let entry = Entry::new(Self::service_name(), &self.key_name)
                .map_err(|e| SignerError::Config(format!("Failed to create keyring entry: {}", e)))?;
            
            let private_key_hex = entry.get_password()
                .map_err(|e| SignerError::Config(format!("Failed to load key from keyring: {}", e)))?;

            // Validate the retrieved key
            if private_key_hex.is_empty() {
                return Err(SignerError::InvalidKey("Retrieved private key is empty".to_string()));
            }

            if !private_key_hex.chars().all(|c| c.is_ascii_hexdigit()) {
                return Err(SignerError::InvalidKey("Retrieved private key is not valid hex".to_string()));
            }

            if private_key_hex.len() != 64 {
                return Err(SignerError::InvalidKey("Retrieved private key has invalid length".to_string()));
            }

            self.key_material = Some(KeyMaterial::from_hex(&private_key_hex)?);
            info!("Loaded private key '{}' from OS keyring", self.key_name);
            Ok(())
        }
        
        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        {
            Err(SignerError::Config(
                "OS keyring backend is only supported on Linux and macOS".to_string()
            ))
        }
    }

    /// Check if key exists in keyring
    fn key_exists_in_keyring(&self) -> bool {
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        {
            use keyring::Entry;
            
            if let Ok(entry) = Entry::new(Self::service_name(), &self.key_name) {
                entry.get_password().is_ok()
            } else {
                false
            }
        }
        
        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        {
            false
        }
    }

    /// Delete key from keyring
    fn delete_key_from_keyring(&self) -> Result<(), SignerError> {
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        {
            use keyring::Entry;
            
            info!("Creating keyring entry for deletion - service: '{}', account: '{}'", Self::service_name(), self.key_name);
            let entry = Entry::new(Self::service_name(), &self.key_name)
                .map_err(|e| SignerError::Config(format!("Failed to create keyring entry: {}", e)))?;
            
            // First check if the key exists
            info!("Checking if key exists before deletion...");
            match entry.get_password() {
                Ok(_) => {
                    info!("✅ Key found, proceeding with deletion");
                }
                Err(e) => {
                    warn!("⚠️  Key not found in keyring: {}", e);
                    return Err(SignerError::Config(format!("Key '{}' not found in keyring: {}", self.key_name, e)));
                }
            }
            
            info!("Deleting key from keyring...");
            entry.delete_credential()
                .map_err(|e| SignerError::Config(format!("Failed to delete key from keyring: {}", e)))?;
            
            info!("✅ Deleted private key '{}' from OS keyring", self.key_name);
            Ok(())
        }
        
        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        {
            Err(SignerError::Config(
                "OS keyring backend is only supported on Linux and macOS".to_string()
            ))
        }
    }

    /// Check OS keyring availability
    fn check_keyring_availability() -> Result<(), SignerError> {
        #[cfg(target_os = "linux")]
        {
            // Check if we're in a desktop session or have access to D-Bus
            if std::env::var("XDG_RUNTIME_DIR").is_err() && std::env::var("DBUS_SESSION_BUS_ADDRESS").is_err() {
                warn!("⚠️  No desktop session detected. OS keyring may not be available.");
                warn!("⚠️  Consider running in a user session or using a different backend.");
            }
            Ok(())
        }

        #[cfg(target_os = "macos")]
        {
            // macOS keychain should always be available
            Ok(())
        }

        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        {
            Err(SignerError::Config(
                "OS keyring backend is only supported on Linux and macOS".to_string()
            ))
        }
    }
}

#[async_trait]
impl KeystoreBackend for OsKeyringBackend {
    async fn init(&mut self, _config: Option<&str>) -> Result<(), SignerError> {
        Self::check_keyring_availability()?;
        
        // Only try to load the key if it exists in the keyring
        // This allows for operations like delete without requiring the key to be loaded first
        if self.key_exists_in_keyring() {
            self.load_key_from_keyring()?;
        }
        
        Ok(())
    }

    async fn store_key(&self, key_material: &KeyMaterial) -> Result<(), SignerError> {
        Self::check_keyring_availability()?;
        let private_key_hex = key_material.to_hex();
        self.store_key_in_keyring(&private_key_hex)?;
        Ok(())
    }

    async fn load_key(&self) -> Result<KeyMaterial, SignerError> {
        self.key_material
            .as_ref()
            .ok_or_else(|| SignerError::Config("Keystore not initialized".to_string()))
            .map(|km| KeyMaterial::from_bytes(*km.raw_bytes()))
    }

    fn is_available(&self) -> bool {
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        {
            Self::check_keyring_availability().is_ok() && self.key_exists_in_keyring()
        }
        
        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        {
            false
        }
    }

    fn backend_type(&self) -> &'static str {
        "os_keyring"
    }

    fn validate_config(&self) -> Result<(), SignerError> {
        Self::check_keyring_availability()?;
        
        if self.key_name.is_empty() {
            return Err(SignerError::Config("Key name cannot be empty".to_string()));
        }

        // Additional platform-specific warnings
        #[cfg(target_os = "linux")]
        {
            info!("OS Keyring: Using Linux Secret Service (GNOME Keyring/KDE Wallet)");
            info!("Service: '{}', Key: '{}'", Self::service_name(), self.key_name);
            if std::env::var("XDG_RUNTIME_DIR").is_err() {
                warn!("XDG_RUNTIME_DIR not set - keyring may not be accessible");
            }
        }

        #[cfg(target_os = "macos")]
        {
            info!("OS Keyring: Using macOS Keychain");
            info!("Service: '{}', Key: '{}'", Self::service_name(), self.key_name);
        }

        Ok(())
    }

    async fn delete_key(&self) -> Result<(), SignerError> {
        Self::check_keyring_availability()?;
        self.delete_key_from_keyring()?;
        Ok(())
    }
}

impl Drop for OsKeyringBackend {
    fn drop(&mut self) {
        // Clear key material from memory
        self.key_material = None;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keyring_backend_creation() {
        let backend = OsKeyringBackend::new("validator-mainnet".to_string());
        
        assert_eq!(backend.backend_type(), "os_keyring");
        assert_eq!(backend.key_name, "validator-mainnet");
        assert_eq!(OsKeyringBackend::service_name(), "starknet-signer");
    }

    #[test]
    fn test_validate_config() {
        let backend = OsKeyringBackend::new("validator-mainnet".to_string());

        // Should pass basic validation on supported platforms
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        assert!(backend.validate_config().is_ok());

        // Should fail on unsupported platforms
        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        assert!(backend.validate_config().is_err());
    }

    #[test]
    fn test_empty_key_name_validation() {
        let backend = OsKeyringBackend::new("".to_string());
        assert!(backend.validate_config().is_err());
    }
} 