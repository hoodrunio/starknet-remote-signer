use async_trait::async_trait;
use tracing::{info, warn};

use crate::errors::SignerError;
use crate::keystore::backends::KeystoreBackend;
use crate::keystore::key_material::KeyMaterial;

/// OS Keyring backend for secure system-level key storage
#[derive(Debug)]
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

    /// Check if keyring is available on this platform
    fn check_keyring_availability() -> Result<(), SignerError> {
        #[cfg(target_env = "musl")]
        {
            warn!("⚠️  MUSL target detected: OS keyring functionality is limited");
            warn!("⚠️  D-Bus integration is not available for static MUSL builds");
            warn!("⚠️  Consider using file or software backend for MUSL deployments");
            return Err(SignerError::Config(
                "OS keyring backend has limited functionality on MUSL targets due to D-Bus limitations. Use file or software backend instead.".to_string(),
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
            // Check if we have D-Bus available (required for linux-native-sync-persistent)
            if std::env::var("DBUS_SESSION_BUS_ADDRESS").is_err() {
                warn!("⚠️  D-Bus session bus not available, keyring functionality may be limited");
            }
        }

        Ok(())
    }

    /// Store key in OS keyring
    fn store_key_in_keyring(&self, private_key_hex: &str) -> Result<(), SignerError> {
        #[cfg(all(any(target_os = "linux", target_os = "macos"), not(target_env = "musl")))]
        {
            use keyring::Entry;

            info!(
                "Creating keyring entry for service: '{}', account: '{}'",
                Self::service_name(),
                self.key_name
            );
            let entry = Entry::new(Self::service_name(), &self.key_name)
                .map_err(|e| SignerError::Config(format!("Failed to create keyring entry: {e}")))?;

            info!("Storing key in keyring...");
            entry
                .set_password(private_key_hex)
                .map_err(|e| SignerError::Config(format!("Failed to store key in keyring: {e}")))?;

            info!("✅ Stored private key '{}' in OS keyring", self.key_name);

            // Verify the key was stored by trying to retrieve it
            info!("Verifying key storage...");
            match entry.get_password() {
                Ok(retrieved) => {
                    if retrieved == private_key_hex {
                        info!("✅ Key verification successful");
                    } else {
                        warn!(
                            "⚠️  Key verification failed: retrieved key doesn't match stored key"
                        );
                    }
                }
                Err(e) => {
                    warn!("⚠️  Key verification failed: {}", e);
                }
            }

            Ok(())
        }

        #[cfg(target_env = "musl")]
        {
            Err(SignerError::Config(
                "OS keyring backend is not available on MUSL targets due to D-Bus limitations".to_string(),
            ))
        }

        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        {
            Err(SignerError::Config(
                "OS keyring backend is only supported on Linux and macOS".to_string(),
            ))
        }
    }

    /// Load key from OS keyring
    fn load_key_from_keyring(&mut self) -> Result<(), SignerError> {
        #[cfg(all(any(target_os = "linux", target_os = "macos"), not(target_env = "musl")))]
        {
            use keyring::Entry;

            let entry = Entry::new(Self::service_name(), &self.key_name)
                .map_err(|e| SignerError::Config(format!("Failed to create keyring entry: {e}")))?;

            let private_key_hex = entry.get_password().map_err(|e| {
                SignerError::Config(format!("Failed to load key from keyring: {e}"))
            })?;

            // Validate the retrieved key
            if private_key_hex.is_empty() {
                return Err(SignerError::InvalidKey(
                    "Retrieved private key is empty".to_string(),
                ));
            }

            if !private_key_hex.chars().all(|c| c.is_ascii_hexdigit()) {
                return Err(SignerError::InvalidKey(
                    "Retrieved private key is not valid hex".to_string(),
                ));
            }

            if private_key_hex.len() != 64 {
                return Err(SignerError::InvalidKey(
                    "Retrieved private key has invalid length".to_string(),
                ));
            }

            self.key_material = Some(KeyMaterial::from_hex(&private_key_hex)?);
            info!("Loaded private key '{}' from OS keyring", self.key_name);
            Ok(())
        }

        #[cfg(target_env = "musl")]
        {
            Err(SignerError::Config(
                "OS keyring backend is not available on MUSL targets due to D-Bus limitations".to_string(),
            ))
        }

        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        {
            Err(SignerError::Config(
                "OS keyring backend is only supported on Linux and macOS".to_string(),
            ))
        }
    }

    /// Check if key exists in keyring
    fn key_exists_in_keyring(&self) -> bool {
        #[cfg(all(any(target_os = "linux", target_os = "macos"), not(target_env = "musl")))]
        {
            use keyring::Entry;

            if let Ok(entry) = Entry::new(Self::service_name(), &self.key_name) {
                entry.get_password().is_ok()
            } else {
                false
            }
        }

        #[cfg(any(target_env = "musl", not(any(target_os = "linux", target_os = "macos"))))]
        {
            false
        }
    }

    /// Delete key from keyring
    fn delete_key_from_keyring(&self) -> Result<(), SignerError> {
        #[cfg(all(any(target_os = "linux", target_os = "macos"), not(target_env = "musl")))]
        {
            use keyring::Entry;

            info!(
                "Creating keyring entry for deletion - service: '{}', account: '{}'",
                Self::service_name(),
                self.key_name
            );
            let entry = Entry::new(Self::service_name(), &self.key_name)
                .map_err(|e| SignerError::Config(format!("Failed to create keyring entry: {e}")))?;

            // First check if the key exists
            info!("Checking if key exists before deletion...");
            match entry.get_password() {
                Ok(_) => {
                    info!("✅ Key found, proceeding with deletion");
                }
                Err(e) => {
                    warn!("⚠️  Key not found in keyring: {}", e);
                    return Err(SignerError::Config(format!(
                        "Key '{}' not found in keyring: {e}",
                        self.key_name
                    )));
                }
            }

            info!("Deleting key from keyring...");
            entry.delete_credential().map_err(|e| {
                SignerError::Config(format!("Failed to delete key from keyring: {e}"))
            })?;

            info!("✅ Deleted private key '{}' from OS keyring", self.key_name);
            Ok(())
        }

        #[cfg(target_env = "musl")]
        {
            Err(SignerError::Config(
                "OS keyring backend is not available on MUSL targets due to D-Bus limitations".to_string(),
            ))
        }

        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        {
            Err(SignerError::Config(
                "OS keyring backend is only supported on Linux and macOS".to_string(),
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
        #[cfg(all(any(target_os = "linux", target_os = "macos"), not(target_env = "musl")))]
        {
            Self::check_keyring_availability().is_ok() && self.key_exists_in_keyring()
        }

        #[cfg(any(target_env = "musl", not(any(target_os = "linux", target_os = "macos"))))]
        {
            false
        }
    }

    fn backend_type(&self) -> &'static str {
        "os_keyring"
    }

    fn validate_config(&self) -> Result<(), SignerError> {
        Self::check_keyring_availability()
    }

    async fn delete_key(&self) -> Result<(), SignerError> {
        Self::check_keyring_availability()?;
        self.delete_key_from_keyring()
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
