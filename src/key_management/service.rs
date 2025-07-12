use anyhow::Result;
use tracing::{info, warn};

use crate::keystore::backends::BackendUtils;
use crate::keystore::{BackendConfig, FileBackend, KeyMaterial, Keystore};
use crate::utils::prompt_for_passphrase_with_confirmation;

/// Unified key management service for all backend types
pub struct KeyManagementService;

impl KeyManagementService {
    /// Add a key to the specified backend
    pub async fn add_key(
        backend_type: &str,
        key_name: &str,
        private_key_hex: &str,
        keystore_path: Option<String>,
        keystore_dir: Option<String>,
        _env_var: Option<String>, // Not used in current implementation
        passphrase: Option<String>,
    ) -> Result<()> {
        info!("Adding key '{}' to {} backend", key_name, backend_type);

        // Validate private key format
        BackendUtils::validate_private_key_hex(private_key_hex)?;

        match backend_type {
            "software" => Self::add_key_to_software_backend(
                keystore_path,
                key_name,
                private_key_hex,
                passphrase,
            )
            .await,
            "file" => Self::add_key_to_file_backend(
                keystore_dir,
                key_name,
                private_key_hex,
                passphrase,
            )
            .await,
            "environment" => {
                Err(anyhow::anyhow!(
                    "Environment backend does not support key addition. Set the environment variable manually."
                ))
            }
            "os_keyring" => Self::add_key_to_os_keyring_backend(
                key_name,
                private_key_hex,
            )
            .await,
            _ => Err(anyhow::anyhow!(
                "Unknown backend: {}. Supported backends: software, file, environment, os_keyring",
                backend_type
            )),
        }
    }

    /// Delete a key from the specified backend
    pub async fn delete_key(
        backend_type: &str,
        key_name: &str,
        keystore_path: Option<String>,
        keystore_dir: Option<String>,
        confirm: bool,
    ) -> Result<()> {
        if !confirm {
            return Err(anyhow::anyhow!(
                "Key deletion requires confirmation. Use --confirm flag."
            ));
        }

        info!(
            "🗑️  Deleting key '{}' from {} backend",
            key_name, backend_type
        );

        match backend_type {
            "software" => Self::delete_key_from_software_backend(keystore_path).await,
            "file" => Self::delete_key_from_file_backend(keystore_dir, key_name).await,
            "environment" => Err(anyhow::anyhow!(
                "Environment backend does not support key deletion"
            )),
            "os_keyring" => Self::delete_key_from_os_keyring_backend(key_name).await,
            _ => Err(anyhow::anyhow!(
                "Unknown backend: {}. Supported backends: software, file, environment, os_keyring",
                backend_type
            )),
        }
    }

    /// List keys from the specified backend
    pub async fn list_keys(
        backend_type: &str,
        keystore_path: Option<String>,
        keystore_dir: Option<String>,
    ) -> Result<()> {
        info!("📋 Listing keys from {} backend", backend_type);

        match backend_type {
            "software" => Self::list_keys_from_software_backend(keystore_path),
            "file" => Self::list_keys_from_file_backend(keystore_dir),
            "environment" => Self::list_keys_from_environment_backend(),
            "os_keyring" => Self::list_keys_from_os_keyring_backend(),
            _ => Err(anyhow::anyhow!(
                "Unknown backend: {}. Supported backends: software, file, environment, os_keyring",
                backend_type
            )),
        }
    }

    // Private helper methods for each backend type

    async fn add_key_to_software_backend(
        keystore_path: Option<String>,
        key_name: &str,
        private_key_hex: &str,
        passphrase: Option<String>,
    ) -> Result<()> {
        let path = keystore_path.ok_or_else(|| {
            anyhow::anyhow!("Keystore path is required for software backend (use --keystore-path)")
        })?;

        let passphrase = Self::get_secure_passphrase(
            passphrase,
            "Enter passphrase for new software keystore: ",
        )?;

        Keystore::create_keystore(&path, private_key_hex, &passphrase).await?;
        info!(
            "✅ Key '{}' created in software keystore: {}",
            key_name, path
        );
        Ok(())
    }

    async fn add_key_to_file_backend(
        keystore_dir: Option<String>,
        key_name: &str,
        private_key_hex: &str,
        passphrase: Option<String>,
    ) -> Result<()> {
        let dir = keystore_dir.ok_or_else(|| {
            anyhow::anyhow!("Keystore directory is required for file backend (use --keystore-dir)")
        })?;

        let passphrase = Self::get_secure_passphrase(
            passphrase,
            &format!("Enter passphrase for new key '{key_name}': "),
        )?;

        FileBackend::create_key(&dir, key_name, private_key_hex, &passphrase).await?;
        info!("✅ Key '{}' created in file keystore: {}", key_name, dir);
        Ok(())
    }

    async fn add_key_to_os_keyring_backend(key_name: &str, private_key_hex: &str) -> Result<()> {
        let backend_config = BackendConfig::OsKeyring {
            key_name: key_name.to_string(),
        };

        let keystore = Keystore::new(backend_config)?;
        keystore.validate_config()?;

        let key_material = KeyMaterial::from_hex(private_key_hex)?;
        keystore.store_key(&key_material).await?;

        info!(
            "✅ Key '{}' added successfully to os_keyring backend",
            key_name
        );
        Ok(())
    }

    async fn delete_key_from_software_backend(keystore_path: Option<String>) -> Result<()> {
        let path = keystore_path.ok_or_else(|| {
            anyhow::anyhow!("Keystore path is required for software backend (use --keystore-path)")
        })?;

        std::fs::remove_file(&path)?;
        info!("✅ Software keystore file deleted: {}", path);
        Ok(())
    }

    async fn delete_key_from_file_backend(
        keystore_dir: Option<String>,
        key_name: &str,
    ) -> Result<()> {
        let dir = keystore_dir.ok_or_else(|| {
            anyhow::anyhow!("Keystore directory is required for file backend (use --keystore-dir)")
        })?;

        let backend = FileBackend::new(dir.clone());
        backend.delete_key(key_name).await?;
        info!("✅ Key '{}' deleted from file keystore: {}", key_name, dir);
        Ok(())
    }

    async fn delete_key_from_os_keyring_backend(key_name: &str) -> Result<()> {
        let backend_config = BackendConfig::OsKeyring {
            key_name: key_name.to_string(),
        };

        let mut keystore = Keystore::new(backend_config)?;
        keystore.validate_config()?;
        keystore.init(None).await?;
        keystore.delete_key().await?;

        info!(
            "✅ Key '{}' deleted successfully from os_keyring backend",
            key_name
        );
        Ok(())
    }

    fn list_keys_from_software_backend(keystore_path: Option<String>) -> Result<()> {
        let path = keystore_path.ok_or_else(|| {
            anyhow::anyhow!("Keystore path is required for software backend (use --keystore-path)")
        })?;

        if std::path::Path::new(&path).exists() {
            info!("📁 Software keystore found: {}", path);
            info!("   (Software keystores contain one key per file)");
        } else {
            warn!("❌ Software keystore not found: {}", path);
        }
        Ok(())
    }

    fn list_keys_from_file_backend(keystore_dir: Option<String>) -> Result<()> {
        let dir = keystore_dir.ok_or_else(|| {
            anyhow::anyhow!("Keystore directory is required for file backend (use --keystore-dir)")
        })?;

        if std::path::Path::new(&dir).exists() {
            let backend = FileBackend::new(dir.clone());
            match backend.list_keys() {
                Ok(keys) => {
                    info!("📁 File keystore found: {}", dir);
                    if keys.is_empty() {
                        info!("   No keys found in keystore");
                    } else {
                        info!("   Keys found:");
                        for key in keys {
                            info!("   - {}", key);
                        }
                    }
                }
                Err(e) => {
                    warn!("❌ Failed to list keys: {}", e);
                }
            }
        } else {
            warn!("❌ File keystore directory not found: {}", dir);
        }
        Ok(())
    }

    fn list_keys_from_environment_backend() -> Result<()> {
        info!("🌍 Environment backend - check your environment variables");
        info!("   Keys are stored as environment variables, not managed by this tool");
        Ok(())
    }

    fn list_keys_from_os_keyring_backend() -> Result<()> {
        info!("🔑 OS keyring backend");
        info!("   Use your system's keyring tools to list keys:");

        #[cfg(target_os = "linux")]
        info!("   Linux: seahorse (GNOME), kwalletmanager (KDE)");

        #[cfg(target_os = "macos")]
        info!(
            "   macOS: Keychain Access.app or 'security find-generic-password -s starknet-signer'"
        );

        info!("   Service: 'starknet-signer'");
        Ok(())
    }

    fn get_secure_passphrase(provided_passphrase: Option<String>, prompt: &str) -> Result<String> {
        match provided_passphrase {
            Some(provided) => {
                warn!("⚠️  SECURITY WARNING: Passphrase provided via CLI argument");
                warn!("⚠️  This method is less secure as the passphrase may be visible in process lists");
                warn!("⚠️  Consider omitting --passphrase to use secure prompting instead");
                Ok(provided)
            }
            None => prompt_for_passphrase_with_confirmation(prompt),
        }
    }
}
