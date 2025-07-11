use anyhow::Result;
use tracing::{info, warn, error};

use crate::{Keystore, keystore::{BackendConfig, KeyMaterial}, AddKeyArgs, DeleteKeyArgs, ListKeysArgs};
use crate::utils::{prompt_for_passphrase_with_confirmation};

/// Key management module - handles add, delete, and list operations for keystores
pub async fn add_key(args: AddKeyArgs) -> Result<()> {
    info!("Adding key '{}' to {} backend", args.key_name, args.backend);

    // Create backend config
    let backend_config = match args.backend.as_str() {
        "software" => {
            let path = args.keystore_path.ok_or_else(|| {
                anyhow::anyhow!("Keystore path is required for software backend (use --keystore-path)")
            })?;
            
            // Get passphrase securely with confirmation (new key creation)
            let passphrase = match args.passphrase {
                Some(provided) => {
                    warn!("⚠️  SECURITY WARNING: Passphrase provided via CLI argument");
                    warn!("⚠️  This method is less secure as the passphrase may be visible in process lists");
                    warn!("⚠️  Consider omitting --passphrase to use secure prompting instead");
                    provided
                }
                None => {
                    prompt_for_passphrase_with_confirmation("Enter passphrase for new software keystore: ")?
                }
            };
            
            // For software backend, create keystore file
            Keystore::create_keystore(&path, &args.private_key, &passphrase).await?;
            info!("✅ Key '{}' created in software keystore: {}", args.key_name, path);
            return Ok(());
        }
        "file" => {
            let dir = args.keystore_dir.ok_or_else(|| {
                anyhow::anyhow!("Keystore directory is required for file backend (use --keystore-dir)")
            })?;
            
            // Get passphrase securely with confirmation (new key creation)
            let passphrase = match args.passphrase {
                Some(provided) => {
                    warn!("⚠️  SECURITY WARNING: Passphrase provided via CLI argument");
                    warn!("⚠️  This method is less secure as the passphrase may be visible in process lists");
                    warn!("⚠️  Consider omitting --passphrase to use secure prompting instead");
                    provided
                }
                None => {
                    prompt_for_passphrase_with_confirmation(&format!("Enter passphrase for new key '{}': ", args.key_name))?
                }
            };
            
            // For file backend, create key in directory
            use crate::keystore::FileBackend;
            FileBackend::create_key(&dir, &args.key_name, &args.private_key, &passphrase).await?;
            info!("✅ Key '{}' created in file keystore: {}", args.key_name, dir);
            return Ok(());
        }
        "environment" => {
            return Err(anyhow::anyhow!("Environment backend does not support key addition. Set the environment variable manually."));
        }
        "os_keyring" => {
            BackendConfig::OsKeyring { 
                key_name: args.key_name.clone()
            }
        }
        _ => {
            return Err(anyhow::anyhow!("Unknown backend: {}. Supported backends: software, file, environment, os_keyring", args.backend));
        }
    };

    // Create keystore and store key
    let keystore = Keystore::new(backend_config)?;
    keystore.validate_config()?;
    
    let key_material = KeyMaterial::from_hex(&args.private_key)?;
    keystore.store_key(&key_material).await?;

    info!("✅ Key '{}' added successfully to {} backend", args.key_name, args.backend);
    Ok(())
}

pub async fn delete_key(args: DeleteKeyArgs) -> Result<()> {
    if !args.confirm {
        error!("❌ Key deletion requires --confirm flag for safety");
        error!("💡 Usage: starknet-remote-signer keys delete validator --confirm");
        return Ok(());
    }

    info!("🗑️  Deleting key '{}' from {} backend", args.key_name, args.backend);

    // Create backend config
    let backend_config = match args.backend.as_str() {
        "software" => {
            let path = args.keystore_path.ok_or_else(|| {
                anyhow::anyhow!("Keystore path is required for software backend (use --keystore-path)")
            })?;
            
            // For software backend, delete the file
            std::fs::remove_file(&path)?;
            info!("✅ Software keystore file deleted: {}", path);
            return Ok(());
        }
        "file" => {
            let dir = args.keystore_dir.ok_or_else(|| {
                anyhow::anyhow!("Keystore directory is required for file backend (use --keystore-dir)")
            })?;
            
            // For file backend, delete specific key file
            use crate::keystore::FileBackend;
            let backend = FileBackend::new(dir.clone());
            backend.delete_key(&args.key_name).await?;
            info!("✅ Key '{}' deleted from file keystore: {}", args.key_name, dir);
            return Ok(());
        }
        "environment" => {
            return Err(anyhow::anyhow!("Environment backend does not support key deletion"));
        }
        "os_keyring" => {
            BackendConfig::OsKeyring { 
                key_name: args.key_name.clone()
            }
        }
        _ => {
            return Err(anyhow::anyhow!("Unknown backend: {}. Supported backends: software, file, environment, os_keyring", args.backend));
        }
    };

    // Create keystore and initialize it
    let mut keystore = Keystore::new(backend_config)?;
    keystore.validate_config()?;
    
    // Initialize the keystore (will only load key if it exists)
    keystore.init(None).await?;
    
    // Delete the key
    keystore.delete_key().await?;

    info!("✅ Key '{}' deleted successfully from {} backend", args.key_name, args.backend);
    Ok(())
}

pub async fn list_keys(args: ListKeysArgs) -> Result<()> {
    info!("📋 Listing keys from {} backend", args.backend);

    match args.backend.as_str() {
        "software" => {
            let path = args.keystore_path.ok_or_else(|| {
                anyhow::anyhow!("Keystore path is required for software backend (use --keystore-path)")
            })?;
            
            if std::path::Path::new(&path).exists() {
                info!("📁 Software keystore found: {}", path);
                info!("   (Software keystores contain one key per file)");
            } else {
                warn!("❌ Software keystore not found: {}", path);
            }
        }
        "file" => {
            let dir = args.keystore_dir.ok_or_else(|| {
                anyhow::anyhow!("Keystore directory is required for file backend (use --keystore-dir)")
            })?;
            
            if std::path::Path::new(&dir).exists() {
                use crate::keystore::FileBackend;
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
        }
        "environment" => {
            info!("🌍 Environment backend - check your environment variables");
            info!("   Keys are stored as environment variables, not managed by this tool");
        }
        "os_keyring" => {
            info!("🔑 OS keyring backend");
            info!("   Use your system's keyring tools to list keys:");
            
            #[cfg(target_os = "linux")]
            info!("   Linux: seahorse (GNOME), kwalletmanager (KDE)");
            
            #[cfg(target_os = "macos")]
            info!("   macOS: Keychain Access.app or 'security find-generic-password -s starknet-signer'");
            
            info!("   Service: 'starknet-signer'");
        }
        _ => {
            return Err(anyhow::anyhow!("Unknown backend: {}. Supported backends: software, file, environment, os_keyring", args.backend));
        }
    }

    Ok(())
} 