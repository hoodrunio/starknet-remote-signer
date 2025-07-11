use anyhow::Result;
use tracing::{info, warn, error};

use crate::{Keystore, keystore::{BackendConfig, KeyMaterial}, AddKeyArgs, DeleteKeyArgs, ListKeysArgs};

/// Key management module - handles add, delete, and list operations for keystores

pub async fn add_key(args: AddKeyArgs) -> Result<()> {
    info!("Adding key '{}' to {} backend", args.key_name, args.backend);

    // Create backend config
    let backend_config = match args.backend.as_str() {
        "software" => {
            let path = args.keystore_path.ok_or_else(|| {
                anyhow::anyhow!("Keystore path is required for software backend (use --keystore-path)")
            })?;
            let passphrase = args.passphrase.ok_or_else(|| {
                anyhow::anyhow!("Passphrase is required for software backend (use --passphrase)")
            })?;
            
            // For software backend, create keystore file
            Keystore::create_keystore(&path, &args.private_key, &passphrase).await?;
            info!("✅ Key '{}' created in software keystore: {}", args.key_name, path);
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
            return Err(anyhow::anyhow!("Unknown backend: {}", args.backend));
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
        "environment" => {
            return Err(anyhow::anyhow!("Environment backend does not support key deletion"));
        }
        "os_keyring" => {
            BackendConfig::OsKeyring { 
                key_name: args.key_name.clone()
            }
        }
        _ => {
            return Err(anyhow::anyhow!("Unknown backend: {}", args.backend));
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
            return Err(anyhow::anyhow!("Unknown backend: {}", args.backend));
        }
    }

    Ok(())
} 