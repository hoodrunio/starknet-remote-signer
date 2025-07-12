use anyhow::Result;
use tracing::{info, warn};

use crate::cli::ListKeysArgs;
use crate::keystore::FileBackend;

/// List keys from the specified keystore backend
pub async fn list_keys(args: ListKeysArgs) -> Result<()> {
    info!("📋 Listing keys from {} backend", args.backend);

    match args.backend.as_str() {
        "software" => {
            handle_software_backend_listing(args)?;
        }
        "file" => {
            handle_file_backend_listing(args)?;
        }
        "environment" => {
            handle_environment_backend_listing();
        }
        "os_keyring" => {
            handle_os_keyring_backend_listing();
        }
        _ => {
            return Err(anyhow::anyhow!(
                "Unknown backend: {}. Supported backends: software, file, environment, os_keyring",
                args.backend
            ));
        }
    }

    Ok(())
}

/// Handle software backend key listing
fn handle_software_backend_listing(args: ListKeysArgs) -> Result<()> {
    let path = args.keystore_path.ok_or_else(|| {
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

/// Handle file backend key listing
fn handle_file_backend_listing(args: ListKeysArgs) -> Result<()> {
    let dir = args.keystore_dir.ok_or_else(|| {
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

/// Handle environment backend key listing
fn handle_environment_backend_listing() {
    info!("🌍 Environment backend - check your environment variables");
    info!("   Keys are stored as environment variables, not managed by this tool");
}

/// Handle OS keyring backend key listing
fn handle_os_keyring_backend_listing() {
    info!("🔑 OS keyring backend");
    info!("   Use your system's keyring tools to list keys:");

    #[cfg(target_os = "linux")]
    info!("   Linux: seahorse (GNOME), kwalletmanager (KDE)");

    #[cfg(target_os = "macos")]
    info!("   macOS: Keychain Access.app or 'security find-generic-password -s starknet-signer'");

    info!("   Service: 'starknet-signer'");
}
