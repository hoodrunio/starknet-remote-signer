use anyhow::Result;
use tracing::{error, info};

use crate::cli::DeleteKeyArgs;
use crate::keystore::{BackendConfig, FileBackend, Keystore};

/// Delete a key from the specified keystore backend
pub async fn delete_key(args: DeleteKeyArgs) -> Result<()> {
    if !args.confirm {
        error!("❌ Key deletion requires --confirm flag for safety");
        error!("💡 Usage: starknet-remote-signer keys delete validator --confirm");
        return Ok(());
    }

    info!(
        "🗑️  Deleting key '{}' from {} backend",
        args.key_name, args.backend
    );

    // Handle different backend types
    match args.backend.as_str() {
        "software" => {
            handle_software_backend_deletion(args).await?;
        }
        "file" => {
            handle_file_backend_deletion(args).await?;
        }
        "environment" => {
            return Err(anyhow::anyhow!(
                "Environment backend does not support key deletion"
            ));
        }
        "os_keyring" => {
            handle_os_keyring_backend_deletion(args).await?;
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

/// Handle software backend key deletion
async fn handle_software_backend_deletion(args: DeleteKeyArgs) -> Result<()> {
    let path = args.keystore_path.ok_or_else(|| {
        anyhow::anyhow!("Keystore path is required for software backend (use --keystore-path)")
    })?;

    // For software backend, delete the file
    std::fs::remove_file(&path)?;
    info!("✅ Software keystore file deleted: {}", path);
    Ok(())
}

/// Handle file backend key deletion
async fn handle_file_backend_deletion(args: DeleteKeyArgs) -> Result<()> {
    let dir = args.keystore_dir.ok_or_else(|| {
        anyhow::anyhow!("Keystore directory is required for file backend (use --keystore-dir)")
    })?;

    // For file backend, delete specific key file
    let backend = FileBackend::new(dir.clone());
    backend.delete_key(&args.key_name).await?;
    info!(
        "✅ Key '{}' deleted from file keystore: {}",
        args.key_name, dir
    );
    Ok(())
}

/// Handle OS keyring backend key deletion
async fn handle_os_keyring_backend_deletion(args: DeleteKeyArgs) -> Result<()> {
    let backend_config = BackendConfig::OsKeyring {
        key_name: args.key_name.clone(),
    };

    // Create keystore and initialize it
    let mut keystore = Keystore::new(backend_config)?;
    keystore.validate_config()?;

    // Initialize the keystore (will only load key if it exists)
    keystore.init(None).await?;

    // Delete the key
    keystore.delete_key().await?;

    info!(
        "✅ Key '{}' deleted successfully from {} backend",
        args.key_name, args.backend
    );
    Ok(())
}
