use anyhow::Result;
use tracing::{info, warn};

use crate::cli::AddKeyArgs;
use crate::keystore::{BackendConfig, FileBackend, KeyMaterial, Keystore};
use crate::utils::prompt_for_passphrase_with_confirmation;

/// Add a new key to the specified keystore backend
pub async fn add_key(args: AddKeyArgs) -> Result<()> {
    info!("Adding key '{}' to {} backend", args.key_name, args.backend);

    // Create backend config
    let backend_config = match args.backend.as_str() {
        "software" => {
            handle_software_backend(args).await?;
            return Ok(());
        }
        "file" => {
            handle_file_backend(args).await?;
            return Ok(());
        }
        "environment" => {
            return Err(anyhow::anyhow!("Environment backend does not support key addition. Set the environment variable manually."));
        }
        "os_keyring" => BackendConfig::OsKeyring {
            key_name: args.key_name.clone(),
        },
        _ => {
            return Err(anyhow::anyhow!(
                "Unknown backend: {}. Supported backends: software, file, environment, os_keyring",
                args.backend
            ));
        }
    };

    // Handle OS keyring backend
    handle_os_keyring_backend(args, backend_config).await
}

/// Handle software backend key addition
async fn handle_software_backend(args: AddKeyArgs) -> Result<()> {
    let path = args.keystore_path.ok_or_else(|| {
        anyhow::anyhow!("Keystore path is required for software backend (use --keystore-path)")
    })?;

    // Get passphrase securely with confirmation (new key creation)
    let passphrase = get_secure_passphrase(
        args.passphrase,
        "Enter passphrase for new software keystore: ",
    )?;

    // For software backend, create keystore file
    Keystore::create_keystore(&path, &args.private_key, &passphrase).await?;
    info!(
        "✅ Key '{}' created in software keystore: {}",
        args.key_name, path
    );
    Ok(())
}

/// Handle file backend key addition
async fn handle_file_backend(args: AddKeyArgs) -> Result<()> {
    let dir = args.keystore_dir.ok_or_else(|| {
        anyhow::anyhow!("Keystore directory is required for file backend (use --keystore-dir)")
    })?;

    // Get passphrase securely with confirmation (new key creation)
    let passphrase = get_secure_passphrase(
        args.passphrase,
        &format!("Enter passphrase for new key '{}': ", args.key_name),
    )?;

    // For file backend, create key in directory
    FileBackend::create_key(&dir, &args.key_name, &args.private_key, &passphrase).await?;
    info!(
        "✅ Key '{}' created in file keystore: {}",
        args.key_name, dir
    );
    Ok(())
}

/// Handle OS keyring backend key addition
async fn handle_os_keyring_backend(args: AddKeyArgs, backend_config: BackendConfig) -> Result<()> {
    // Create keystore and store key
    let keystore = Keystore::new(backend_config)?;
    keystore.validate_config()?;

    let key_material = KeyMaterial::from_hex(&args.private_key)?;
    keystore.store_key(&key_material).await?;

    info!(
        "✅ Key '{}' added successfully to {} backend",
        args.key_name, args.backend
    );
    Ok(())
}

/// Get passphrase securely with appropriate warnings
fn get_secure_passphrase(provided_passphrase: Option<String>, prompt: &str) -> Result<String> {
    match provided_passphrase {
        Some(provided) => {
            warn!("⚠️  SECURITY WARNING: Passphrase provided via CLI argument");
            warn!(
                "⚠️  This method is less secure as the passphrase may be visible in process lists"
            );
            warn!("⚠️  Consider omitting --passphrase to use secure prompting instead");
            Ok(provided)
        }
        None => prompt_for_passphrase_with_confirmation(prompt),
    }
}
