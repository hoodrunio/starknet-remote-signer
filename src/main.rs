use anyhow::Result;
use clap::Parser;
use tracing::{info, warn, error};

use starknet_remote_signer::{Config, Server, StartArgs, AddKeyArgs, DeleteKeyArgs, ListKeysArgs};

#[derive(Parser)]
#[command(name = "starknet-remote-signer")]
#[command(about = "A secure remote signing service for Starknet validators")]
#[command(version)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,

    /// When no subcommand is provided, these args are used for 'start'
    #[command(flatten)]
    start_args: StartArgs,
}

#[derive(Parser)]
enum Commands {
    /// Start the remote signer server
    Start(StartArgs),
    /// Initialize and create encrypted keystore file
    Init(InitArgs),
    /// Key management commands
    Keys {
        #[command(subcommand)]
        command: KeysCommands,
    },
}

#[derive(Parser)]
enum KeysCommands {
    /// Add a new key to keystore
    Add(AddKeyArgs),
    /// Delete a key from keystore  
    Delete(DeleteKeyArgs),
    /// List all keys in keystore
    List(ListKeysArgs),
}

#[derive(Parser)]
struct InitArgs {
    /// Output path for encrypted keystore
    #[arg(short, long)]
    output: String,

    /// Private key to encrypt (hex, without 0x prefix)
    #[arg(long)]
    private_key: String,

    /// Passphrase for encryption
    #[arg(long)]
    passphrase: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Some(Commands::Start(args)) => start_server(args).await,
        Some(Commands::Init(args)) => init_keystore(args).await,
        Some(Commands::Keys { command }) => match command {
            KeysCommands::Add(args) => add_key(args).await,
            KeysCommands::Delete(args) => delete_key(args).await,
            KeysCommands::List(args) => list_keys(args).await,
        },
        None => start_server(cli.start_args).await, // Default to start for backward compatibility
    }
}

async fn start_server(args: StartArgs) -> Result<()> {
    // Initialize logging
    let subscriber = tracing_subscriber::fmt()
        .with_env_filter(&args.log_level)
        .compact()
        .finish();
    tracing::subscriber::set_global_default(subscriber)?;

    info!("Starting Starknet Remote Signer v{}", env!("CARGO_PKG_VERSION"));

    // Load configuration
    let config = Config::load(args)?;
    
    // Validate configuration
    config.validate()?;

    // Log configuration details
    info!("📊 Configuration loaded:");
    info!("  Server: {}:{}", config.server.address, config.server.port);
    info!("  Keystore backend: {}", config.keystore.backend);
    
    // Log security configuration
    if !config.security.allowed_chain_ids.is_empty() {
        info!("🔒 Allowed chains: [{}]", config.security.allowed_chain_ids.join(", "));
    } else {
        warn!("⚠️  No chain restrictions configured - all chains allowed!");
    }
    
    if !config.security.allowed_ips.is_empty() {
        info!("🔒 Allowed IPs: [{}]", config.security.allowed_ips.join(", "));
    } else {
        warn!("⚠️  No IP restrictions configured - all IPs allowed!");
    }
    
    if config.audit.enabled {
        info!("📝 Audit logging enabled: {}", config.audit.log_path);
    } else {
        warn!("⚠️  Audit logging disabled");
    }

    // Security warnings
    if !config.tls.enabled {
        warn!("⚠️  TLS disabled - communications are not encrypted! This is not recommended for production.");
    }

    // Start server
    let server = Server::new(config).await?;
    server.serve().await?;

    Ok(())
}

async fn add_key(args: AddKeyArgs) -> Result<()> {
    use starknet_remote_signer::{Keystore, keystore::{BackendConfig, KeyMaterial}};
    
    // Initialize logging
    let subscriber = tracing_subscriber::fmt()
        .with_env_filter("info")
        .compact()
        .finish();
    tracing::subscriber::set_global_default(subscriber)?;

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

async fn delete_key(args: DeleteKeyArgs) -> Result<()> {
    use starknet_remote_signer::{Keystore, keystore::BackendConfig};
    
    // Initialize logging
    let subscriber = tracing_subscriber::fmt()
        .with_env_filter("info")
        .compact()
        .finish();
    tracing::subscriber::set_global_default(subscriber)?;

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

async fn list_keys(args: ListKeysArgs) -> Result<()> {    
    // Initialize logging
    let subscriber = tracing_subscriber::fmt()
        .with_env_filter("info")
        .compact()
        .finish();
    tracing::subscriber::set_global_default(subscriber)?;

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

async fn init_keystore(args: InitArgs) -> Result<()> {
    use starknet_remote_signer::Keystore;
    
    // Initialize logging
    let subscriber = tracing_subscriber::fmt()
        .with_env_filter("info")
        .compact()
        .finish();
    tracing::subscriber::set_global_default(subscriber)?;

    info!("Creating encrypted keystore at: {}", args.output);

    // Create encrypted keystore
    Keystore::create_keystore(&args.output, &args.private_key, &args.passphrase).await?;

    info!("✅ Keystore created successfully!");
    info!("🔑 Public key will be displayed when starting the signer");
    warn!("⚠️  Keep your passphrase secure - it cannot be recovered!");

    Ok(())
} 