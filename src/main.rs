use anyhow::Result;
use clap::Parser;
use tracing::{info, warn};

use starknet_remote_signer::{Config, Server, StartArgs, AddKeyArgs, DeleteKeyArgs, ListKeysArgs, key_management};

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
        Some(Commands::Keys { command }) => {
            // Initialize logging for key management commands
            let subscriber = tracing_subscriber::fmt()
                .with_env_filter("info")
                .compact()
                .finish();
            tracing::subscriber::set_global_default(subscriber)?;

            match command {
                KeysCommands::Add(args) => key_management::add_key(args).await,
                KeysCommands::Delete(args) => key_management::delete_key(args).await,
                KeysCommands::List(args) => key_management::list_keys(args).await,
            }
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