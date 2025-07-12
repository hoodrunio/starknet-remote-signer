use anyhow::Result;
use clap::Parser;
use tracing::{info, warn};

use starknet_remote_signer::{
    key_management, Cli, Commands, Config, InitArgs, KeysCommands, Server, StartArgs,
};

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
        }
        None => start_server(cli.start_args).await, // Default to start for backward compatibility
    }
}

async fn start_server(args: StartArgs) -> Result<()> {
    // Store CLI log level for priority handling
    let cli_log_level = args.log_level.clone();

    // Load configuration first to get logging config
    let mut config = Config::load(args)?;
    let log_level = cli_log_level
        .or_else(|| std::env::var("RUST_LOG").ok())
        .unwrap_or_else(|| config.logging.level.clone());

    // Initialize logging
    let subscriber = tracing_subscriber::fmt()
        .with_env_filter(&log_level)
        .compact()
        .finish();
    tracing::subscriber::set_global_default(subscriber)?;

    info!(
        "Starting Starknet Remote Signer v{}",
        env!("CARGO_PKG_VERSION")
    );
    info!("Log level: {}", log_level);

    // Validate configuration
    config.validate()?;

    // Get passphrase securely if needed for keystore
    if let Some(passphrase) = config.get_keystore_passphrase()? {
        config.passphrase = Some(passphrase);
    }

    // Log configuration details
    info!("📊 Configuration loaded:");
    info!("  Server: {}:{}", config.server.address, config.server.port);
    info!("  Keystore backend: {}", config.keystore.backend);

    // Log security configuration
    if !config.security.allowed_chain_ids.is_empty() {
        info!(
            "🔒 Allowed chains: [{}]",
            config.security.allowed_chain_ids.join(", ")
        );
    } else {
        warn!("⚠️  No chain restrictions configured - all chains allowed!");
    }

    if !config.security.allowed_ips.is_empty() {
        info!(
            "🔒 Allowed IPs: [{}]",
            config.security.allowed_ips.join(", ")
        );
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
    use starknet_remote_signer::{utils::prompt_for_passphrase_with_confirmation, Keystore};

    // Initialize logging
    let subscriber = tracing_subscriber::fmt()
        .with_env_filter("info")
        .compact()
        .finish();
    tracing::subscriber::set_global_default(subscriber)?;

    info!("Creating encrypted keystore at: {}", args.output);

    // Get passphrase securely
    let passphrase = match args.passphrase {
        Some(provided_passphrase) => {
            warn!("⚠️  SECURITY WARNING: Passphrase provided via CLI argument");
            warn!(
                "⚠️  This method is less secure as the passphrase may be visible in process lists"
            );
            warn!("⚠️  Consider omitting --passphrase to use secure prompting instead");
            provided_passphrase
        }
        None => prompt_for_passphrase_with_confirmation("Enter passphrase for new keystore: ")?,
    };

    // Create encrypted keystore
    Keystore::create_keystore(&args.output, &args.private_key, &passphrase).await?;

    info!("✅ Keystore created successfully!");
    info!("🔑 Public key will be displayed when starting the signer");
    warn!("⚠️  Keep your passphrase secure - it cannot be recovered!");

    Ok(())
}
