use clap::Parser;

#[derive(Parser)]
#[command(name = "starknet-remote-signer")]
#[command(about = "A secure remote signing service for Starknet validators")]
#[command(version)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Option<Commands>,

    /// When no subcommand is provided, these args are used for 'start'
    #[command(flatten)]
    pub start_args: StartArgs,
}

#[derive(Parser)]
pub enum Commands {
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
pub enum KeysCommands {
    /// Add a new key to keystore
    Add(AddKeyArgs),
    /// Delete a key from keystore  
    Delete(DeleteKeyArgs),
    /// List all keys in keystore
    List(ListKeysArgs),
}

#[derive(Parser)]
pub struct StartArgs {
    /// Configuration file path
    #[arg(short, long, env = "SIGNER_CONFIG")]
    pub config: Option<String>,

    /// Server bind address
    #[arg(long, env = "SIGNER_ADDRESS", default_value = "0.0.0.0")]
    pub address: String,

    /// Server port
    #[arg(short, long, env = "SIGNER_PORT", default_value = "3000")]
    pub port: u16,

    /// Keystore backend: "software", "environment", "os_keyring"
    #[arg(long, env = "SIGNER_KEYSTORE_BACKEND")]
    pub keystore_backend: Option<String>,

    /// Key name to use (for os_keyring backend)
    #[arg(long, env = "SIGNER_KEY_NAME")]
    pub key_name: Option<String>,

    /// Path to encrypted keystore file (for software backend)
    #[arg(long, env = "SIGNER_KEYSTORE_PATH")]
    pub keystore_path: Option<String>,

    /// Directory for file-based keystore (for file backend)
    #[arg(long, env = "SIGNER_KEYSTORE_DIR")]
    pub keystore_dir: Option<String>,

    /// Environment variable name for private key (for environment backend)
    #[arg(long, env = "SIGNER_ENV_VAR", default_value = "SIGNER_PRIVATE_KEY")]
    pub env_var: Option<String>,

    /// Passphrase for encrypted keystore (will be prompted securely if needed)
    /// Setting this via environment variable is NOT recommended for security
    #[arg(long, env = "SIGNER_PASSPHRASE")]
    pub passphrase: Option<String>,

    /// Enable TLS
    #[arg(long, env = "SIGNER_TLS")]
    pub tls: bool,

    /// TLS certificate file path
    #[arg(long, env = "SIGNER_TLS_CERT")]
    pub tls_cert: Option<String>,

    /// TLS private key file path
    #[arg(long, env = "SIGNER_TLS_KEY")]
    pub tls_key: Option<String>,

    /// Log level
    #[arg(long, env = "RUST_LOG")]
    pub log_level: Option<String>,
}

#[derive(Parser)]
pub struct InitArgs {
    /// Output path for encrypted keystore
    #[arg(short, long)]
    pub output: String,

    /// Private key to encrypt (hex, without 0x prefix)
    #[arg(long)]
    pub private_key: String,

    /// Passphrase for encryption (will be prompted securely if not provided)
    /// Setting this via CLI argument is NOT recommended for security
    #[arg(long)]
    pub passphrase: Option<String>,
}

#[derive(Parser)]
pub struct AddKeyArgs {
    /// Key name (like "validator", "alice", etc.)
    pub key_name: String,

    /// Private key hex string (without 0x prefix)
    #[arg(long)]
    pub private_key: String,

    /// Keystore backend: "software", "file", "environment", "os_keyring"
    #[arg(long, default_value = "os_keyring")]
    pub backend: String,

    /// Path for software keystore (required for software backend)
    #[arg(long)]
    pub keystore_path: Option<String>,

    /// Directory for file-based keystore (required for file backend)
    #[arg(long)]
    pub keystore_dir: Option<String>,

    /// Passphrase for encrypted keystore (will be prompted securely)
    /// Setting this via CLI argument is NOT recommended for security
    #[arg(long)]
    pub passphrase: Option<String>,
}

#[derive(Parser)]
pub struct DeleteKeyArgs {
    /// Key name to delete
    pub key_name: String,

    /// Keystore backend: "software", "file", "environment", "os_keyring"
    #[arg(long, default_value = "os_keyring")]
    pub backend: String,

    /// Path for software keystore (required for software backend)
    #[arg(long)]
    pub keystore_path: Option<String>,

    /// Directory for file-based keystore (required for file backend)
    #[arg(long)]
    pub keystore_dir: Option<String>,

    /// Confirm deletion (safety check)
    #[arg(long)]
    pub confirm: bool,
}

#[derive(Parser)]
pub struct ListKeysArgs {
    /// Keystore backend: "software", "file", "environment", "os_keyring"
    #[arg(long, default_value = "os_keyring")]
    pub backend: String,

    /// Path for software keystore (required for software backend)
    #[arg(long)]
    pub keystore_path: Option<String>,

    /// Directory for file-based keystore (required for file backend)
    #[arg(long)]
    pub keystore_dir: Option<String>,
}
