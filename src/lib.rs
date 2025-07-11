use clap::Parser;

pub mod config;
pub mod errors;
pub mod keystore;
pub mod server;
pub mod signer;
pub mod audit;
pub mod security;
pub mod utils;

pub use config::Config;
pub use errors::SignerError;
pub use keystore::Keystore;
pub use server::Server;
pub use signer::StarknetSigner;

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

    /// Keystore backend: "software", "environment", "hsm"
    #[arg(long, env = "SIGNER_KEYSTORE_BACKEND")]
    pub keystore_backend: Option<String>,

    /// Path to encrypted keystore file (for software backend)
    #[arg(long, env = "SIGNER_KEYSTORE_PATH")]
    pub keystore_path: Option<String>,

    /// Environment variable name for private key (for environment backend)
    #[arg(long, env = "SIGNER_ENV_VAR", default_value = "SIGNER_PRIVATE_KEY")]
    pub env_var: Option<String>,

    /// OS keyring key name (for os_keyring backend) - like "validator", "alice", etc.
    #[arg(long, env = "SIGNER_KEYRING_KEY_NAME", default_value = "validator")]
    pub keyring_key_name: Option<String>,

    /// Passphrase for encrypted keystore
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
    #[arg(long, env = "RUST_LOG", default_value = "info")]
    pub log_level: String,
}

#[derive(Parser)]
enum Commands {
    /// Start the remote signer server
    Start(StartArgs),
    /// Initialize and create encrypted keystore
    Init(InitArgs),
    /// Delete key from keystore
    DeleteKey(DeleteKeyArgs),
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

#[derive(Parser)]
pub struct DeleteKeyArgs {
    /// Keystore backend: "software", "environment", "os_keyring"
    #[arg(long, env = "SIGNER_KEYSTORE_BACKEND", default_value = "os_keyring")]
    pub backend: String,

    /// Path to encrypted keystore file (for software backend)
    #[arg(long, env = "SIGNER_KEYSTORE_PATH")]
    pub keystore_path: Option<String>,

    /// Environment variable name (for environment backend)
    #[arg(long, env = "SIGNER_ENV_VAR")]
    pub env_var: Option<String>,

    /// OS keyring key name (for os_keyring backend) - like "validator", "alice", etc.
    #[arg(long, env = "SIGNER_KEYRING_KEY_NAME", default_value = "validator")]
    pub key_name: Option<String>,

    /// Confirm deletion (safety check)
    #[arg(long)]
    pub confirm: bool,
}

// Integration tests
#[cfg(test)]
pub mod integration_test; 