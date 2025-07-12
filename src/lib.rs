pub mod audit;
pub mod cli;
pub mod config;
pub mod constants;
pub mod errors;
pub mod handlers;
pub mod key_management;
pub mod keystore;
pub mod middleware;
pub mod security;
pub mod server;
pub mod services;
pub mod signer;
pub mod utils;
pub mod validation;

pub use config::Config;
pub use errors::SignerError;
pub use keystore::Keystore;
pub use server::Server;
pub use signer::StarknetSigner;

// Re-export CLI types for main.rs
pub use cli::*;

// Integration tests
#[cfg(test)]
pub mod integration_test;
