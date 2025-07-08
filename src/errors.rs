use thiserror::Error;

#[derive(Debug, Error)]
pub enum SignerError {
    #[error("Configuration error: {0}")]
    Config(String),
    
    #[error("Invalid private key: {0}")]
    InvalidKey(String),
    
    #[error("Keystore error: {0}")]
    Keystore(String),
    
    #[error("Cryptography error: {0}")]
    Crypto(String),
    
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    
    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
    
    #[error("Internal error: {0}")]
    Internal(String),
    
    #[error("Unauthorized: {0}")]
    Unauthorized(String),
}

impl From<anyhow::Error> for SignerError {
    fn from(err: anyhow::Error) -> Self {
        SignerError::Internal(err.to_string())
    }
}

 