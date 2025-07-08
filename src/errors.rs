use thiserror::Error;

#[derive(Error, Debug)]
pub enum SignerError {
    #[error("Configuration error: {0}")]
    Config(String),

    #[error("Crypto error: {0}")]
    Crypto(String),



    #[error("Invalid request: {0}")]
    InvalidRequest(String),

    #[error("Internal server error: {0}")]
    Internal(String),

    #[error("TLS configuration error: {0}")]
    Tls(String),
}

impl From<anyhow::Error> for SignerError {
    fn from(err: anyhow::Error) -> Self {
        SignerError::Internal(err.to_string())
    }
}

impl From<serde_json::Error> for SignerError {
    fn from(err: serde_json::Error) -> Self {
        SignerError::InvalidRequest(err.to_string())
    }
}

impl From<hex::FromHexError> for SignerError {
    fn from(err: hex::FromHexError) -> Self {
        SignerError::Crypto(format!("Hex decode error: {}", err))
    }
} 