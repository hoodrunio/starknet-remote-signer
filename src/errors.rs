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

    #[error("Transaction validation failed: {0}")]
    ValidationFailed(String),

    #[error("Security error: {0}")]
    Security(String),

    #[error("Validation error: {0}")]
    Validation(String),

    #[error("Signing error: {0}")]
    Signing(String),
}

impl SignerError {
    /// Returns a sanitized error message safe for client responses
    /// This prevents information disclosure while preserving error context for operators
    pub fn client_message(&self) -> String {
        match self {
            SignerError::Config(_) => "Configuration error".to_string(),
            SignerError::InvalidKey(_) => "Invalid key format".to_string(),
            SignerError::Keystore(_) => "Keystore operation failed".to_string(),
            SignerError::Crypto(_) => "Cryptographic operation failed".to_string(),
            SignerError::Io(_) => "I/O operation failed".to_string(),
            SignerError::Serialization(_) => "Data format error".to_string(),
            SignerError::Internal(_) => "Internal server error".to_string(),
            SignerError::Unauthorized(_) => "Access denied".to_string(),
            SignerError::ValidationFailed(_) => "Request validation failed".to_string(),
            SignerError::Security(_) => "Security policy violation".to_string(),
            SignerError::Validation(_) => "Invalid request parameters".to_string(),
            SignerError::Signing(_) => "Signing operation failed".to_string(),
        }
    }

    /// Returns the original detailed error message for operator logs/debugging
    pub fn operator_message(&self) -> String {
        self.to_string()
    }
}

impl From<anyhow::Error> for SignerError {
    fn from(err: anyhow::Error) -> Self {
        SignerError::Internal(err.to_string())
    }
}
