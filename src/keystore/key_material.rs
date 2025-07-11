use starknet::signers::SigningKey;
use starknet_crypto::Felt;
use zeroize::ZeroizeOnDrop;

use crate::errors::SignerError;

/// In-memory key material that gets zeroized on drop
#[derive(ZeroizeOnDrop)]
pub struct KeyMaterial {
    private_key: [u8; 32],
}

impl KeyMaterial {
    /// Create key material from a hex string
    pub fn from_hex(hex_key: &str) -> Result<Self, SignerError> {
        let key_felt = Felt::from_hex(hex_key)
            .map_err(|e| SignerError::InvalidKey(format!("Invalid private key hex: {}", e)))?;
        
        let key_bytes = key_felt.to_bytes_be();
        
        Ok(Self {
            private_key: key_bytes,
        })
    }

    /// Create key material from bytes
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self {
            private_key: bytes,
        }
    }

    /// Get the signing key
    pub fn signing_key(&self) -> Result<SigningKey, SignerError> {
        let felt = Felt::from_bytes_be(&self.private_key);
        Ok(SigningKey::from_secret_scalar(felt))
    }

    /// Get the private key as Felt
    pub fn as_felt(&self) -> Felt {
        Felt::from_bytes_be(&self.private_key)
    }

    /// Get the private key as hex string (for serialization only)
    pub fn to_hex(&self) -> String {
        hex::encode(self.private_key)
    }

    /// Get raw bytes (use with caution)
    pub fn raw_bytes(&self) -> &[u8; 32] {
        &self.private_key
    }
} 