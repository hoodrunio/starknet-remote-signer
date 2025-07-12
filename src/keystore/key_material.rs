use starknet::signers::SigningKey;
use starknet_crypto::Felt;
use zeroize::ZeroizeOnDrop;

use crate::errors::SignerError;

/// In-memory key material that gets zeroized on drop
#[derive(ZeroizeOnDrop)]
pub struct KeyMaterial {
    private_key: [u8; 32],
}

impl std::fmt::Debug for KeyMaterial {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KeyMaterial")
            .field("private_key", &"[REDACTED]")
            .finish()
    }
}

impl KeyMaterial {
    /// Create key material from a hex string
    pub fn from_hex(hex_key: &str) -> Result<Self, SignerError> {
        // First try direct hex decode to preserve leading zeros
        if hex_key.len() == 64 {
            match hex::decode(hex_key) {
                Ok(bytes) if bytes.len() == 32 => {
                    let mut key_bytes = [0u8; 32];
                    key_bytes.copy_from_slice(&bytes);
                    return Ok(Self {
                        private_key: key_bytes,
                    });
                }
                _ => {}
            }
        }

        // Fallback to Felt parsing for other formats
        let key_felt = Felt::from_hex(hex_key)
            .map_err(|e| SignerError::InvalidKey(format!("Invalid private key hex: {e}")))?;

        let key_bytes = key_felt.to_bytes_be();

        Ok(Self {
            private_key: key_bytes,
        })
    }

    /// Create key material from bytes
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self { private_key: bytes }
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
        // Use direct hex encoding to preserve all 64 characters
        hex::encode(self.private_key)
    }

    /// Get raw bytes (use with caution)
    pub fn raw_bytes(&self) -> &[u8; 32] {
        &self.private_key
    }
}
