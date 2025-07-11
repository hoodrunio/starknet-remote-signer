use josekit::jwe::{JweHeader, PBES2_HS256_A128KW};

use crate::errors::SignerError;

/// JOSE JWE token for encrypted key storage
/// Uses PBES2-HS256+A128KW for password-based key derivation and wrapping
/// Uses A256GCM for content encryption
pub type EncryptedKeystore = String;

/// Encrypt private key using JOSE JWE with PBES2-HS256+A128KW and A256GCM
pub fn encrypt_key(
    private_key: &[u8; 32],
    passphrase: &str,
) -> Result<EncryptedKeystore, SignerError> {
    // Create JWE header with PBES2-HS256+A128KW key management and A256GCM content encryption
    let mut header = JweHeader::new();
    header.set_algorithm("PBES2-HS256+A128KW");
    header.set_content_encryption("A256GCM");

    // Create encrypter from password
    let encrypter = PBES2_HS256_A128KW
        .encrypter_from_bytes(passphrase.as_bytes())
        .map_err(|e| SignerError::Crypto(format!("Failed to create encrypter: {e}")))?;

    // Encrypt the private key data
    let jwe_token = josekit::jwe::serialize_compact(private_key, &header, &encrypter)
        .map_err(|e| SignerError::Crypto(format!("Encryption failed: {e}")))?;

    Ok(jwe_token)
}

/// Decrypt private key from JOSE JWE token
pub fn decrypt_key(jwe_token: &str, passphrase: &str) -> Result<[u8; 32], SignerError> {
    // Create decrypter from password
    let decrypter = PBES2_HS256_A128KW
        .decrypter_from_bytes(passphrase.as_bytes())
        .map_err(|e| SignerError::Crypto(format!("Failed to create decrypter: {e}")))?;

    // Decrypt the JWE token
    let (decrypted_data, _header) = josekit::jwe::deserialize_compact(jwe_token, &decrypter)
        .map_err(|e| SignerError::Crypto(format!("Decryption failed: {e}")))?;

    // Ensure the decrypted data is the correct length
    if decrypted_data.len() != 32 {
        return Err(SignerError::InvalidKey(format!(
            "Invalid decrypted key length: expected 32 bytes, got {}",
            decrypted_data.len()
        )));
    }

    // Convert to fixed-size array
    let mut key = [0u8; 32];
    key.copy_from_slice(&decrypted_data);
    Ok(key)
}
