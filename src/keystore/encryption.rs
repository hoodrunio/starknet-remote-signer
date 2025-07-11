use rand::{RngCore, rngs::OsRng};
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

use crate::errors::SignerError;

/// Key derivation parameters for PBKDF2
pub const PBKDF2_ITERATIONS: u32 = 100_000;
pub const SALT_SIZE: usize = 32;
pub const KEY_SIZE: usize = 32;

/// Encrypted key storage format
#[derive(Serialize, Deserialize)]
pub struct EncryptedKeystore {
    /// PBKDF2 salt
    pub salt: Vec<u8>,
    /// Encrypted private key
    pub encrypted_key: Vec<u8>,
    /// AES-GCM nonce
    pub nonce: Vec<u8>,
    /// Key derivation iterations
    pub iterations: u32,
    /// Version for future compatibility
    pub version: u8,
}

/// Encrypt private key using AES-256-GCM with PBKDF2 key derivation
pub fn encrypt_key(private_key: &[u8; 32], passphrase: &str) -> Result<EncryptedKeystore, SignerError> {
    use aes_gcm::{Aes256Gcm, KeyInit, aead::Aead};
    use pbkdf2::pbkdf2_hmac;
    use sha2::Sha256;

    // Generate random salt and nonce
    let mut salt = [0u8; SALT_SIZE];
    let mut nonce = [0u8; 12]; // GCM nonce is 12 bytes
    OsRng.fill_bytes(&mut salt);
    OsRng.fill_bytes(&mut nonce);

    // Derive key from passphrase
    let mut derived_key = [0u8; KEY_SIZE];
    pbkdf2_hmac::<Sha256>(passphrase.as_bytes(), &salt, PBKDF2_ITERATIONS, &mut derived_key);

    // Encrypt the private key
    let cipher = Aes256Gcm::new((&derived_key).into());
    let encrypted_key = cipher.encrypt((&nonce).into(), private_key.as_ref())
        .map_err(|e| SignerError::Crypto(format!("Encryption failed: {}", e)))?;

    // Zeroize sensitive data
    derived_key.zeroize();

    Ok(EncryptedKeystore {
        salt: salt.to_vec(),
        encrypted_key,
        nonce: nonce.to_vec(),
        iterations: PBKDF2_ITERATIONS,
        version: 1,
    })
}

/// Decrypt private key
pub fn decrypt_key(keystore: &EncryptedKeystore, passphrase: &str) -> Result<[u8; 32], SignerError> {
    use aes_gcm::{Aes256Gcm, KeyInit, aead::Aead};
    use pbkdf2::pbkdf2_hmac;
    use sha2::Sha256;

    // Derive key from passphrase
    let mut derived_key = [0u8; KEY_SIZE];
    pbkdf2_hmac::<Sha256>(
        passphrase.as_bytes(), 
        &keystore.salt, 
        keystore.iterations, 
        &mut derived_key
    );

    // Decrypt the private key
    let cipher = Aes256Gcm::new((&derived_key).into());
    let nonce_slice = keystore.nonce.as_slice();
    let decrypted = cipher.decrypt(nonce_slice.into(), keystore.encrypted_key.as_ref())
        .map_err(|e| SignerError::Crypto(format!("Decryption failed: {}", e)))?;

    // Zeroize sensitive data
    derived_key.zeroize();

    if decrypted.len() != 32 {
        return Err(SignerError::InvalidKey("Invalid decrypted key length".to_string()));
    }

    let mut key = [0u8; 32];
    key.copy_from_slice(&decrypted);
    Ok(key)
} 