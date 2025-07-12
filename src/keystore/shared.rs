use std::sync::Arc;
use tokio::sync::Mutex;

use crate::errors::SignerError;
use crate::keystore::core::Keystore;

/// Thread-safe keystore wrapper for use in async contexts
#[derive(Clone)]
pub struct SharedKeystore {
    inner: Arc<Mutex<Keystore>>,
}

impl SharedKeystore {
    /// Create a new shared keystore
    pub fn new(keystore: Keystore) -> Self {
        Self {
            inner: Arc::new(Mutex::new(keystore)),
        }
    }

    /// Initialize the keystore
    pub async fn init(&self, config: Option<&str>) -> Result<(), SignerError> {
        let mut keystore = self.inner.lock().await;
        keystore.init(config).await
    }

    /// Get signing key
    pub async fn signing_key(&self) -> Result<starknet::signers::SigningKey, SignerError> {
        let keystore = self.inner.lock().await;
        keystore.signing_key().await
    }

    /// Get public key
    pub async fn public_key(&self) -> Result<starknet_crypto::Felt, SignerError> {
        let keystore = self.inner.lock().await;
        keystore.public_key().await
    }

    /// Check if available
    pub async fn is_available(&self) -> bool {
        let keystore = self.inner.lock().await;
        keystore.is_available()
    }

    /// Get backend type
    pub async fn backend_type(&self) -> String {
        let keystore = self.inner.lock().await;
        keystore.backend_type().to_string()
    }

    /// Delete key from storage
    pub async fn delete_key(&self) -> Result<(), SignerError> {
        let keystore = self.inner.lock().await;
        keystore.delete_key().await
    }
} 