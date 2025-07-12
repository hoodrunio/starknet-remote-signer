use starknet::core::types::BroadcastedInvokeTransactionV3;
use starknet_crypto::Felt;
use tracing::{debug, info};

use super::transaction_hash::compute_transaction_hash;
use crate::errors::SignerError;
use crate::keystore::SharedKeystore;

/// Thread-safe signer that handles Starknet transaction signing
#[derive(Clone)]
pub struct StarknetSigner {
    keystore: SharedKeystore,
}

impl StarknetSigner {
    /// Create a new signer from a keystore
    pub async fn new(keystore: crate::keystore::Keystore) -> Result<Self, SignerError> {
        let shared_keystore = SharedKeystore::new(keystore);
        let public_key = shared_keystore.public_key().await?;
        info!("Signer initialized with public key: 0x{:x}", public_key);

        Ok(Self {
            keystore: shared_keystore,
        })
    }

    /// Get the public key of this signer
    pub async fn public_key(&self) -> Result<Felt, SignerError> {
        self.keystore.public_key().await
    }

    /// Sign a transaction hash
    pub async fn sign_transaction_hash(
        &self,
        transaction_hash: Felt,
    ) -> Result<Vec<Felt>, SignerError> {
        debug!("Signing transaction hash: 0x{:x}", transaction_hash);

        let signing_key = self.keystore.signing_key().await?;
        let signature = signing_key
            .sign(&transaction_hash)
            .map_err(|e| SignerError::Crypto(format!("Signing failed: {e}")))?;

        // Note: Felt types don't implement Zeroize, so we can't use SecureBuffer
        // The signature components are returned directly
        // In a future enhancement, we could implement custom Zeroize for Felt
        Ok(vec![signature.r, signature.s])
    }

    /// Sign a full transaction (computes hash and signs)
    pub async fn sign_transaction(
        &self,
        transaction: &BroadcastedInvokeTransactionV3,
        chain_id: Felt,
    ) -> Result<Vec<Felt>, SignerError> {
        let transaction_hash = compute_transaction_hash(transaction, chain_id)?;
        debug!("Computed transaction hash: 0x{:x}", transaction_hash);

        // Note: Felt types don't implement Zeroize, so we can't use SecureBuffer for transaction_hash
        // The hash is used directly for signing
        self.sign_transaction_hash(transaction_hash).await
    }
}
