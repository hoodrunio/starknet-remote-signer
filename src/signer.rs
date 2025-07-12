use starknet::core::types::BroadcastedInvokeTransactionV3;
use starknet_crypto::{poseidon_hash_many, Felt, PoseidonHasher};
use tracing::{debug, info};

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

        self.sign_transaction_hash(transaction_hash).await
    }
}

/// Cairo string for "invoke"
const PREFIX_INVOKE: Felt = Felt::from_raw([
    513398556346534256,
    18446744073709551615,
    18446744073709551615,
    18443034532770911073,
]);

/// 2 ^ 128 + 3
const QUERY_VERSION_THREE: Felt = Felt::from_raw([
    576460752142432688,
    18446744073709551584,
    17407,
    18446744073700081569,
]);

/// Compute the transaction hash for an invoke transaction v3
/// This is a copy of the transaction hash computation from starknet-rs
pub fn compute_transaction_hash(
    tx: &BroadcastedInvokeTransactionV3,
    chain_id: Felt,
) -> Result<Felt, SignerError> {
    let mut hasher = PoseidonHasher::new();

    hasher.update(PREFIX_INVOKE);
    hasher.update(if tx.is_query {
        QUERY_VERSION_THREE
    } else {
        Felt::THREE
    });
    hasher.update(tx.sender_address);

    // Compute fee hash
    hasher.update({
        let mut fee_hasher = PoseidonHasher::new();

        fee_hasher.update(tx.tip.into());

        // L1 Gas resource bounds
        let mut resource_buffer = [
            0, 0, b'L', b'1', b'_', b'G', b'A', b'S', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0,
        ];
        resource_buffer[8..(8 + 8)]
            .copy_from_slice(&tx.resource_bounds.l1_gas.max_amount.to_be_bytes());
        resource_buffer[(8 + 8)..]
            .copy_from_slice(&tx.resource_bounds.l1_gas.max_price_per_unit.to_be_bytes());
        fee_hasher.update(Felt::from_bytes_be(&resource_buffer));

        // L2 Gas resource bounds
        let mut resource_buffer = [
            0, 0, b'L', b'2', b'_', b'G', b'A', b'S', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0,
        ];
        resource_buffer[8..(8 + 8)]
            .copy_from_slice(&tx.resource_bounds.l2_gas.max_amount.to_be_bytes());
        resource_buffer[(8 + 8)..]
            .copy_from_slice(&tx.resource_bounds.l2_gas.max_price_per_unit.to_be_bytes());
        fee_hasher.update(Felt::from_bytes_be(&resource_buffer));

        // L1 Data Gas resource bounds
        let mut resource_buffer = [
            0, b'L', b'1', b'_', b'D', b'A', b'T', b'A', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ];
        resource_buffer[8..(8 + 8)]
            .copy_from_slice(&tx.resource_bounds.l1_data_gas.max_amount.to_be_bytes());
        resource_buffer[(8 + 8)..].copy_from_slice(
            &tx.resource_bounds
                .l1_data_gas
                .max_price_per_unit
                .to_be_bytes(),
        );
        fee_hasher.update(Felt::from_bytes_be(&resource_buffer));

        fee_hasher.finalize()
    });

    hasher.update(poseidon_hash_many(&tx.paymaster_data));
    hasher.update(chain_id);
    hasher.update(tx.nonce);

    // Hard-coded L1 DA mode for nonce and fee
    hasher.update(Felt::ZERO);

    hasher.update(poseidon_hash_many(&tx.account_deployment_data));
    hasher.update(poseidon_hash_many(&tx.calldata));

    Ok(hasher.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;
    use starknet::core::{
        chain_id,
        types::{DataAvailabilityMode, ResourceBounds, ResourceBoundsMapping},
    };
    use starknet::macros::felt;

    #[test]
    fn test_transaction_hash_computation() {
        let tx = BroadcastedInvokeTransactionV3 {
            sender_address: felt!(
                "0x2e216b191ac966ba1d35cb6cfddfaf9c12aec4dfe869d9fa6233611bb334ee9"
            ),
            calldata: vec![
                felt!("0x1"),
                felt!("0x3f32e152b9637c31bfcf73e434f78591067a01ba070505ff6ee195642c9acfb"),
                felt!("0x37446750a403c1b4014436073cf8d08ceadc5b156ac1c8b7b0ca41a0c9c1c54"),
                felt!("0x1"),
                felt!("0x7979a0a0a175d7e738e8e9ba6fa6d48f680d67758f719390eee58e790819836"),
            ],
            signature: vec![],
            nonce: felt!("0x106"),
            resource_bounds: ResourceBoundsMapping {
                l1_gas: ResourceBounds {
                    max_amount: 0,
                    max_price_per_unit: 0x51066a69ad72c,
                },
                l1_data_gas: ResourceBounds {
                    max_amount: 0x600,
                    max_price_per_unit: 0x1254,
                },
                l2_gas: ResourceBounds {
                    max_amount: 0xf00000,
                    max_price_per_unit: 0x308c5bff6,
                },
            },
            tip: 0,
            paymaster_data: vec![],
            account_deployment_data: vec![],
            nonce_data_availability_mode: DataAvailabilityMode::L1,
            fee_data_availability_mode: DataAvailabilityMode::L1,
            is_query: false,
        };

        let chain_id = chain_id::SEPOLIA;
        let tx_hash = compute_transaction_hash(&tx, chain_id).unwrap();

        // This should match the expected hash from the original example
        assert_eq!(
            tx_hash,
            felt!("0x382a7406fe3931ba1faf00d1eaa36b7c8770b8d185b091b730ecdb4dba5f3ce")
        );
    }

    #[tokio::test]
    async fn test_signer_creation_and_signing() {
        use crate::keystore::{backends::BackendConfig, Keystore};

        let private_key = "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef";
        std::env::set_var("TEST_SIGNER_KEY", private_key);

        let mut keystore = Keystore::new(BackendConfig::Environment {
            var_name: "TEST_SIGNER_KEY".to_string(),
        })
        .unwrap();
        keystore.init(None).await.unwrap();

        let signer = StarknetSigner::new(keystore).await.unwrap();

        // Test public key retrieval
        let public_key = signer.public_key().await.unwrap();
        assert_ne!(public_key, Felt::ZERO);

        // Test signing a simple hash
        let test_hash = felt!("0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef");
        let signature = signer.sign_transaction_hash(test_hash).await.unwrap();

        // Signature should have two non-zero components
        assert_ne!(signature[0], Felt::ZERO);
        assert_ne!(signature[1], Felt::ZERO);
    }

    #[tokio::test]
    async fn test_signer_with_file_backend() {
        use crate::keystore::{backends::BackendConfig, FileBackend, Keystore};
        use tempfile::TempDir;

        let temp_dir = TempDir::new().unwrap();
        let keystore_path = temp_dir.path().to_str().unwrap();
        let private_key = "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef";
        let password = "test_password_123";
        let key_name = "test_key";

        // Create key in file backend
        FileBackend::create_key(keystore_path, key_name, private_key, password)
            .await
            .unwrap();

        // Load keystore with file backend
        let mut keystore = Keystore::new(BackendConfig::File {
            keystore_dir: keystore_path.to_string(),
            key_name: Some(key_name.to_string()),
        })
        .unwrap();
        keystore.init(Some(password)).await.unwrap();

        let signer = StarknetSigner::new(keystore).await.unwrap();

        // Test public key retrieval
        let public_key = signer.public_key().await.unwrap();
        assert_ne!(public_key, Felt::ZERO);

        // Test signing a simple hash
        let test_hash = felt!("0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef");
        let signature = signer.sign_transaction_hash(test_hash).await.unwrap();

        // Signature should have two non-zero components
        assert_ne!(signature[0], Felt::ZERO);
        assert_ne!(signature[1], Felt::ZERO);
    }
}
