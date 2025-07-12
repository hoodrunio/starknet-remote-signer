#[cfg(test)]
mod tests {
    use crate::signer::starknet_signer::StarknetSigner;
    use crate::signer::transaction_hash::compute_transaction_hash;
    use starknet::core::{
        chain_id,
        types::{
            BroadcastedInvokeTransactionV3, DataAvailabilityMode, ResourceBounds,
            ResourceBoundsMapping,
        },
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
        use starknet_crypto::Felt;

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
        use starknet_crypto::Felt;
        use tempfile::TempDir;

        let temp_dir = TempDir::new().unwrap();
        let keystore_path = temp_dir.path().to_str().unwrap();
        let private_key = "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef";
        let password = "test_password_123";
        let key_name = "test_key";

        // Create key in file backend
        FileBackend::create_key_string(keystore_path, key_name, private_key, password)
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
