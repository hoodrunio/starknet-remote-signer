#[cfg(test)]
use tempfile::NamedTempFile;

#[cfg(test)]
use crate::keystore::backends::BackendConfig;
#[cfg(test)]
use crate::keystore::core::Keystore;

#[tokio::test]
async fn test_environment_keystore() {
    let private_key = "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef";
    std::env::set_var("TEST_PRIVATE_KEY", private_key);

    let config = BackendConfig::Environment {
        var_name: "TEST_PRIVATE_KEY".to_string(),
    };

    let mut keystore = Keystore::new(config).unwrap();
    assert_eq!(keystore.backend_type(), "environment");

    keystore.init(None).await.unwrap();

    let loaded_key = keystore.signing_key().await.unwrap();
    let expected_key = starknet::signers::SigningKey::from_secret_scalar(
        starknet_crypto::Felt::from_hex(private_key).unwrap(),
    );

    assert_eq!(loaded_key.secret_scalar(), expected_key.secret_scalar());
}

#[tokio::test]
async fn test_software_keystore() {
    let temp_file = NamedTempFile::new().unwrap();
    let keystore_path = temp_file.path().to_str().unwrap();
    let private_key = "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef";
    let passphrase = "test_password_123";

    // Create keystore
    Keystore::create_keystore(keystore_path, private_key, passphrase)
        .await
        .unwrap();

    // Load keystore
    let config = BackendConfig::Software {
        keystore_path: keystore_path.to_string(),
    };

    let mut keystore = Keystore::new(config).unwrap();
    assert_eq!(keystore.backend_type(), "software");

    keystore.init(Some(passphrase)).await.unwrap();

    let loaded_key = keystore.signing_key().await.unwrap();
    let expected_key = starknet::signers::SigningKey::from_secret_scalar(
        starknet_crypto::Felt::from_hex(private_key).unwrap(),
    );

    assert_eq!(loaded_key.secret_scalar(), expected_key.secret_scalar());
}

#[test]
fn test_keystore_backend_types() {
    let software_config = BackendConfig::Software {
        keystore_path: "/test/path".to_string(),
    };
    let keystore = Keystore::new(software_config).unwrap();
    assert_eq!(keystore.backend_type(), "software");

    let env_config = BackendConfig::Environment {
        var_name: "TEST_VAR".to_string(),
    };
    let keystore = Keystore::new(env_config).unwrap();
    assert_eq!(keystore.backend_type(), "environment");

    let keyring_config = BackendConfig::OsKeyring {
        key_name: "test-key".to_string(),
    };
    let keystore = Keystore::new(keyring_config).unwrap();
    assert_eq!(keystore.backend_type(), "os_keyring");
}

#[test]
fn test_hsm_backend_not_implemented() {
    let hsm_config = BackendConfig::Hsm {
        device_path: "/dev/hsm0".to_string(),
    };

    let result = Keystore::new(hsm_config);
    assert!(result.is_err());
    assert!(result
        .unwrap_err()
        .to_string()
        .contains("not yet implemented"));
}
