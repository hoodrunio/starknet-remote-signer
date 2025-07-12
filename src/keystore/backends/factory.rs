use crate::errors::SignerError;
use crate::keystore::backends::{
    BackendConfig, EnvironmentBackend, FileBackend, KeystoreBackend, OsKeyringBackend,
    SoftwareBackend,
};

/// Factory for creating keystore backends from configuration
pub struct BackendFactory;

impl BackendFactory {
    /// Create a backend from configuration
    pub fn create(config: BackendConfig) -> Result<Box<dyn KeystoreBackend>, SignerError> {
        let backend: Box<dyn KeystoreBackend> = match config {
            BackendConfig::Software { keystore_path } => {
                Box::new(SoftwareBackend::new(keystore_path))
            }
            BackendConfig::File {
                keystore_dir,
                key_name,
            } => Box::new(FileBackend::new_with_key(keystore_dir, key_name)),
            BackendConfig::Environment { var_name } => Box::new(EnvironmentBackend::new(var_name)),
            BackendConfig::OsKeyring { key_name } => Box::new(OsKeyringBackend::new(key_name)),
            BackendConfig::Hsm { .. } => {
                return Err(SignerError::Config(
                    "HSM backend not yet implemented".to_string(),
                ));
            }
        };

        Ok(backend)
    }

    /// Create a backend from CLI arguments for key management operations
    pub fn from_cli_args(
        backend_type: &str,
        key_name: Option<String>,
        keystore_path: Option<String>,
        keystore_dir: Option<String>,
        env_var: Option<String>,
    ) -> Result<Box<dyn KeystoreBackend>, SignerError> {
        let config = match backend_type {
            "software" => {
                let path = keystore_path.ok_or_else(|| {
                    SignerError::Config(
                        "Keystore path is required for software backend".to_string(),
                    )
                })?;
                BackendConfig::Software {
                    keystore_path: path,
                }
            }
            "file" => {
                let dir = keystore_dir.ok_or_else(|| {
                    SignerError::Config(
                        "Keystore directory is required for file backend".to_string(),
                    )
                })?;
                BackendConfig::File {
                    keystore_dir: dir,
                    key_name,
                }
            }
            "environment" => {
                let var = env_var.unwrap_or_else(|| "SIGNER_PRIVATE_KEY".to_string());
                BackendConfig::Environment { var_name: var }
            }
            "os_keyring" => {
                let name = key_name.ok_or_else(|| {
                    SignerError::Config("Key name is required for os_keyring backend".to_string())
                })?;
                BackendConfig::OsKeyring { key_name: name }
            }
            _ => {
                return Err(SignerError::Config(format!(
                    "Unknown backend: {backend_type}. Supported backends: software, file, environment, os_keyring"
                )));
            }
        };

        Self::create(config)
    }
}
