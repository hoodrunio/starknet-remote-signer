use super::types::Config;
use crate::errors::SignerError;
use crate::keystore::{BackendConfig, Keystore};
use crate::utils::get_passphrase_securely;

impl Config {
    /// Get passphrase securely for keystore operations
    pub fn get_keystore_passphrase(&self) -> Result<Option<String>, SignerError> {
        match self.keystore.backend.as_str() {
            "software" | "file" => {
                let passphrase =
                    get_passphrase_securely(self.passphrase.clone(), "Enter keystore passphrase: ")
                        .map_err(|e| {
                            SignerError::Config(format!("Failed to get passphrase: {e}"))
                        })?;
                Ok(Some(passphrase))
            }
            _ => Ok(None), // Other backends don't need passphrase
        }
    }

    /// Create keystore from configuration
    pub async fn create_keystore(&self) -> Result<Keystore, SignerError> {
        let backend = self.create_backend_config()?;
        Keystore::new(backend)
    }

    /// Create backend configuration from config settings
    fn create_backend_config(&self) -> Result<BackendConfig, SignerError> {
        match self.keystore.backend.as_str() {
            "software" => {
                let path = self
                    .keystore
                    .path
                    .as_ref()
                    .ok_or_else(|| SignerError::Config("Keystore path not set".to_string()))?;
                Ok(BackendConfig::Software {
                    keystore_path: path.clone(),
                })
            }
            "file" => {
                let dir =
                    self.keystore.dir.as_ref().ok_or_else(|| {
                        SignerError::Config("Keystore directory not set".to_string())
                    })?;
                Ok(BackendConfig::File {
                    keystore_dir: dir.clone(),
                    key_name: self.keystore.key_name.clone(),
                })
            }
            "environment" => {
                let env_var = self.keystore.env_var.as_ref().ok_or_else(|| {
                    SignerError::Config("Environment variable not set".to_string())
                })?;
                Ok(BackendConfig::Environment {
                    var_name: env_var.clone(),
                })
            }
            "os_keyring" => {
                let key_name = self.keystore.key_name.as_ref().ok_or_else(|| {
                    SignerError::Config("Key name not set for OS keyring backend".to_string())
                })?;
                Ok(BackendConfig::OsKeyring {
                    key_name: key_name.clone(),
                })
            }
            "hsm" => {
                Err(SignerError::Config(
                    "HSM backend not yet implemented".to_string(),
                ))
            }
            _ => {
                Err(SignerError::Config(
                    format!("Unknown keystore backend: {}. Supported backends: software, file, environment, os_keyring, hsm", self.keystore.backend)
                ))
            }
        }
    }
}
