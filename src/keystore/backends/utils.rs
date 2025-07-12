use std::fs;
use tracing::warn;

use crate::errors::SignerError;

/// Common utilities for keystore backends
pub struct BackendUtils;

impl BackendUtils {
    /// Validate private key hex format
    pub fn validate_private_key_hex(private_key_hex: &str) -> Result<(), SignerError> {
        if private_key_hex.is_empty() {
            return Err(SignerError::InvalidKey(
                "Private key cannot be empty".to_string(),
            ));
        }

        if !private_key_hex.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(SignerError::InvalidKey(
                "Private key must be a valid hex string".to_string(),
            ));
        }

        if private_key_hex.len() != 64 {
            return Err(SignerError::InvalidKey(
                "Private key must be exactly 64 hex characters (32 bytes)".to_string(),
            ));
        }

        Ok(())
    }

    /// Set restrictive file permissions (Unix only)
    pub fn set_secure_file_permissions(path: &str) -> Result<(), SignerError> {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = fs::metadata(path)
                .map_err(|e| SignerError::Config(format!("Failed to get file metadata: {e}")))?
                .permissions();
            perms.set_mode(0o600); // rw-------
            fs::set_permissions(path, perms)
                .map_err(|e| SignerError::Config(format!("Failed to set file permissions: {e}")))?;
        }
        Ok(())
    }

    /// Set restrictive directory permissions (Unix only)
    pub fn set_secure_directory_permissions(path: &str) -> Result<(), SignerError> {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = fs::metadata(path)
                .map_err(|e| SignerError::Config(format!("Failed to get directory metadata: {e}")))?
                .permissions();
            perms.set_mode(0o700); // rwx------
            fs::set_permissions(path, perms).map_err(|e| {
                SignerError::Config(format!("Failed to set directory permissions: {e}"))
            })?;
        }
        Ok(())
    }

    /// Create directory with secure permissions if it doesn't exist
    pub fn ensure_secure_directory(path: &str) -> Result<(), SignerError> {
        if !std::path::Path::new(path).exists() {
            fs::create_dir_all(path)
                .map_err(|e| SignerError::Config(format!("Failed to create directory: {e}")))?;
            Self::set_secure_directory_permissions(path)?;
        }
        Ok(())
    }

    /// Check if a path exists and is readable
    pub fn check_path_readable(path: &str) -> Result<(), SignerError> {
        fs::metadata(path)
            .map_err(|e| SignerError::Config(format!("Cannot access path {path}: {e}")))?;
        Ok(())
    }

    /// Check if a directory is writable by creating a test file
    pub fn check_directory_writable(path: &str) -> Result<(), SignerError> {
        let test_file = std::path::Path::new(path).join(".test_write");
        match fs::write(&test_file, "test") {
            Ok(()) => {
                let _ = fs::remove_file(&test_file);
                Ok(())
            }
            Err(e) => Err(SignerError::Config(format!(
                "Cannot write to directory {path}: {e}"
            ))),
        }
    }

    /// Log security warnings for less secure backends
    pub fn log_security_warnings(backend_type: &str) {
        if backend_type == "environment" {
            warn!("⚠️  SECURITY WARNING: Environment backend configured");
            warn!("⚠️  Private keys stored in environment variables are less secure");
            warn!("⚠️  Consider using 'software' or 'file' backend with encrypted keystore for production");
        }
    }

    /// Format backend-specific error messages consistently
    pub fn format_backend_error(backend_type: &str, operation: &str, details: &str) -> String {
        format!("{backend_type} backend {operation}: {details}")
    }
}
