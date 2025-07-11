use std::net::SocketAddr;
use axum::Router;
use tracing::info;

use crate::config::TlsConfig;
use crate::errors::SignerError;

/// TLS utility for managing TLS configuration and server setup
pub struct TlsManager {
    config: TlsConfig,
}

impl TlsManager {
    /// Create a new TLS manager with the given configuration
    pub fn new(config: TlsConfig) -> Self {
        Self { config }
    }

    /// Check if TLS is enabled
    pub fn is_enabled(&self) -> bool {
        self.config.enabled
    }

    /// Load TLS configuration from certificate and key files
    pub async fn load_tls_config(&self) -> Result<axum_server::tls_rustls::RustlsConfig, SignerError> {
        if !self.config.enabled {
            return Err(SignerError::Config("TLS is not enabled".to_string()));
        }

        let cert_file = self.config.cert_file.as_ref()
            .ok_or_else(|| SignerError::Config("TLS certificate file not specified".to_string()))?;
        let key_file = self.config.key_file.as_ref()
            .ok_or_else(|| SignerError::Config("TLS key file not specified".to_string()))?;

        // Validate that files exist
        if !std::path::Path::new(cert_file).exists() {
            return Err(SignerError::Config(format!("TLS certificate file not found: {cert_file}")));
        }
        if !std::path::Path::new(key_file).exists() {
            return Err(SignerError::Config(format!("TLS key file not found: {key_file}")));
        }

        info!("Loading TLS configuration from {} and {}", cert_file, key_file);

        // Create TLS config using axum-server
        let tls_config = axum_server::tls_rustls::RustlsConfig::from_pem_file(cert_file, key_file)
            .await
            .map_err(|e| SignerError::Config(format!("Failed to load TLS config: {e}")))?;

        Ok(tls_config)
    }

    /// Start TLS server with the given router and address
    pub async fn serve_tls(
        &self,
        app: Router,
        addr: SocketAddr,
    ) -> Result<(), SignerError> {
        let tls_config = self.load_tls_config().await?;

        info!("🔒 TLS enabled");
        info!("✅ Server ready - accepting TLS connections on {}", addr);

        // Start TLS server
        axum_server::bind_rustls(addr, tls_config)
            .serve(app.into_make_service_with_connect_info::<SocketAddr>())
            .await
            .map_err(|e| SignerError::Internal(format!("TLS server error: {e}")))?;

        Ok(())
    }

    /// Start non-TLS server with the given router and address
    pub async fn serve_http(
        app: Router,
        addr: SocketAddr,
    ) -> Result<(), SignerError> {
        let listener = tokio::net::TcpListener::bind(addr).await
            .map_err(|e| SignerError::Internal(format!("Failed to bind to {addr}: {e}")))?;

        info!("✅ Server ready - accepting connections (HTTP only) on {}", addr);

        axum::serve(listener, app.into_make_service_with_connect_info::<SocketAddr>())
            .await
            .map_err(|e| SignerError::Internal(format!("Server error: {e}")))?;

        Ok(())
    }

    /// Get TLS configuration summary for logging
    pub fn get_config_summary(&self) -> String {
        if self.config.enabled {
            format!(
                "TLS enabled (cert: {}, key: {})",
                self.config.cert_file.as_deref().unwrap_or("not set"),
                self.config.key_file.as_deref().unwrap_or("not set")
            )
        } else {
            "TLS disabled".to_string()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_tls_manager_disabled() {
        let config = TlsConfig {
            enabled: false,
            cert_file: None,
            key_file: None,
        };
        let tls_manager = TlsManager::new(config);
        assert!(!tls_manager.is_enabled());
        assert_eq!(tls_manager.get_config_summary(), "TLS disabled");
    }

    #[test]
    fn test_tls_manager_enabled() {
        let config = TlsConfig {
            enabled: true,
            cert_file: Some("/path/to/cert.pem".to_string()),
            key_file: Some("/path/to/key.pem".to_string()),
        };
        let tls_manager = TlsManager::new(config);
        assert!(tls_manager.is_enabled());
        assert_eq!(
            tls_manager.get_config_summary(),
            "TLS enabled (cert: /path/to/cert.pem, key: /path/to/key.pem)"
        );
    }

    #[tokio::test]
    async fn test_load_tls_config_disabled() {
        let config = TlsConfig {
            enabled: false,
            cert_file: None,
            key_file: None,
        };
        let tls_manager = TlsManager::new(config);
        
        let result = tls_manager.load_tls_config().await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("TLS is not enabled"));
    }

    #[tokio::test]
    async fn test_load_tls_config_missing_files() {
        let config = TlsConfig {
            enabled: true,
            cert_file: Some("/nonexistent/cert.pem".to_string()),
            key_file: Some("/nonexistent/key.pem".to_string()),
        };
        let tls_manager = TlsManager::new(config);
        
        let result = tls_manager.load_tls_config().await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("not found"));
    }
} 