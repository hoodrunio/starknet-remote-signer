#[cfg(test)]
mod tests {
    use crate::server::Server;
    use axum::http::StatusCode;
    use axum_test::TestServer;

    async fn create_test_server() -> TestServer {
        // Set test private key in environment BEFORE creating config
        std::env::set_var(
            "TEST_PRIVATE_KEY",
            "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
        );

        let config = crate::Config {
            server: crate::config::ServerConfig {
                address: "0.0.0.0".to_string(),
                port: 3000,
            },
            tls: crate::config::TlsConfig {
                enabled: false,
                cert_file: None,
                key_file: None,
            },
            keystore: crate::config::KeystoreConfig {
                backend: "environment".to_string(),
                path: None,
                dir: None,
                env_var: Some("TEST_PRIVATE_KEY".to_string()),
                device: None,
                key_name: None,
            },
            passphrase: None,
            security: crate::config::SecurityConfig::default(),
            audit: crate::config::AuditConfig::default(),
            logging: crate::config::LoggingConfig::default(),
        };

        // Set test private key in environment
        std::env::set_var(
            "TEST_PRIVATE_KEY",
            "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
        );
        let server = Server::new(config).await.expect("Failed to create server");
        TestServer::new(server.create_router()).expect("Failed to create test server")
    }

    #[tokio::test]
    #[ignore = "TODO: Fix IP validation issues in test environment"]
    async fn test_health_check() {
        let server = create_test_server().await;

        let response = server.get("/health").await;
        assert_eq!(response.status_code(), StatusCode::OK);

        let health: crate::handlers::HealthResponse = response.json();
        assert_eq!(health.status, "healthy");
        assert_eq!(health.version, env!("CARGO_PKG_VERSION"));
    }

    #[tokio::test]
    #[ignore = "TODO: Fix IP validation issues in test environment"]
    async fn test_public_key() {
        let server = create_test_server().await;

        let response = server.get("/get_public_key").await;
        assert_eq!(response.status_code(), StatusCode::OK);

        let key_response: crate::handlers::PublicKeyResponse = response.json();
        assert_ne!(key_response.public_key, starknet_crypto::Felt::ZERO);
    }

    #[tokio::test]
    #[ignore = "TODO: Fix IP validation issues in test environment"]
    async fn test_metrics() {
        let server = create_test_server().await;

        // Call health to increment metrics
        let _ = server.get("/health").await;

        let response = server.get("/metrics").await;
        assert_eq!(response.status_code(), StatusCode::OK);

        let metrics: crate::handlers::MetricsResponse = response.json();
        assert_eq!(metrics.health_checks, 1);
    }
}
