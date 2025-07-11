#[cfg(test)]
mod integration_tests {
    use crate::config::{AuditConfig, KeystoreConfig, SecurityConfig, ServerConfig, TlsConfig};
    use crate::{Config, Server};
    use axum::extract::connect_info::MockConnectInfo;
    use axum_test::TestServer;
    use serde_json::json;
    use starknet::core::types::{
        BroadcastedInvokeTransactionV3, DataAvailabilityMode, ResourceBounds, ResourceBoundsMapping,
    };
    use starknet::macros::felt;
    use std::net::SocketAddr;

    async fn create_test_server() -> TestServer {
        // Set test private key in environment
        std::env::set_var(
            "TEST_PRIVATE_KEY",
            "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
        );

        let config = Config {
            server: ServerConfig {
                address: "127.0.0.1".to_string(),
                port: 3000,
            },
            tls: TlsConfig {
                enabled: false,
                cert_file: None,
                key_file: None,
            },
            keystore: KeystoreConfig {
                backend: "environment".to_string(),
                path: None,
                dir: None,
                env_var: Some("TEST_PRIVATE_KEY".to_string()),
                device: None,
                key_name: None,
            },
            passphrase: None,
            security: SecurityConfig {
                allowed_chain_ids: vec![], // Allow all chains in tests
                allowed_ips: vec![],       // Allow all IPs in tests
            },
            audit: AuditConfig {
                enabled: false,                              // Disable audit logging in tests
                log_path: "/tmp/test-audit.log".to_string(), // Temporary path for tests
                rotate_daily: false,
            },
        };

        let server = Server::new(config).await.unwrap();

        // Add MockConnectInfo layer to provide SocketAddr in tests
        let app = server
            .create_router()
            .layer(MockConnectInfo(SocketAddr::from(([127, 0, 0, 1], 8080))));

        TestServer::new(app).unwrap()
    }

    #[tokio::test]
    async fn test_starknet_attestation_compatibility() {
        let server = create_test_server().await;

        // This is exactly what starknet-attestation sends
        let request_body = json!({
            "transaction": {
                "type": "INVOKE",
                "sender_address": "0x2e216b191ac966ba1d35cb6cfddfaf9c12aec4dfe869d9fa6233611bb334ee9",
                "calldata": [
                    "0x1",
                    "0x4862e05d00f2d0981c4a912269c21ad99438598ab86b6e70d1cee267caaa78d",
                    "0x37446750a403c1b4014436073cf8d08ceadc5b156ac1c8b7b0ca41a0c9c1c54",
                    "0x1",
                    "0x614f596b9d8eafbc87a48ff3a2a4bd503762d3f4be7c91cdeb766cf869c2233"
                ],
                "version": "0x3",
                "signature": [],
                "nonce": "0xbf",
                "resource_bounds": {
                    "l1_gas": {
                        "max_amount": "0x0",
                        "max_price_per_unit": "0x49f83fa3027b"
                    },
                    "l1_data_gas": {
                        "max_amount": "0x600",
                        "max_price_per_unit": "0x3948c"
                    },
                    "l2_gas": {
                        "max_amount": "0x1142700",
                        "max_price_per_unit": "0x33a8f57f9"
                    }
                },
                "tip": "0x0",
                "paymaster_data": [],
                "account_deployment_data": [],
                "nonce_data_availability_mode": "L1",
                "fee_data_availability_mode": "L1"
            },
            "chain_id": "0x534e5f5345504f4c4941"
        });

        // Send request exactly like starknet-attestation does
        let response = server.post("/sign").json(&request_body).await;

        assert_eq!(response.status_code(), 200);

        let response_json: serde_json::Value = response.json();

        // Check response format matches what starknet-attestation expects
        assert!(response_json.get("signature").is_some());
        let signature = response_json["signature"].as_array().unwrap();
        assert_eq!(signature.len(), 2); // Should have r and s components

        // Signatures should be valid hex strings
        for component in signature {
            let sig_str = component.as_str().unwrap();
            assert!(sig_str.starts_with("0x"));
            assert!(sig_str.len() > 10); // Should be a meaningful signature
        }

        println!("✅ starknet-attestation compatibility test passed!");
        println!(
            "Response: {}",
            serde_json::to_string_pretty(&response_json).unwrap()
        );
    }

    #[tokio::test]
    async fn test_real_transaction_from_starknet_attestation() {
        let server = create_test_server().await;

        // Real transaction structure from starknet-attestation README
        let tx = BroadcastedInvokeTransactionV3 {
            sender_address: felt!(
                "0x2e216b191ac966ba1d35cb6cfddfaf9c12aec4dfe869d9fa6233611bb334ee9"
            ),
            calldata: vec![
                felt!("0x1"),
                felt!("0x4862e05d00f2d0981c4a912269c21ad99438598ab86b6e70d1cee267caaa78d"),
                felt!("0x37446750a403c1b4014436073cf8d08ceadc5b156ac1c8b7b0ca41a0c9c1c54"),
                felt!("0x1"),
                felt!("0x614f596b9d8eafbc87a48ff3a2a4bd503762d3f4be7c91cdeb766cf869c2233"),
            ],
            signature: vec![],
            nonce: felt!("0xbf"),
            resource_bounds: ResourceBoundsMapping {
                l1_gas: ResourceBounds {
                    max_amount: 0,
                    max_price_per_unit: 0x49f83fa3027b,
                },
                l1_data_gas: ResourceBounds {
                    max_amount: 0x600,
                    max_price_per_unit: 0x3948c,
                },
                l2_gas: ResourceBounds {
                    max_amount: 0x1142700,
                    max_price_per_unit: 0x33a8f57f9,
                },
            },
            tip: 0,
            paymaster_data: vec![],
            account_deployment_data: vec![],
            nonce_data_availability_mode: DataAvailabilityMode::L1,
            fee_data_availability_mode: DataAvailabilityMode::L1,
            is_query: false,
        };

        let request = json!({
            "transaction": tx,
            "chain_id": "0x534e5f5345504f4c4941"
        });

        let response = server.post("/sign").json(&request).await;

        assert_eq!(response.status_code(), 200);

        let response_json: serde_json::Value = response.json();
        assert!(response_json.get("signature").is_some());

        println!("✅ Real transaction test passed!");
    }

    #[tokio::test]
    async fn test_health_endpoint() {
        let server = create_test_server().await;

        let response = server.get("/health").await;
        assert_eq!(response.status_code(), 200);

        let health: serde_json::Value = response.json();
        assert_eq!(health["status"], "healthy");
        assert!(health.get("public_key").is_some());

        println!("✅ Health check test passed!");
    }

    #[tokio::test]
    async fn test_public_key_endpoint() {
        let server = create_test_server().await;

        let response = server.get("/get_public_key").await;
        assert_eq!(response.status_code(), 200);

        let key_response: serde_json::Value = response.json();
        assert!(key_response.get("public_key").is_some());

        println!("✅ Public key test passed!");
    }
}
