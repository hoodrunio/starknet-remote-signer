use axum::{
    extract::{ConnectInfo, State},
    http::StatusCode,
    response::Json,
    routing::{get, post},
    Router,
};
use serde::{Deserialize, Serialize};
use starknet::core::types::BroadcastedInvokeTransactionV3;
use starknet_crypto::Felt;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tower::ServiceBuilder;
use tower_http::{cors::CorsLayer, trace::TraceLayer};
use tracing::{error, info, warn};

use crate::audit::{AttestationAuditEntry, AuditLogger};
use crate::config::Config;
use crate::errors::SignerError;
use crate::security::SecurityValidator;
use crate::signer::{StarknetSigner, compute_transaction_hash};

/// Helper function to validate IP address
fn validate_ip_access(security: &Option<SecurityValidator>, addr: &SocketAddr) -> Result<(), StatusCode> {
    if let Some(security) = security {
        if let Err(_) = security.validate_ip(&addr.ip()) {
            return Err(StatusCode::FORBIDDEN);
        }
    }
    Ok(())
}

/// Shared application state
#[derive(Clone)]
pub struct AppState {
    pub signer: StarknetSigner,
    pub config: Config,
    pub metrics: Arc<Metrics>,
    pub security: Option<SecurityValidator>,
    pub audit_logger: Option<Arc<AuditLogger>>,
}

/// Basic metrics for monitoring
#[derive(Default)]
pub struct Metrics {
    pub sign_requests: AtomicU64,
    pub sign_errors: AtomicU64,
    pub health_checks: AtomicU64,
}

/// HTTP Server for the remote signer
pub struct Server {
    config: Config,
    app_state: AppState,
}

/// Request/Response types
#[derive(Deserialize)]
pub struct SignRequest {
    pub transaction: BroadcastedInvokeTransactionV3,
    pub chain_id: Felt,
}

#[derive(Serialize)]
pub struct SignResponse {
    pub signature: Vec<Felt>,
}

#[derive(Serialize, Deserialize)]
pub struct PublicKeyResponse {
    pub public_key: Felt,
}

#[derive(Serialize, Deserialize)]
pub struct HealthResponse {
    pub status: String,
    pub version: String,
    pub public_key: Felt,
}

#[derive(Serialize, Deserialize)]
pub struct MetricsResponse {
    pub sign_requests: u64,
    pub sign_errors: u64,
    pub health_checks: u64,
}

impl Server {
    pub async fn new(config: Config) -> Result<Self, SignerError> {
        // Initialize keystore
        let mut keystore = config.create_keystore().await?;
        keystore.init(config.passphrase.as_deref()).await?;
        
        let signer = StarknetSigner::new(keystore)?;
        let metrics = Arc::new(Metrics::default());

        // Initialize security validator if configured
        let security = if !config.security.allowed_chain_ids.is_empty() || !config.security.allowed_ips.is_empty() {
            Some(SecurityValidator::new(
                config.security.allowed_chain_ids.clone(),
                config.security.allowed_ips.clone(),
            )?)
        } else {
            None
        };

        // Initialize audit logger if configured
        let audit_logger = if config.audit.enabled {
            Some(Arc::new(AuditLogger::new(&config.audit.log_path)?))
        } else {
            None
        };

        let app_state = AppState {
            signer,
            config: config.clone(),
            metrics,
            security,
            audit_logger,
        };

        Ok(Self { config, app_state })
    }

    pub async fn serve(self) -> Result<(), SignerError> {
        let app = self.create_router();

        let addr = SocketAddr::new(
            self.config.server.address.parse()
                .map_err(|e| SignerError::Config(format!("Invalid bind address: {}", e)))?,
            self.config.server.port,
        );

        info!("🚀 Starknet Remote Signer starting on {}", addr);
        
        let listener = tokio::net::TcpListener::bind(addr).await
            .map_err(|e| SignerError::Internal(format!("Failed to bind to {}: {}", addr, e)))?;

        if self.config.tls.enabled {
            info!("🔒 TLS enabled");
            // Note: TLS implementation would go here if needed
            warn!("TLS support not yet implemented in this version");
        }

        info!("✅ Server ready - accepting connections");

        axum::serve(listener, app.into_make_service_with_connect_info::<SocketAddr>())
            .await
            .map_err(|e| SignerError::Internal(format!("Server error: {}", e)))?;

        Ok(())
    }

    pub fn create_router(&self) -> Router {
        Router::new()
            .route("/health", get(health_check))
            .route("/get_public_key", get(get_public_key))
            .route("/sign", post(sign_transaction))
            .route("/metrics", get(get_metrics))
            .with_state(self.app_state.clone())
            .layer(
                ServiceBuilder::new()
                    .layer(TraceLayer::new_for_http())
                    .layer(CorsLayer::permissive()),
            )
    }
}

/// Health check endpoint
async fn health_check(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
) -> Result<Json<HealthResponse>, StatusCode> {
    // IP security check
    if let Err(_) = validate_ip_access(&state.security, &addr) {
        warn!("Rejected health check from unauthorized IP: {}", addr.ip());
        return Err(StatusCode::FORBIDDEN);
    }
    
    state.metrics.health_checks.fetch_add(1, Ordering::Relaxed);
    
    let public_key = state.signer.public_key().await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    
    Ok(Json(HealthResponse {
        status: "healthy".to_string(),
        version: env!("CARGO_PKG_VERSION").to_string(),
        public_key,
    }))
}

/// Get public key endpoint
async fn get_public_key(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
) -> Result<Json<PublicKeyResponse>, StatusCode> {
    // IP security check
    if let Err(_) = validate_ip_access(&state.security, &addr) {
        warn!("Rejected public key request from unauthorized IP: {}", addr.ip());
        return Err(StatusCode::FORBIDDEN);
    }
    
    let public_key = state.signer.public_key().await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    
    Ok(Json(PublicKeyResponse { public_key }))
}

/// Sign transaction endpoint
async fn sign_transaction(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Json(request): Json<SignRequest>,
) -> Result<Json<SignResponse>, StatusCode> {
    let start_time = std::time::Instant::now();
    state.metrics.sign_requests.fetch_add(1, Ordering::Relaxed);

    // Create audit entry
    let mut audit_entry = if state.audit_logger.is_some() {
        Some(AttestationAuditEntry::from_request(&request, &addr.ip().to_string(), start_time))
    } else {
        None
    };

    // Security checks
    if let Some(security) = &state.security {
        // Check IP allowlist
        if let Err(_) = validate_ip_access(&Some(security.clone()), &addr) {
            if let Some(audit) = &mut audit_entry {
                audit.set_error(format!("Unauthorized IP: {}", addr.ip()));
                audit.update_duration(start_time);
                if let Some(logger) = &state.audit_logger {
                    let _ = logger.log(audit).await;
                }
            }
            warn!("Rejected request from unauthorized IP: {}", addr.ip());
            return Err(StatusCode::FORBIDDEN);
        }

        // Check chain ID
        if let Err(e) = security.validate_chain_id(request.chain_id) {
            if let Some(audit) = &mut audit_entry {
                audit.set_error(e.to_string());
                audit.update_duration(start_time);
                if let Some(logger) = &state.audit_logger {
                    let _ = logger.log(audit).await;
                }
            }
            warn!("Rejected request for unauthorized chain ID: 0x{:x}", request.chain_id);
            return Err(StatusCode::BAD_REQUEST);
        }
    }

    info!(
        "Signing request from {} for sender: 0x{:x}, chain_id: 0x{:x}",
        addr.ip(), request.transaction.sender_address, request.chain_id
    );

    // Compute transaction hash for audit
    let tx_hash = match compute_transaction_hash(&request.transaction, request.chain_id) {
        Ok(hash) => {
            if let Some(audit) = &mut audit_entry {
                audit.set_transaction_hash(hash);
            }
            hash
        }
        Err(e) => {
            if let Some(audit) = &mut audit_entry {
                audit.set_error(format!("Failed to compute tx hash: {}", e));
                audit.update_duration(start_time);
                if let Some(logger) = &state.audit_logger {
                    let _ = logger.log(audit).await;
                }
            }
            state.metrics.sign_errors.fetch_add(1, Ordering::Relaxed);
            error!("Failed to compute transaction hash: {}", e);
            return Err(StatusCode::INTERNAL_SERVER_ERROR);
        }
    };

    // Sign transaction
    match state.signer.sign_transaction(&request.transaction, request.chain_id).await {
        Ok(signature) => {
            if let Some(audit) = &mut audit_entry {
                audit.set_signature(&signature);
                audit.set_success(true);
                audit.update_duration(start_time);
                if let Some(logger) = &state.audit_logger {
                    let _ = logger.log(audit).await;
                }
            }

            info!(
                "Transaction signed successfully for {} (tx_hash: 0x{:x})",
                addr.ip(), tx_hash
            );
            Ok(Json(SignResponse { signature }))
        }
        Err(e) => {
            if let Some(audit) = &mut audit_entry {
                audit.set_error(format!("Signing failed: {}", e));
                audit.update_duration(start_time);
                if let Some(logger) = &state.audit_logger {
                    let _ = logger.log(audit).await;
                }
            }

            state.metrics.sign_errors.fetch_add(1, Ordering::Relaxed);
            error!("Signing failed: {}", e);
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

/// Get metrics endpoint
async fn get_metrics(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
) -> Result<Json<MetricsResponse>, StatusCode> {
    // IP security check
    if let Err(_) = validate_ip_access(&state.security, &addr) {
        warn!("Rejected metrics request from unauthorized IP: {}", addr.ip());
        return Err(StatusCode::FORBIDDEN);
    }
    
    Ok(Json(MetricsResponse {
        sign_requests: state.metrics.sign_requests.load(Ordering::Relaxed),
        sign_errors: state.metrics.sign_errors.load(Ordering::Relaxed),
        health_checks: state.metrics.health_checks.load(Ordering::Relaxed),
    }))
}



#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::StatusCode;
    use axum_test::TestServer;
    
    async fn create_test_server() -> TestServer {
        let config = Config {
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
                env_var: Some("TEST_PRIVATE_KEY".to_string()),
                device: None,
            },
            passphrase: None,
            security: crate::config::SecurityConfig::default(),
            audit: crate::config::AuditConfig::default(),
        };

        // Set test private key in environment
        std::env::set_var("TEST_PRIVATE_KEY", "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef");
        let server = Server::new(config).await.unwrap();
        TestServer::new(server.create_router()).unwrap()
    }

    #[tokio::test]
    async fn test_health_check() {
        let server = create_test_server().await;
        
        let response = server.get("/health").await;
        assert_eq!(response.status_code(), StatusCode::OK);
        
        let health: HealthResponse = response.json();
        assert_eq!(health.status, "healthy");
        assert_eq!(health.version, env!("CARGO_PKG_VERSION"));
    }

    #[tokio::test]
    async fn test_public_key() {
        let server = create_test_server().await;
        
        let response = server.get("/get_public_key").await;
        assert_eq!(response.status_code(), StatusCode::OK);
        
        let key_response: PublicKeyResponse = response.json();
        assert_ne!(key_response.public_key, Felt::ZERO);
    }

    #[tokio::test]
    async fn test_metrics() {
        let server = create_test_server().await;
        
        // Call health to increment metrics
        let _ = server.get("/health").await;
        
        let response = server.get("/metrics").await;
        assert_eq!(response.status_code(), StatusCode::OK);
        
        let metrics: MetricsResponse = response.json();
        assert_eq!(metrics.health_checks, 1);
    }
} 