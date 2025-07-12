use axum::{
    routing::{get, post},
    Router,
};
use std::net::SocketAddr;
use tower::ServiceBuilder;
use tower_http::{cors::CorsLayer, trace::TraceLayer};
use tracing::info;

use crate::config::Config;
use crate::errors::SignerError;
use crate::handlers::{get_metrics, get_public_key, health_check, sign_transaction};
use crate::middleware::security_headers_middleware;
use crate::utils::TlsManager;

pub mod state;
pub use state::AppState;

#[cfg(test)]
mod tests;

/// HTTP Server for the remote signer
pub struct Server {
    config: Config,
    app_state: AppState,
}

impl Server {
    pub async fn new(config: Config) -> Result<Self, SignerError> {
        let app_state = AppState::new(config.clone()).await?;
        Ok(Self { config, app_state })
    }

    pub async fn serve(self) -> Result<(), SignerError> {
        let app = self.create_router();

        let addr = SocketAddr::new(
            self.config
                .server
                .address
                .parse()
                .map_err(|e| SignerError::Config(format!("Invalid bind address: {e}")))?,
            self.config.server.port,
        );

        info!("🚀 Starknet Remote Signer starting on {}", addr);

        // Create TLS manager
        let tls_manager = TlsManager::new(self.config.tls.clone());

        // Log TLS configuration
        info!("TLS Configuration: {}", tls_manager.get_config_summary());

        if tls_manager.is_enabled() {
            // Start TLS server
            tls_manager.serve_tls(app, addr).await?;
        } else {
            // Start HTTP server
            TlsManager::serve_http(app, addr).await?;
        }

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
                    .layer(CorsLayer::permissive())
                    .layer(axum::middleware::from_fn(security_headers_middleware)),
            )
    }
}
