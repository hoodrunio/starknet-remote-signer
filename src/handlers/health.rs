use axum::{
    extract::{ConnectInfo, State},
    http::{HeaderMap, StatusCode},
    response::Json,
};
use std::net::SocketAddr;
use std::sync::atomic::Ordering;
use tracing::{info, warn};

use super::types::HealthResponse;
use crate::server::state::AppState;
use crate::utils::{extract_real_ip, validate_ip_access};

/// Health check endpoint
pub async fn health_check(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> Result<Json<HealthResponse>, StatusCode> {
    // IP security check
    let real_ip = match validate_ip_access(&state.security, &headers, &addr) {
        Ok(ip) => ip,
        Err(_) => {
            warn!(
                "Rejected health check from unauthorized IP: {}",
                extract_real_ip(&headers, &addr)
            );
            return Err(StatusCode::FORBIDDEN);
        }
    };

    state.metrics.health_checks.fetch_add(1, Ordering::Relaxed);
    info!("Health check from {}", real_ip);

    let public_key = state
        .signer
        .public_key()
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(Json(HealthResponse {
        status: "healthy".to_string(),
        version: env!("CARGO_PKG_VERSION").to_string(),
        public_key,
    }))
}
