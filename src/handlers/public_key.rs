use axum::{
    extract::{ConnectInfo, State},
    http::{HeaderMap, StatusCode},
    response::Json,
};
use std::net::SocketAddr;
use tracing::{info, warn};

use super::types::PublicKeyResponse;
use crate::server::state::AppState;
use crate::utils::{extract_real_ip, validate_ip_access};

/// Get public key endpoint
pub async fn get_public_key(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> Result<Json<PublicKeyResponse>, StatusCode> {
    // IP security check
    let real_ip = match validate_ip_access(&state.security, &headers, &addr) {
        Ok(ip) => ip,
        Err(_) => {
            warn!(
                "Rejected public key request from unauthorized IP: {}",
                extract_real_ip(&headers, &addr)
            );
            return Err(StatusCode::FORBIDDEN);
        }
    };

    info!("Public key requested from {}", real_ip);
    let public_key = state
        .signer
        .public_key()
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(Json(PublicKeyResponse { public_key }))
}
