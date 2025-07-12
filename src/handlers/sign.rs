use axum::{
    extract::{ConnectInfo, State},
    http::{HeaderMap, StatusCode},
    response::Json,
};
use std::net::SocketAddr;
use std::sync::atomic::Ordering;
use tracing::warn;

use super::types::{SignRequest, SignResponse};
use crate::server::state::AppState;
use crate::services::SigningService;
use crate::utils::{extract_real_ip, validate_ip_access};

/// Sign transaction endpoint
pub async fn sign_transaction(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(request): Json<SignRequest>,
) -> Result<Json<SignResponse>, StatusCode> {
    state.metrics.sign_requests.fetch_add(1, Ordering::Relaxed);

    // Get real client IP
    let real_ip = extract_real_ip(&headers, &addr);

    // Security checks
    // Check IP allowlist
    if validate_ip_access(&state.security, &headers, &addr).is_err() {
        warn!("Rejected request from unauthorized IP: {}", real_ip);
        return Err(StatusCode::FORBIDDEN);
    }

    // Use the signing service to handle the business logic
    match SigningService::sign_transaction(
        &state,
        &request.transaction,
        request.chain_id,
        &real_ip.to_string(),
    )
    .await
    {
        Ok(signature) => Ok(Json(SignResponse { signature })),
        Err(e) => {
            state.metrics.sign_errors.fetch_add(1, Ordering::Relaxed);

            // Map errors to appropriate HTTP status codes
            match e {
                crate::errors::SignerError::Security(_) => Err(StatusCode::FORBIDDEN),
                crate::errors::SignerError::Validation(_) => Err(StatusCode::BAD_REQUEST),
                _ => Err(StatusCode::INTERNAL_SERVER_ERROR),
            }
        }
    }
}
