use axum::{
    extract::{ConnectInfo, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Json, Response},
};
use std::net::SocketAddr;
use std::sync::atomic::Ordering;
use tracing::{error, warn};

use super::types::{ErrorResponse, SignRequest, SignResponse};
use crate::server::state::AppState;
use crate::services::SigningService;
use crate::utils::{extract_real_ip, validate_ip_access};

/// Sign transaction endpoint
pub async fn sign_transaction(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(request): Json<SignRequest>,
) -> Response {
    state.metrics.sign_requests.fetch_add(1, Ordering::Relaxed);

    // Get real client IP
    let real_ip = extract_real_ip(&headers, &addr);

    // Security checks
    // Check IP allowlist
    if validate_ip_access(&state.security, &headers, &addr).is_err() {
        warn!("Rejected request from unauthorized IP: {}", real_ip);
        let error_response = ErrorResponse {
            error: "Access denied".to_string(),
            code: "FORBIDDEN".to_string(),
        };
        return (StatusCode::FORBIDDEN, Json(error_response)).into_response();
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
        Ok(signature) => (StatusCode::OK, Json(SignResponse { signature })).into_response(),
        Err(e) => {
            state.metrics.sign_errors.fetch_add(1, Ordering::Relaxed);

            // Log the detailed error for operators
            error!("Signing error: {}", e.operator_message());

            // Map errors to appropriate HTTP status codes and sanitized messages
            let (status, error_code) = match e {
                crate::errors::SignerError::Security(_)
                | crate::errors::SignerError::Unauthorized(_) => {
                    (StatusCode::FORBIDDEN, "FORBIDDEN")
                }
                crate::errors::SignerError::Validation(_)
                | crate::errors::SignerError::ValidationFailed(_) => {
                    (StatusCode::BAD_REQUEST, "BAD_REQUEST")
                }
                _ => (StatusCode::INTERNAL_SERVER_ERROR, "INTERNAL_ERROR"),
            };

            let error_response = ErrorResponse {
                error: e.client_message(),
                code: error_code.to_string(),
            };

            (status, Json(error_response)).into_response()
        }
    }
}
