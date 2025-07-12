use axum::{
    extract::{ConnectInfo, State},
    http::{HeaderMap, StatusCode},
    response::Json,
};
use std::net::SocketAddr;
use std::sync::atomic::Ordering;
use tracing::{info, warn};

use super::types::MetricsResponse;
use crate::server::state::AppState;
use crate::utils::{extract_real_ip, validate_ip_access};

/// Get metrics endpoint
pub async fn get_metrics(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> Result<Json<MetricsResponse>, StatusCode> {
    // IP security check
    let real_ip = match validate_ip_access(&state.security, &headers, &addr) {
        Ok(ip) => ip,
        Err(_) => {
            warn!(
                "Rejected metrics request from unauthorized IP: {}",
                extract_real_ip(&headers, &addr)
            );
            return Err(StatusCode::FORBIDDEN);
        }
    };

    info!("Metrics requested from {}", real_ip);
    Ok(Json(MetricsResponse {
        sign_requests: state.metrics.sign_requests.load(Ordering::Relaxed),
        sign_errors: state.metrics.sign_errors.load(Ordering::Relaxed),
        health_checks: state.metrics.health_checks.load(Ordering::Relaxed),
    }))
}
