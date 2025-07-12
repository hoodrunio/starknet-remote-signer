use serde::{Deserialize, Serialize};
use starknet::core::types::BroadcastedInvokeTransactionV3;
use starknet_crypto::Felt;

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
