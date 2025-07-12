use starknet::core::types::BroadcastedInvokeTransactionV3;
use starknet_crypto::Felt;
use std::time::Instant;
use tracing::info;

use crate::audit::AttestationAuditEntry;
use crate::server::state::AppState;
use crate::signer::compute_transaction_hash;
use crate::validation::AttestationValidator;

/// Check if a transaction is in preparation/estimation phase vs actual invoke phase
/// This handles both Go tool (resource bounds check) and Rust tool (is_query check)
pub fn is_transaction_in_preparation_phase(transaction: &BroadcastedInvokeTransactionV3) -> bool {
    // Check 1: eqlabs attestation uses is_query field for fee estimation
    if transaction.is_query {
        return true;
    }

    // Check 2: Nethermind attestation uses default resource bounds (all zeros) for preparation
    transaction.resource_bounds.l1_gas.max_amount == 0
        && transaction.resource_bounds.l1_gas.max_price_per_unit == 0
        && transaction.resource_bounds.l1_data_gas.max_amount == 0
        && transaction.resource_bounds.l1_data_gas.max_price_per_unit == 0
        && transaction.resource_bounds.l2_gas.max_amount == 0
        && transaction.resource_bounds.l2_gas.max_price_per_unit == 0
}

pub struct SigningService;

impl SigningService {
    pub async fn sign_transaction(
        state: &AppState,
        transaction: &BroadcastedInvokeTransactionV3,
        chain_id: Felt,
        real_ip: &str,
    ) -> Result<Vec<Felt>, crate::errors::SignerError> {
        let start_time = Instant::now();

        // Create audit entry
        let mut audit_entry = if state.audit_logger.is_some() {
            Some(AttestationAuditEntry::from_request(
                &crate::handlers::types::SignRequest {
                    transaction: transaction.clone(),
                    chain_id,
                },
                real_ip,
                start_time,
            ))
        } else {
            None
        };

        // Validate chain ID
        if let Err(e) = state.security.validate_chain_id(chain_id) {
            if let Some(audit) = &mut audit_entry {
                audit.set_error(e.to_string());
                audit.update_duration(start_time);
                if let Some(logger) = &state.audit_logger {
                    let _ = logger.log(audit).await;
                }
            }
            return Err(crate::errors::SignerError::Security(format!(
                "Unauthorized chain ID: 0x{chain_id:x}"
            )));
        }

        // Create chain-specific validator for this request
        let chain_specific_validator = AttestationValidator::with_chain_detection(chain_id);

        // Validate that this is a valid attestation transaction
        let attestation_info =
            match chain_specific_validator.validate_attestation_request(transaction, chain_id) {
                Ok(info) => info,
                Err(e) => {
                    if let Some(audit) = &mut audit_entry {
                        audit.set_error(format!("Invalid attestation transaction: {e}"));
                        audit.update_duration(start_time);
                        if let Some(logger) = &state.audit_logger {
                            let _ = logger.log(audit).await;
                        }
                    }
                    return Err(crate::errors::SignerError::Validation(format!(
                        "Invalid attestation transaction: {e}"
                    )));
                }
            };

        // Determine if this is a prepare phase or invoke phase
        let is_prepare_phase = is_transaction_in_preparation_phase(transaction);

        if is_prepare_phase {
            info!(
                "Signing attestation request from {} for sender: 0x{:x}, chain_id: 0x{:x} [PREPARATION PHASE] - {}",
                real_ip, transaction.sender_address, chain_id, attestation_info.summary()
            );
        } else {
            info!(
                "Signing attestation request from {} for sender: 0x{:x}, chain_id: 0x{:x} [EXECUTION PHASE] - {}",
                real_ip, transaction.sender_address, chain_id, attestation_info.summary()
            );
        }

        // Compute transaction hash for audit
        let tx_hash = match compute_transaction_hash(transaction, chain_id) {
            Ok(hash) => {
                if let Some(audit) = &mut audit_entry {
                    audit.set_transaction_hash(hash);
                }
                hash
            }
            Err(e) => {
                if let Some(audit) = &mut audit_entry {
                    audit.set_error(format!("Failed to compute tx hash: {e}"));
                    audit.update_duration(start_time);
                    if let Some(logger) = &state.audit_logger {
                        let _ = logger.log(audit).await;
                    }
                }
                return Err(crate::errors::SignerError::Signing(format!(
                    "Failed to compute transaction hash: {e}"
                )));
            }
        };

        // Sign transaction
        match state.signer.sign_transaction(transaction, chain_id).await {
            Ok(signature) => {
                if let Some(audit) = &mut audit_entry {
                    audit.set_signature(&signature);
                    audit.set_success(true);
                    audit.update_duration(start_time);
                    if let Some(logger) = &state.audit_logger {
                        let _ = logger.log(audit).await;
                    }
                }

                if is_prepare_phase {
                    info!(
                        "Attestation transaction prepared successfully (tx_hash: 0x{:x}) - Preparation phase complete - {}",
                        tx_hash, attestation_info.summary()
                    );
                } else {
                    info!(
                        "Attestation transaction signed successfully (tx_hash: 0x{:x}) - Ready for broadcast - {}",
                        tx_hash, attestation_info.summary()
                    );
                }

                Ok(signature)
            }
            Err(e) => {
                if let Some(audit) = &mut audit_entry {
                    audit.set_error(format!("Signing failed: {e}"));
                    audit.update_duration(start_time);
                    if let Some(logger) = &state.audit_logger {
                        let _ = logger.log(audit).await;
                    }
                }
                Err(e)
            }
        }
    }
}
