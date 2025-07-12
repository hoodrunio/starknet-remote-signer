use starknet::core::types::BroadcastedInvokeTransactionV3;
use starknet::core::utils::get_selector_from_name;
use starknet_crypto::Felt;
use tracing::debug;

use super::attestation_info::AttestationInfo;
use super::chain_contracts::ChainContracts;
use crate::constants::{validation::*, MAINNET_CHAIN_ID, SEPOLIA_CHAIN_ID};
use crate::errors::SignerError;

/// Validator for attestation-specific transactions
/// This ensures that only valid attestation transactions are signed
#[derive(Debug, Clone)]
pub struct AttestationValidator {
    /// Chain-specific contract addresses
    chain_contracts: Option<ChainContracts>,
    /// Whether to enforce strict validation (recommended for production)
    strict_mode: bool,
}

impl AttestationValidator {
    /// Create a new attestation validator with chain-specific contracts
    pub fn new(chain_contracts: Option<ChainContracts>, strict_mode: bool) -> Self {
        Self {
            chain_contracts,
            strict_mode,
        }
    }

    /// Create validator with chain detection
    pub fn with_chain_detection(chain_id: Felt) -> Self {
        let contracts = ChainContracts::for_chain(chain_id);
        Self::new(contracts, true)
    }

    /// Validate complete attestation request including chain_id
    pub fn validate_attestation_request(
        &self,
        transaction: &BroadcastedInvokeTransactionV3,
        chain_id: Felt,
    ) -> Result<AttestationInfo, SignerError> {
        debug!("Validating complete attestation request");

        // 1. Validate chain ID first
        self.validate_chain_id(chain_id)?;

        // 2. Validate basic transaction structure
        self.validate_transaction_structure(transaction)?;

        // 3. Validate attestation pattern
        self.validate_attestation_transaction(transaction)
    }

    /// Validate chain ID
    fn validate_chain_id(&self, chain_id: Felt) -> Result<(), SignerError> {
        if chain_id != MAINNET_CHAIN_ID && chain_id != SEPOLIA_CHAIN_ID {
            return Err(SignerError::ValidationFailed(format!(
                "Invalid chain ID: 0x{chain_id:x}. Only Mainnet (SN_MAIN) and Sepolia (SN_SEPOLIA) are supported"
            )));
        }

        // Ensure we have contracts configured for this chain
        if self.chain_contracts.is_none() {
            return Err(SignerError::ValidationFailed(
                "No contracts configured for this chain".to_string(),
            ));
        }

        debug!("✅ Valid chain ID: 0x{:x}", chain_id);
        Ok(())
    }

    /// Validate basic transaction structure
    fn validate_transaction_structure(
        &self,
        transaction: &BroadcastedInvokeTransactionV3,
    ) -> Result<(), SignerError> {
        // Validate sender address
        if transaction.sender_address == Felt::ZERO {
            return Err(SignerError::ValidationFailed(
                "Sender address cannot be zero".to_string(),
            ));
        }

        // Strict mode validations
        if self.strict_mode {
            if !transaction.paymaster_data.is_empty() {
                return Err(SignerError::ValidationFailed(
                    "Attestation transactions should not have paymaster data".to_string(),
                ));
            }

            if !transaction.account_deployment_data.is_empty() {
                return Err(SignerError::ValidationFailed(
                    "Attestation transactions should not have account deployment data".to_string(),
                ));
            }

            // Tip should be zero for attestation transactions
            if transaction.tip != 0 {
                return Err(SignerError::ValidationFailed(
                    "Attestation transactions should not have tips".to_string(),
                ));
            }
        }

        Ok(())
    }

    /// Validate if a transaction is a valid attestation transaction
    pub fn validate_attestation_transaction(
        &self,
        transaction: &BroadcastedInvokeTransactionV3,
    ) -> Result<AttestationInfo, SignerError> {
        debug!("Validating attestation transaction pattern");

        // Get the "attest" function selector
        let attest_selector = get_selector_from_name("attest")
            .map_err(|e| SignerError::ValidationFailed(format!("Selector lookup failed: {}", e)))?;

        // Extract calldata pattern
        let calldata = &transaction.calldata;

        // Attestation transactions have exactly 5 calldata elements:
        // [0]: call array length (should be 1)
        // [1]: attestation contract address
        // [2]: function selector (attest function)
        // [3]: calldata length (should be 1)
        // [4]: block hash being attested
        if calldata.len() != ATTESTATION_CALLDATA_LENGTH {
            return Err(SignerError::ValidationFailed(format!(
                "Invalid calldata length for attestation transaction: expected {}, got {}",
                ATTESTATION_CALLDATA_LENGTH,
                calldata.len()
            )));
        }

        let call_array_length = calldata[0];
        let contract_address = calldata[1];
        let function_selector = calldata[2];
        let calldata_length = calldata[3];
        let block_hash = calldata[4];

        // Validate call array length (must be exactly 1)
        if call_array_length != EXPECTED_CALL_ARRAY_LENGTH {
            return Err(SignerError::ValidationFailed(format!(
                "Invalid call array length: expected {EXPECTED_CALL_ARRAY_LENGTH:#x}, got {call_array_length:#x}"
            )));
        }

        // Validate calldata length (must be exactly 1)
        if calldata_length != EXPECTED_ATTESTATION_CALLDATA_LENGTH {
            return Err(SignerError::ValidationFailed(format!(
                "Invalid calldata length: expected {EXPECTED_ATTESTATION_CALLDATA_LENGTH:#x}, got {calldata_length:#x}"
            )));
        }

        // Validate function selector (must be "attest")
        if function_selector != attest_selector {
            return Err(SignerError::ValidationFailed(format!(
                "Invalid function selector: expected attest ({attest_selector:#x}), got {function_selector:#x}"
            )));
        }

        // Validate contract address against ALL valid attestation contracts for this chain
        if let Some(contracts) = &self.chain_contracts {
            if !contracts.is_valid_attestation_contract(contract_address) {
                let valid_contracts = contracts.attestation_contract_addresses();

                return Err(SignerError::ValidationFailed(format!(
                    "Invalid attestation contract address: {:#x}. Valid contracts for this chain: [{}]",
                    contract_address,
                    valid_contracts.join(", ")
                )));
            }
        } else {
            return Err(SignerError::ValidationFailed(
                "No chain contracts configured for validation".to_string(),
            ));
        }

        // Additional strict mode validations
        if self.strict_mode {
            // Ensure block hash is not zero
            if block_hash == Felt::ZERO {
                return Err(SignerError::ValidationFailed(
                    "Block hash cannot be zero in attestation".to_string(),
                ));
            }

            // Ensure contract address is not zero
            if contract_address == Felt::ZERO {
                return Err(SignerError::ValidationFailed(
                    "Attestation contract address cannot be zero".to_string(),
                ));
            }
        }

        debug!(
            "✅ Valid attestation transaction: contract={:#x}, selector={:#x}, block_hash={:#x}",
            contract_address, function_selector, block_hash
        );

        Ok(AttestationInfo::new(
            contract_address,
            function_selector,
            block_hash,
            call_array_length,
            calldata_length,
        ))
    }
}
