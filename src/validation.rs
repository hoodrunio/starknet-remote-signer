use starknet::core::types::BroadcastedInvokeTransactionV3;
use starknet::core::utils::get_selector_from_name;
use starknet_crypto::Felt;
use tracing::{debug, warn};

use crate::constants::{mainnet, sepolia, validation::*, MAINNET_CHAIN_ID, SEPOLIA_CHAIN_ID};
use crate::errors::SignerError;

/// Chain-specific contract addresses for attestation validation
#[derive(Debug, Clone)]
pub struct ChainContracts {
    pub staking_contract: Felt,
    pub attestation_contracts: Vec<Felt>, // Support multiple contracts per chain
}

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
        let contracts = Self::get_chain_contracts(chain_id);
        Self::new(contracts, true)
    }

    /// Get contract addresses for specific chain
    pub fn get_chain_contracts(chain_id: Felt) -> Option<ChainContracts> {
        if chain_id == MAINNET_CHAIN_ID {
            Some(ChainContracts {
                staking_contract: mainnet::STAKING_CONTRACT,
                attestation_contracts: vec![mainnet::ATTESTATION_CONTRACT],
            })
        } else if chain_id == SEPOLIA_CHAIN_ID {
            Some(ChainContracts {
                staking_contract: sepolia::STAKING_CONTRACT,
                attestation_contracts: vec![
                    sepolia::STARKNET_ATTESTATION_CONTRACT,
                    sepolia::STARKNET_STAKING_V2_CONTRACT,
                ],
            })
        } else {
            warn!(
                "Unknown chain ID: 0x{:x}, attestation validation disabled",
                chain_id
            );
            None
        }
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
        let attest_selector = get_selector_from_name("attest").unwrap();

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
            if !contracts.attestation_contracts.contains(&contract_address) {
                let valid_contracts: Vec<String> = contracts
                    .attestation_contracts
                    .iter()
                    .map(|addr| format!("{addr:#x}"))
                    .collect();

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

        Ok(AttestationInfo {
            contract_address,
            function_selector,
            block_hash,
            call_array_length,
            calldata_length,
        })
    }
}

/// Information extracted from a valid attestation transaction
#[derive(Debug, Clone)]
pub struct AttestationInfo {
    pub contract_address: Felt,
    pub function_selector: Felt,
    pub block_hash: Felt,
    pub call_array_length: Felt,
    pub calldata_length: Felt,
}

impl AttestationInfo {
    /// Get a summary string for logging
    pub fn summary(&self) -> String {
        format!(
            "contract={:#x}, selector={:#x}, block={:#x}",
            self.contract_address, self.function_selector, self.block_hash
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use starknet::core::types::{DataAvailabilityMode, ResourceBounds, ResourceBoundsMapping};
    use starknet::macros::felt;

    #[test]
    fn test_valid_sepolia_attestation_starknet_attestation() {
        let validator = AttestationValidator::with_chain_detection(felt!("0x534e5f5345504f4c4941"));

        let tx = BroadcastedInvokeTransactionV3 {
            sender_address: felt!("0x123"),
            calldata: vec![
                felt!("0x1"), // call array length
                felt!("0x3f32e152b9637c31bfcf73e434f78591067a01ba070505ff6ee195642c9acfb"), // starknet-attestation contract
                get_selector_from_name("attest").unwrap(), // attest selector
                felt!("0x1"),                              // calldata length
                felt!("0x614f596b9d8eafbc87a48ff3a2a4bd503762d3f4be7c91cdeb766cf869c2233"), // block hash
            ],
            signature: vec![],
            nonce: felt!("0x1"),
            resource_bounds: ResourceBoundsMapping {
                l1_gas: ResourceBounds {
                    max_amount: 0,
                    max_price_per_unit: 0,
                },
                l1_data_gas: ResourceBounds {
                    max_amount: 0,
                    max_price_per_unit: 0,
                },
                l2_gas: ResourceBounds {
                    max_amount: 0,
                    max_price_per_unit: 0,
                },
            },
            tip: 0,
            paymaster_data: vec![],
            account_deployment_data: vec![],
            nonce_data_availability_mode: DataAvailabilityMode::L1,
            fee_data_availability_mode: DataAvailabilityMode::L1,
            is_query: false,
        };

        let result = validator.validate_attestation_request(&tx, felt!("0x534e5f5345504f4c4941"));
        assert!(result.is_ok());
    }

    #[test]
    fn test_valid_sepolia_attestation_starknet_staking_v2() {
        let validator = AttestationValidator::with_chain_detection(felt!("0x534e5f5345504f4c4941"));

        let tx = BroadcastedInvokeTransactionV3 {
            sender_address: felt!("0x123"),
            calldata: vec![
                felt!("0x1"), // call array length
                felt!("0x03f32e152b9637c31bfcf73e434f78591067a01ba070505ff6ee195642c9acfb"), // starknet-staking-v2 contract
                get_selector_from_name("attest").unwrap(), // attest selector
                felt!("0x1"),                              // calldata length
                felt!("0x614f596b9d8eafbc87a48ff3a2a4bd503762d3f4be7c91cdeb766cf869c2233"), // block hash
            ],
            signature: vec![],
            nonce: felt!("0x1"),
            resource_bounds: ResourceBoundsMapping {
                l1_gas: ResourceBounds {
                    max_amount: 0,
                    max_price_per_unit: 0,
                },
                l1_data_gas: ResourceBounds {
                    max_amount: 0,
                    max_price_per_unit: 0,
                },
                l2_gas: ResourceBounds {
                    max_amount: 0,
                    max_price_per_unit: 0,
                },
            },
            tip: 0,
            paymaster_data: vec![],
            account_deployment_data: vec![],
            nonce_data_availability_mode: DataAvailabilityMode::L1,
            fee_data_availability_mode: DataAvailabilityMode::L1,
            is_query: false,
        };

        let result = validator.validate_attestation_request(&tx, felt!("0x534e5f5345504f4c4941"));
        assert!(result.is_ok());
    }

    #[test]
    fn test_invalid_chain_id() {
        let validator = AttestationValidator::with_chain_detection(felt!("0x534e5f5345504f4c4941"));

        let tx = BroadcastedInvokeTransactionV3 {
            sender_address: felt!("0x123"),
            calldata: vec![
                felt!("0x1"),
                felt!("0x3f32e152b9637c31bfcf73e434f78591067a01ba070505ff6ee195642c9acfb"),
                get_selector_from_name("attest").unwrap(),
                felt!("0x1"),
                felt!("0x614f596b9d8eafbc87a48ff3a2a4bd503762d3f4be7c91cdeb766cf869c2233"),
            ],
            signature: vec![],
            nonce: felt!("0x1"),
            resource_bounds: ResourceBoundsMapping {
                l1_gas: ResourceBounds {
                    max_amount: 0,
                    max_price_per_unit: 0,
                },
                l1_data_gas: ResourceBounds {
                    max_amount: 0,
                    max_price_per_unit: 0,
                },
                l2_gas: ResourceBounds {
                    max_amount: 0,
                    max_price_per_unit: 0,
                },
            },
            tip: 0,
            paymaster_data: vec![],
            account_deployment_data: vec![],
            nonce_data_availability_mode: DataAvailabilityMode::L1,
            fee_data_availability_mode: DataAvailabilityMode::L1,
            is_query: false,
        };

        // Invalid chain ID
        let result = validator.validate_attestation_request(&tx, felt!("0x123456"));
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Invalid chain ID"));
    }

    #[test]
    fn test_invalid_contract_address() {
        let validator = AttestationValidator::with_chain_detection(felt!("0x534e5f5345504f4c4941"));

        let tx = BroadcastedInvokeTransactionV3 {
            sender_address: felt!("0x123"),
            calldata: vec![
                felt!("0x1"),
                felt!("0x999"), // Invalid contract address
                get_selector_from_name("attest").unwrap(),
                felt!("0x1"),
                felt!("0x614f596b9d8eafbc87a48ff3a2a4bd503762d3f4be7c91cdeb766cf869c2233"),
            ],
            signature: vec![],
            nonce: felt!("0x1"),
            resource_bounds: ResourceBoundsMapping {
                l1_gas: ResourceBounds {
                    max_amount: 0,
                    max_price_per_unit: 0,
                },
                l1_data_gas: ResourceBounds {
                    max_amount: 0,
                    max_price_per_unit: 0,
                },
                l2_gas: ResourceBounds {
                    max_amount: 0,
                    max_price_per_unit: 0,
                },
            },
            tip: 0,
            paymaster_data: vec![],
            account_deployment_data: vec![],
            nonce_data_availability_mode: DataAvailabilityMode::L1,
            fee_data_availability_mode: DataAvailabilityMode::L1,
            is_query: false,
        };

        let result = validator.validate_attestation_request(&tx, felt!("0x534e5f5345504f4c4941"));
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Invalid attestation contract address"));
    }

    #[test]
    fn test_invalid_calldata_length() {
        let validator = AttestationValidator::with_chain_detection(felt!("0x534e5f5345504f4c4941"));

        let tx = BroadcastedInvokeTransactionV3 {
            sender_address: felt!("0x123"),
            calldata: vec![felt!("0x1"), felt!("0x2")], // Too short
            signature: vec![],
            nonce: felt!("0x1"),
            resource_bounds: ResourceBoundsMapping {
                l1_gas: ResourceBounds {
                    max_amount: 0,
                    max_price_per_unit: 0,
                },
                l1_data_gas: ResourceBounds {
                    max_amount: 0,
                    max_price_per_unit: 0,
                },
                l2_gas: ResourceBounds {
                    max_amount: 0,
                    max_price_per_unit: 0,
                },
            },
            tip: 0,
            paymaster_data: vec![],
            account_deployment_data: vec![],
            nonce_data_availability_mode: DataAvailabilityMode::L1,
            fee_data_availability_mode: DataAvailabilityMode::L1,
            is_query: false,
        };

        let result = validator.validate_attestation_request(&tx, felt!("0x534e5f5345504f4c4941"));
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Invalid calldata length"));
    }
}
