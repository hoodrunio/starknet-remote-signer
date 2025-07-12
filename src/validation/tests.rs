#[cfg(test)]
mod tests {
    use super::super::validator::AttestationValidator;
    use starknet::core::types::{DataAvailabilityMode, ResourceBounds, ResourceBoundsMapping};
    use starknet::core::utils::get_selector_from_name;
    use starknet::macros::felt;

    #[test]
    fn test_valid_sepolia_attestation_starknet_attestation() {
        let validator = AttestationValidator::with_chain_detection(felt!("0x534e5f5345504f4c4941"));

        let tx = starknet::core::types::BroadcastedInvokeTransactionV3 {
            sender_address: felt!("0x123"),
            calldata: vec![
                felt!("0x1"), // call array length
                felt!("0x3f32e152b9637c31bfcf73e434f78591067a01ba070505ff6ee195642c9acfb"), // starknet-attestation contract
                get_selector_from_name("attest").expect("attest selector should be valid"), // attest selector
                felt!("0x1"), // calldata length
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
    fn test_valid_sepolia_attestation_starknet_staking_lz() {
        let validator = AttestationValidator::with_chain_detection(felt!("0x534e5f5345504f4c4941"));

        let tx = starknet::core::types::BroadcastedInvokeTransactionV3 {
            sender_address: felt!("0x123"),
            calldata: vec![
                felt!("0x1"), // call array length
                felt!("0x03f32e152b9637c31bfcf73e434f78591067a01ba070505ff6ee195642c9acfb"), // starknet attestation contract
                get_selector_from_name("attest").expect("attest selector should be valid"), // attest selector
                felt!("0x1"), // calldata length
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

        let tx = starknet::core::types::BroadcastedInvokeTransactionV3 {
            sender_address: felt!("0x123"),
            calldata: vec![
                felt!("0x1"),
                felt!("0x3f32e152b9637c31bfcf73e434f78591067a01ba070505ff6ee195642c9acfb"),
                get_selector_from_name("attest").expect("attest selector should be valid"),
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

        let tx = starknet::core::types::BroadcastedInvokeTransactionV3 {
            sender_address: felt!("0x123"),
            calldata: vec![
                felt!("0x1"),
                felt!("0x999"), // Invalid contract address
                get_selector_from_name("attest").expect("attest selector should be valid"),
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

        let tx = starknet::core::types::BroadcastedInvokeTransactionV3 {
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
