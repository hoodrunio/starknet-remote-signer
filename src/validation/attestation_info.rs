use starknet_crypto::Felt;

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
    /// Create new attestation info
    pub fn new(
        contract_address: Felt,
        function_selector: Felt,
        block_hash: Felt,
        call_array_length: Felt,
        calldata_length: Felt,
    ) -> Self {
        Self {
            contract_address,
            function_selector,
            block_hash,
            call_array_length,
            calldata_length,
        }
    }

    /// Get a summary string for logging
    pub fn summary(&self) -> String {
        format!(
            "contract={:#x}, selector={:#x}, block={:#x}",
            self.contract_address, self.function_selector, self.block_hash
        )
    }
}
