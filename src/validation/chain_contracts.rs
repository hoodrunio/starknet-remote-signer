use starknet_crypto::Felt;
use tracing::warn;

use crate::constants::{mainnet, sepolia, MAINNET_CHAIN_ID, SEPOLIA_CHAIN_ID};

/// Chain-specific contract addresses for attestation validation
#[derive(Debug, Clone)]
pub struct ChainContracts {
    pub staking_contract: Felt,
    pub attestation_contracts: Vec<Felt>, // Support multiple contracts per chain
}

impl ChainContracts {
    /// Get contract addresses for specific chain
    pub fn for_chain(chain_id: Felt) -> Option<Self> {
        if chain_id == MAINNET_CHAIN_ID {
            Some(Self {
                staking_contract: mainnet::STAKING_CONTRACT,
                attestation_contracts: vec![mainnet::ATTESTATION_CONTRACT],
            })
        } else if chain_id == SEPOLIA_CHAIN_ID {
            Some(Self {
                staking_contract: sepolia::STAKING_CONTRACT,
                attestation_contracts: vec![
                    sepolia::STARKNET_ATTESTATION_CONTRACT,
                    sepolia::STARKNET_STAKING_LZ_CONTRACT,
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

    /// Check if a contract address is a valid attestation contract for this chain
    pub fn is_valid_attestation_contract(&self, contract_address: Felt) -> bool {
        self.attestation_contracts.contains(&contract_address)
    }

    /// Get all valid attestation contract addresses as formatted strings
    pub fn attestation_contract_addresses(&self) -> Vec<String> {
        self.attestation_contracts
            .iter()
            .map(|addr| format!("{addr:#x}"))
            .collect()
    }
}
