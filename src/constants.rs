use starknet::macros::felt;
use starknet_crypto::Felt;

/// Chain ID constants
pub const MAINNET_CHAIN_ID: Felt = felt!("0x534e5f4d41494e"); // SN_MAIN
pub const SEPOLIA_CHAIN_ID: Felt = felt!("0x534e5f5345504f4c4941"); // SN_SEPOLIA

/// Mainnet contract addresses
pub mod mainnet {
    use super::*;

    /// Staking contract address on Mainnet
    pub const STAKING_CONTRACT: Felt =
        felt!("0x00ca1702e64c81d9a07b86bd2c540188d92a2c73cf5cc0e508d949015e7e84a7");

    /// Attestation contract addresses on Mainnet
    pub const ATTESTATION_CONTRACT: Felt =
        felt!("0x010398fe631af9ab2311840432d507bf7ef4b959ae967f1507928f5afe888a99");
}

/// Sepolia contract addresses
pub mod sepolia {
    use super::*;

    /// Staking contract address on Sepolia
    pub const STAKING_CONTRACT: Felt =
        felt!("0x03745ab04a431fc02871a139be6b93d9260b0ff3e779ad9c8b377183b23109f1");

    /// Attestation contract addresses on Sepolia
    /// Both tools use slightly different addresses
    pub const STARKNET_ATTESTATION_CONTRACT: Felt =
        felt!("0x3f32e152b9637c31bfcf73e434f78591067a01ba070505ff6ee195642c9acfb");
    pub const STARKNET_STAKING_LZ_CONTRACT: Felt =
        felt!("0x03f32e152b9637c31bfcf73e434f78591067a01ba070505ff6ee195642c9acfb");
    // leading zero is intentional
}

/// Function selector constants
pub mod selectors {
    use super::*;

    /// The "attest" function selector
    /// This is computed from get_selector_from_name("attest")
    pub const ATTEST_SELECTOR: Felt =
        felt!("0x2db340e6c609371026731f47050d3976552c89b4fbb012941663841c59d1af3");
}

/// Validation constants
pub mod validation {
    use super::*;

    /// Expected calldata length for attestation transactions
    pub const ATTESTATION_CALLDATA_LENGTH: usize = 5;

    /// Expected call array length (must be exactly 1)
    pub const EXPECTED_CALL_ARRAY_LENGTH: Felt = felt!("0x1");

    /// Expected attestation calldata length (must be exactly 1)
    pub const EXPECTED_ATTESTATION_CALLDATA_LENGTH: Felt = felt!("0x1");
}
