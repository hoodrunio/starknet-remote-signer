use starknet::core::types::BroadcastedInvokeTransactionV3;
use starknet_crypto::{poseidon_hash_many, Felt, PoseidonHasher};

use crate::errors::SignerError;

/// Cairo string for "invoke"
const PREFIX_INVOKE: Felt = Felt::from_raw([
    513398556346534256,
    18446744073709551615,
    18446744073709551615,
    18443034532770911073,
]);

/// 2 ^ 128 + 3
const QUERY_VERSION_THREE: Felt = Felt::from_raw([
    576460752142432688,
    18446744073709551584,
    17407,
    18446744073700081569,
]);

/// Compute the transaction hash for an invoke transaction v3
/// This is a copy of the transaction hash computation from starknet-rs
pub fn compute_transaction_hash(
    tx: &BroadcastedInvokeTransactionV3,
    chain_id: Felt,
) -> Result<Felt, SignerError> {
    let mut hasher = PoseidonHasher::new();

    hasher.update(PREFIX_INVOKE);
    hasher.update(if tx.is_query {
        QUERY_VERSION_THREE
    } else {
        Felt::THREE
    });
    hasher.update(tx.sender_address);

    // Compute fee hash
    hasher.update({
        let mut fee_hasher = PoseidonHasher::new();

        fee_hasher.update(tx.tip.into());

        // L1 Gas resource bounds
        let mut resource_buffer = [
            0, 0, b'L', b'1', b'_', b'G', b'A', b'S', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0,
        ];
        resource_buffer[8..(8 + 8)]
            .copy_from_slice(&tx.resource_bounds.l1_gas.max_amount.to_be_bytes());
        resource_buffer[(8 + 8)..]
            .copy_from_slice(&tx.resource_bounds.l1_gas.max_price_per_unit.to_be_bytes());
        fee_hasher.update(Felt::from_bytes_be(&resource_buffer));

        // L2 Gas resource bounds
        let mut resource_buffer = [
            0, 0, b'L', b'2', b'_', b'G', b'A', b'S', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0,
        ];
        resource_buffer[8..(8 + 8)]
            .copy_from_slice(&tx.resource_bounds.l2_gas.max_amount.to_be_bytes());
        resource_buffer[(8 + 8)..]
            .copy_from_slice(&tx.resource_bounds.l2_gas.max_price_per_unit.to_be_bytes());
        fee_hasher.update(Felt::from_bytes_be(&resource_buffer));

        // L1 Data Gas resource bounds
        let mut resource_buffer = [
            0, b'L', b'1', b'_', b'D', b'A', b'T', b'A', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ];
        resource_buffer[8..(8 + 8)]
            .copy_from_slice(&tx.resource_bounds.l1_data_gas.max_amount.to_be_bytes());
        resource_buffer[(8 + 8)..].copy_from_slice(
            &tx.resource_bounds
                .l1_data_gas
                .max_price_per_unit
                .to_be_bytes(),
        );
        fee_hasher.update(Felt::from_bytes_be(&resource_buffer));

        fee_hasher.finalize()
    });

    hasher.update(poseidon_hash_many(&tx.paymaster_data));
    hasher.update(chain_id);
    hasher.update(tx.nonce);

    // Hard-coded L1 DA mode for nonce and fee
    hasher.update(Felt::ZERO);

    hasher.update(poseidon_hash_many(&tx.account_deployment_data));
    hasher.update(poseidon_hash_many(&tx.calldata));

    Ok(hasher.finalize())
}
