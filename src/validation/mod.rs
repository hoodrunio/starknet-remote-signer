pub mod attestation_info;
pub mod chain_contracts;
pub mod validator;

#[cfg(test)]
mod tests;

// Re-export main types for easier access
pub use attestation_info::AttestationInfo;
pub use chain_contracts::ChainContracts;
pub use validator::AttestationValidator;
