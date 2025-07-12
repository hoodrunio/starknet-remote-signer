use starknet::core::utils::parse_cairo_short_string;
use starknet_crypto::Felt;
use std::collections::HashSet;
use std::net::IpAddr;

use crate::errors::SignerError;

#[derive(Clone)]
pub struct SecurityValidator {
    allowed_chain_ids: HashSet<String>,
    allowed_chain_ids_hex: HashSet<Felt>,
    allowed_ips: HashSet<IpAddr>,
}

impl SecurityValidator {
    pub fn new(
        allowed_chain_ids: Vec<String>,
        allowed_ips: Vec<String>,
    ) -> Result<Self, SignerError> {
        let mut chain_ids = HashSet::new();
        let mut chain_ids_hex = HashSet::new();

        // Process allowed chain IDs
        for chain_id in allowed_chain_ids {
            chain_ids.insert(chain_id.clone());

            // Convert known chain IDs to Felt
            let felt_id = match chain_id.as_str() {
                "SN_MAIN" => {
                    // Cairo short string for "SN_MAIN"
                    Felt::from_hex("0x534e5f4d41494e")
                        .map_err(|e| SignerError::Config(format!("Invalid chain ID: {e}")))?
                }
                "SN_SEPOLIA" => {
                    // Cairo short string for "SN_SEPOLIA"
                    Felt::from_hex("0x534e5f5345504f4c4941")
                        .map_err(|e| SignerError::Config(format!("Invalid chain ID: {e}")))?
                }
                _ => {
                    // Try to parse as hex
                    Felt::from_hex(&chain_id).map_err(|e| {
                        SignerError::Config(format!("Invalid chain ID {chain_id}: {e}"))
                    })?
                }
            };
            chain_ids_hex.insert(felt_id);
        }

        // Process allowed IPs
        let mut ips = HashSet::new();
        for ip_str in allowed_ips {
            let ip: IpAddr = ip_str
                .parse()
                .map_err(|_| SignerError::Config(format!("Invalid IP address: {ip_str}")))?;
            ips.insert(ip);
        }

        Ok(Self {
            allowed_chain_ids: chain_ids,
            allowed_chain_ids_hex: chain_ids_hex,
            allowed_ips: ips,
        })
    }

    pub fn validate_ip(&self, ip: &IpAddr) -> Result<(), SignerError> {
        // If no IPs configured, allow all
        if self.allowed_ips.is_empty() {
            return Ok(());
        }

        if !self.allowed_ips.contains(ip) {
            return Err(SignerError::Unauthorized(format!(
                "IP address {ip} is not allowed"
            )));
        }

        Ok(())
    }

    pub fn validate_chain_id(&self, chain_id: Felt) -> Result<(), SignerError> {
        // If no chain IDs configured, allow all
        if self.allowed_chain_ids.is_empty() && self.allowed_chain_ids_hex.is_empty() {
            return Ok(());
        }

        // Check if chain ID matches any allowed value
        if self.allowed_chain_ids_hex.contains(&chain_id) {
            return Ok(());
        }

        // Try to parse as string and check
        if let Ok(chain_str) = parse_cairo_short_string(&chain_id) {
            if self.allowed_chain_ids.contains(&chain_str) {
                return Ok(());
            }
        }

        Err(SignerError::Unauthorized(format!(
            "Chain ID {chain_id} is not allowed"
        )))
    }
} 