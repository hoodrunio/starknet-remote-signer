use std::collections::HashSet;
use std::net::IpAddr;
use starknet::core::utils::parse_cairo_short_string;
use starknet_crypto::Felt;

use crate::errors::SignerError;

#[derive(Clone)]
pub struct SecurityValidator {
    allowed_chain_ids: HashSet<String>,
    allowed_chain_ids_hex: HashSet<Felt>,
    allowed_ips: HashSet<IpAddr>,
}

impl SecurityValidator {
    pub fn new(allowed_chain_ids: Vec<String>, allowed_ips: Vec<String>) -> Result<Self, SignerError> {
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
                        .map_err(|e| SignerError::Config(format!("Invalid chain ID: {}", e)))?
                }
                "SN_SEPOLIA" => {
                    // Cairo short string for "SN_SEPOLIA"
                    Felt::from_hex("0x534e5f5345504f4c4941")
                        .map_err(|e| SignerError::Config(format!("Invalid chain ID: {}", e)))?
                }
                _ => {
                    // Try to parse as hex
                    Felt::from_hex(&chain_id)
                        .map_err(|e| SignerError::Config(format!("Invalid chain ID {}: {}", chain_id, e)))?
                }
            };
            chain_ids_hex.insert(felt_id);
        }
        
        // Process allowed IPs
        let mut ips = HashSet::new();
        for ip_str in allowed_ips {
            let ip: IpAddr = ip_str.parse()
                .map_err(|_| SignerError::Config(format!("Invalid IP address: {}", ip_str)))?;
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
                "IP address {} is not allowed", ip
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
            "Chain ID {} is not allowed", chain_id
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use starknet::macros::felt;
    
    #[test]
    fn test_chain_id_validation() {
        let validator = SecurityValidator::new(
            vec!["SN_MAIN".to_string(), "SN_SEPOLIA".to_string()],
            vec![]
        ).unwrap();
        
        // Test valid chain IDs
        assert!(validator.validate_chain_id(felt!("0x534e5f4d41494e")).is_ok()); // SN_MAIN
        assert!(validator.validate_chain_id(felt!("0x534e5f5345504f4c4941")).is_ok()); // SN_SEPOLIA
        
        // Test invalid chain ID
        assert!(validator.validate_chain_id(felt!("0x1234")).is_err());
    }
    
    #[test]
    fn test_ip_validation() {
        let validator = SecurityValidator::new(
            vec![],
            vec!["127.0.0.1".to_string(), "10.0.0.1".to_string()]
        ).unwrap();
        
        // Test valid IPs
        assert!(validator.validate_ip(&"127.0.0.1".parse().unwrap()).is_ok());
        assert!(validator.validate_ip(&"10.0.0.1".parse().unwrap()).is_ok());
        
        // Test invalid IP
        assert!(validator.validate_ip(&"192.168.1.1".parse().unwrap()).is_err());
    }
    
    #[test]
    fn test_empty_allows_all() {
        let validator = SecurityValidator::new(vec![], vec![]).unwrap();
        
        // Should allow any chain ID
        assert!(validator.validate_chain_id(felt!("0x1234")).is_ok());
        
        // Should allow any IP
        assert!(validator.validate_ip(&"1.2.3.4".parse().unwrap()).is_ok());
    }
} 