use super::validator::SecurityValidator;
use starknet::macros::felt;

#[test]
fn test_chain_id_validation() {
    let validator = SecurityValidator::new(
        vec!["SN_MAIN".to_string(), "SN_SEPOLIA".to_string()],
        vec![],
    )
    .unwrap();

    // Test valid chain IDs
    assert!(validator
        .validate_chain_id(felt!("0x534e5f4d41494e"))
        .is_ok()); // SN_MAIN
    assert!(validator
        .validate_chain_id(felt!("0x534e5f5345504f4c4941"))
        .is_ok()); // SN_SEPOLIA

    // Test invalid chain ID
    assert!(validator.validate_chain_id(felt!("0x1234")).is_err());
}

#[test]
fn test_ip_validation() {
    let validator = SecurityValidator::new(
        vec![],
        vec!["127.0.0.1".to_string(), "10.0.0.1".to_string()],
    )
    .unwrap();

    // Test valid IPs
    assert!(validator.validate_ip(&"127.0.0.1".parse().unwrap()).is_ok());
    assert!(validator.validate_ip(&"10.0.0.1".parse().unwrap()).is_ok());

    // Test invalid IP
    assert!(validator
        .validate_ip(&"192.168.1.1".parse().unwrap())
        .is_err());
}

#[test]
fn test_empty_allows_all() {
    let validator = SecurityValidator::new(vec![], vec![]).unwrap();

    // Should allow any chain ID
    assert!(validator.validate_chain_id(felt!("0x1234")).is_ok());

    // Should allow any IP
    assert!(validator.validate_ip(&"1.2.3.4".parse().unwrap()).is_ok());
}
