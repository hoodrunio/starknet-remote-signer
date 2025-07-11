use anyhow::Result;
use rpassword::prompt_password;
use tracing::{info, warn};

/// Securely prompt for a password from the user
pub fn prompt_for_passphrase(prompt_message: &str) -> Result<String> {
    // Security warning about environment variables
    warn!("🔐 Prompting for passphrase securely...");
    warn!("💡 Tip: For automation, consider using encrypted keystores with OS keyring backend");
    
    let passphrase = prompt_password(prompt_message)?;
    
    if passphrase.is_empty() {
        return Err(anyhow::anyhow!("Passphrase cannot be empty"));
    }
    
    if passphrase.len() < 8 {
        warn!("⚠️  Short passphrase detected. Consider using a longer, more secure passphrase.");
    }
    
    info!("✅ Passphrase received securely");
    Ok(passphrase)
}

/// Get passphrase from CLI args or prompt user securely
pub fn get_passphrase_securely(
    cli_passphrase: Option<String>,
    prompt_message: &str,
) -> Result<String> {
    match cli_passphrase {
        Some(passphrase) => {
            warn!("⚠️  SECURITY WARNING: Passphrase provided via CLI argument or environment variable");
            warn!("⚠️  This method is less secure as the passphrase may be visible in process lists or logs");
            warn!("⚠️  Consider removing the --passphrase argument to use secure prompting instead");
            
            if passphrase.is_empty() {
                return Err(anyhow::anyhow!("Provided passphrase cannot be empty"));
            }
            
            Ok(passphrase)
        }
        None => {
            prompt_for_passphrase(prompt_message)
        }
    }
}

/// Prompt for passphrase confirmation (for key creation)
pub fn prompt_for_passphrase_with_confirmation(prompt_message: &str) -> Result<String> {
    warn!("🔐 Creating new encrypted key - passphrase confirmation required");
    
    let passphrase = prompt_for_passphrase(prompt_message)?;
    let confirmation = prompt_password("Confirm passphrase: ")?;
    
    if passphrase != confirmation {
        return Err(anyhow::anyhow!("Passphrases do not match"));
    }
    
    info!("✅ Passphrase confirmed");
    Ok(passphrase)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_passphrase_with_cli_arg() {
        let result = get_passphrase_securely(
            Some("test_password_123".to_string()),
            "Enter passphrase: "
        );
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "test_password_123");
    }

    #[test]
    fn test_empty_cli_passphrase_fails() {
        let result = get_passphrase_securely(
            Some("".to_string()),
            "Enter passphrase: "
        );
        assert!(result.is_err());
    }
} 