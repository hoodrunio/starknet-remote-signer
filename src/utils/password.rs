use anyhow::Result;
use rpassword::prompt_password;
use tracing::{info, warn};

use super::SecureString;

/// Securely prompt for a password from the user
pub fn prompt_for_passphrase(prompt_message: &str) -> Result<SecureString> {
    // Security warning about environment variables
    warn!("🔐 Prompting for passphrase securely...");
    warn!("💡 Tip: For automation, consider using encrypted keystores with OS keyring backend");

    let passphrase = prompt_password(prompt_message)?;
    let secure_passphrase = SecureString::new(passphrase);

    if secure_passphrase.is_empty() {
        return Err(anyhow::anyhow!("Passphrase cannot be empty"));
    }

    if secure_passphrase.len() < 8 {
        warn!("⚠️  Short passphrase detected. Consider using a longer, more secure passphrase.");
    }

    info!("✅ Passphrase received securely");
    Ok(secure_passphrase)
}

/// Legacy function for backward compatibility - returns String
pub fn prompt_for_passphrase_string(prompt_message: &str) -> Result<String> {
    let secure_passphrase = prompt_for_passphrase(prompt_message)?;
    secure_passphrase
        .into_string()
        .map_err(|e| anyhow::anyhow!("Invalid UTF-8 in passphrase: {}", e))
}

/// Get passphrase from CLI args or prompt user securely
pub fn get_passphrase_securely(
    cli_passphrase: Option<String>,
    prompt_message: &str,
) -> Result<SecureString> {
    match cli_passphrase {
        Some(passphrase) => {
            warn!("⚠️  SECURITY WARNING: Passphrase provided via CLI argument or environment variable");
            warn!("⚠️  This method is less secure as the passphrase may be visible in process lists or logs");
            warn!(
                "⚠️  Consider removing the --passphrase argument to use secure prompting instead"
            );

            let secure_passphrase = SecureString::new(passphrase);
            if secure_passphrase.is_empty() {
                return Err(anyhow::anyhow!("Provided passphrase cannot be empty"));
            }

            Ok(secure_passphrase)
        }
        None => prompt_for_passphrase(prompt_message),
    }
}

/// Legacy function for backward compatibility - returns String
pub fn get_passphrase_securely_string(
    cli_passphrase: Option<String>,
    prompt_message: &str,
) -> Result<String> {
    let secure_passphrase = get_passphrase_securely(cli_passphrase, prompt_message)?;
    secure_passphrase
        .into_string()
        .map_err(|e| anyhow::anyhow!("Invalid UTF-8 in passphrase: {}", e))
}

/// Prompt for passphrase confirmation (for key creation)
pub fn prompt_for_passphrase_with_confirmation(prompt_message: &str) -> Result<SecureString> {
    warn!("🔐 Creating new encrypted key - passphrase confirmation required");

    let passphrase = prompt_for_passphrase(prompt_message)?;
    let confirmation_str = prompt_password("Confirm passphrase: ")?;
    let confirmation = SecureString::new(confirmation_str);

    if !passphrase.secure_eq(&confirmation) {
        return Err(anyhow::anyhow!("Passphrases do not match"));
    }

    info!("✅ Passphrase confirmed");
    Ok(passphrase)
}

/// Legacy function for backward compatibility - returns String
pub fn prompt_for_passphrase_with_confirmation_string(prompt_message: &str) -> Result<String> {
    let secure_passphrase = prompt_for_passphrase_with_confirmation(prompt_message)?;
    secure_passphrase
        .into_string()
        .map_err(|e| anyhow::anyhow!("Invalid UTF-8 in passphrase: {}", e))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_passphrase_with_cli_arg() {
        let result = get_passphrase_securely_string(
            Some("test_password_123".to_string()),
            "Enter passphrase: ",
        );
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "test_password_123");
    }

    #[test]
    fn test_empty_cli_passphrase_fails() {
        let result = get_passphrase_securely(Some("".to_string()), "Enter passphrase: ");
        assert!(result.is_err());
    }
}
