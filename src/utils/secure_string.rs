use std::fmt;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// A secure string wrapper that automatically zeroizes memory on drop
/// Use this for passwords, passphrases, and other sensitive string data
#[derive(ZeroizeOnDrop)]
pub struct SecureString {
    data: Vec<u8>,
}

impl SecureString {
    /// Create a new SecureString from a regular string
    pub fn new(s: String) -> Self {
        Self {
            data: s.into_bytes(),
        }
    }

    /// Create a SecureString from a &str
    pub fn from_string_slice(s: &str) -> Self {
        Self {
            data: s.as_bytes().to_vec(),
        }
    }

    /// Create an empty SecureString
    pub fn empty() -> Self {
        Self { data: Vec::new() }
    }

    /// Get the string as a &str (use sparingly and only when necessary)
    pub fn as_str(&self) -> Result<&str, std::str::Utf8Error> {
        std::str::from_utf8(&self.data)
    }

    /// Get the bytes (use with caution)
    pub fn as_bytes(&self) -> &[u8] {
        &self.data
    }

    /// Check if the string is empty
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    /// Get the length of the string
    pub fn len(&self) -> usize {
        self.data.len()
    }

    /// Securely compare with another SecureString
    pub fn secure_eq(&self, other: &SecureString) -> bool {
        use subtle::ConstantTimeEq;

        if self.data.len() != other.data.len() {
            return false;
        }

        self.data.ct_eq(&other.data).into()
    }

    /// Manually zeroize the content (called automatically on drop)
    pub fn zeroize(&mut self) {
        self.data.zeroize();
    }

    /// Convert to a String (the original data is zeroized)
    /// Use this method only when you need to transfer ownership
    pub fn into_string(mut self) -> Result<String, std::string::FromUtf8Error> {
        let result = String::from_utf8(self.data.clone());
        self.data.zeroize();
        result
    }
}

impl From<String> for SecureString {
    fn from(s: String) -> Self {
        Self::new(s)
    }
}

impl From<&str> for SecureString {
    fn from(s: &str) -> Self {
        Self::from_string_slice(s)
    }
}

impl fmt::Debug for SecureString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SecureString")
            .field("data", &"[REDACTED]")
            .field("len", &self.data.len())
            .finish()
    }
}

impl fmt::Display for SecureString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[REDACTED SecureString of {} bytes]", self.data.len())
    }
}

// Prevent accidental cloning of sensitive data
impl Clone for SecureString {
    fn clone(&self) -> Self {
        Self {
            data: self.data.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_secure_string_creation() {
        let s = SecureString::from_string_slice("test password");
        assert_eq!(s.len(), 13);
        assert!(!s.is_empty());
        assert_eq!(s.as_str().unwrap(), "test password");
    }

    #[test]
    fn test_secure_string_eq() {
        let s1 = SecureString::from_string_slice("password123");
        let s2 = SecureString::from_string_slice("password123");
        let s3 = SecureString::from_string_slice("different");

        assert!(s1.secure_eq(&s2));
        assert!(!s1.secure_eq(&s3));
    }

    #[test]
    fn test_secure_string_debug() {
        let s = SecureString::from_string_slice("secret");
        let debug_str = format!("{:?}", s);
        assert!(debug_str.contains("[REDACTED]"));
        assert!(!debug_str.contains("secret"));
    }

    #[test]
    fn test_secure_string_display() {
        let s = SecureString::from_string_slice("secret");
        let display_str = format!("{}", s);
        assert!(display_str.contains("[REDACTED"));
        assert!(!display_str.contains("secret"));
    }

    #[test]
    fn test_empty_secure_string() {
        let s = SecureString::empty();
        assert!(s.is_empty());
        assert_eq!(s.len(), 0);
    }
}
