use std::fmt;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Secure wrapper for sensitive data that ensures zeroization
/// Use this for temporary sensitive values like transaction hashes, signatures, etc.
#[derive(ZeroizeOnDrop)]
pub struct SecureBuffer<T: Zeroize> {
    data: T,
}

impl<T: Zeroize> SecureBuffer<T> {
    /// Create a new secure buffer
    pub fn new(data: T) -> Self {
        Self { data }
    }

    /// Get a reference to the data
    pub fn data(&self) -> &T {
        &self.data
    }

    /// Get a mutable reference to the data
    pub fn data_mut(&mut self) -> &mut T {
        &mut self.data
    }

    /// Extract the data, consuming the buffer
    /// Note: The extracted data will NOT be automatically zeroized
    pub fn into_inner(mut self) -> T {
        // We need to prevent the Drop implementation from running
        // since we're transferring ownership
        let data = std::mem::replace(&mut self.data, unsafe { std::mem::zeroed() });
        std::mem::forget(self);
        data
    }

    /// Manually zeroize the buffer
    pub fn zeroize(&mut self) {
        self.data.zeroize();
    }
}

impl<T: Zeroize + Clone> Clone for SecureBuffer<T> {
    fn clone(&self) -> Self {
        Self {
            data: self.data.clone(),
        }
    }
}

impl<T: Zeroize> fmt::Debug for SecureBuffer<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SecureBuffer")
            .field("data", &"[REDACTED]")
            .finish()
    }
}

/// Secure buffer specifically for byte arrays
pub type SecureBytes = SecureBuffer<Vec<u8>>;

/// Secure buffer for fixed-size byte arrays
#[derive(ZeroizeOnDrop)]
pub struct SecureArray<const N: usize> {
    data: [u8; N],
}

impl<const N: usize> SecureArray<N> {
    /// Create a new secure array
    pub fn new(data: [u8; N]) -> Self {
        Self { data }
    }

    /// Create a zeroed secure array
    pub fn zero() -> Self {
        Self { data: [0u8; N] }
    }

    /// Get a reference to the array
    pub fn as_array(&self) -> &[u8; N] {
        &self.data
    }

    /// Get a slice reference
    pub fn as_slice(&self) -> &[u8] {
        &self.data
    }

    /// Get a mutable reference to the array
    pub fn as_mut_array(&mut self) -> &mut [u8; N] {
        &mut self.data
    }

    /// Get a mutable slice reference
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        &mut self.data
    }

    /// Copy data into the array
    pub fn copy_from_slice(&mut self, src: &[u8]) -> Result<(), String> {
        if src.len() != N {
            return Err(format!(
                "Source length {} does not match array size {}",
                src.len(),
                N
            ));
        }
        self.data.copy_from_slice(src);
        Ok(())
    }

    /// Manually zeroize the array
    pub fn zeroize(&mut self) {
        self.data.zeroize();
    }
}

impl<const N: usize> fmt::Debug for SecureArray<N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SecureArray")
            .field("size", &N)
            .field("data", &"[REDACTED]")
            .finish()
    }
}

impl<const N: usize> Clone for SecureArray<N> {
    fn clone(&self) -> Self {
        Self { data: self.data }
    }
}

/// Type alias for 32-byte secure arrays (common for private keys)
pub type SecureKey = SecureArray<32>;

/// Type alias for 64-byte secure arrays (common for signatures)  
pub type SecureSignature = SecureArray<64>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_secure_buffer() {
        let sensitive_data = vec![1, 2, 3, 4, 5];
        let mut buffer = SecureBuffer::new(sensitive_data);

        assert_eq!(buffer.data(), &[1, 2, 3, 4, 5]);

        buffer.zeroize();
        // Vec::zeroize() clears the vector instead of overwriting with zeros
        assert_eq!(buffer.data(), &Vec::<i32>::new());
    }

    #[test]
    fn test_secure_array() {
        let mut arr = SecureArray::new([1, 2, 3, 4]);
        assert_eq!(arr.as_slice(), &[1, 2, 3, 4]);

        arr.zeroize();
        assert_eq!(arr.as_slice(), &[0, 0, 0, 0]);
    }

    #[test]
    fn test_secure_key() {
        let key_data = [0x42u8; 32];
        let mut secure_key = SecureKey::new(key_data);

        assert_eq!(secure_key.as_array()[0], 0x42);

        secure_key.zeroize();
        assert_eq!(secure_key.as_array()[0], 0);
    }

    #[test]
    fn test_debug_no_leak() {
        let buffer = SecureBuffer::new(vec![1, 2, 3, 4, 5]);
        let debug_str = format!("{:?}", buffer);

        assert!(debug_str.contains("[REDACTED]"));
        assert!(!debug_str.contains("1"));
        assert!(!debug_str.contains("2"));
    }
}
