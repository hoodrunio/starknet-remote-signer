// Re-export sub-modules
pub mod backends;
pub mod core;
pub mod encryption;
pub mod key_material;
pub mod shared;
pub mod tests;

// Re-export commonly used types
pub use backends::{BackendConfig, KeystoreBackend};
pub use core::Keystore;
pub use encryption::EncryptedKeystore;
pub use key_material::KeyMaterial;
pub use shared::SharedKeystore;

// Re-export backend implementations
pub use backends::{EnvironmentBackend, FileBackend, OsKeyringBackend, SoftwareBackend};
