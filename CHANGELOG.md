# Changelog

All notable changes to the Starknet Remote Signer project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.2] - 2025-07-12

### Added
- Transaction phase detection during signing process for better validation
- Attestation transaction validation support
- Constants module for configuration values
- Comprehensive secure memory handling with `SecureBuffer` and `SecureArray` types
- `SecureString` type for password and sensitive string management
- Enhanced logging configuration and structured logging
- `KeyManagementService` for centralized key operations
- Factory pattern for keystore backend creation
- Utility functions for secure file operations and permissions
- Enhanced error response types with structured error codes
- Better separation between client-facing and operator error messages

### Changed
- **BREAKING**: Enhanced error handling with sanitized client messages and detailed operator logs
- **SECURITY**: File paths in error messages now abstracted to prevent information disclosure
- **SECURITY**: Configuration details moved from INFO to DEBUG logging level
- **SECURITY**: Chain validation errors no longer expose supported network details
- **SECURITY**: IP validation errors provide generic messages instead of exposing specific IPs
- Password handling throughout the codebase now uses `SecureString` for enhanced security
- Refactored codebase into organized module structure for better maintainability
- Key management operations now use centralized service pattern
- Improved file backend implementation with better error handling
- Enhanced OS keyring backend with better platform-specific handling
- Streamlined CLI command handling with dedicated command module

### Fixed
- Information disclosure vulnerabilities in error messages
- File path exposure in keystore error responses
- Backend enumeration through error messages
- Memory safety improvements with automatic zeroization of sensitive data

### Security
- **CRITICAL**: Fixed information disclosure in validation error messages
- **HIGH**: Abstracted file system paths from client-facing error messages
- **MEDIUM**: Reduced configuration verbosity to prevent system detail leakage
- Added secure memory handling with automatic cleanup of sensitive data
- Enhanced password security with constant-time comparison operations
- Improved error message sanitization for production security
- Better separation of concerns between client responses and operator debugging

## [0.1.1] - 2025-07-11

### Added
- Initial implementation of Starknet remote signer
- Support for multiple keystore backends:
  - File backend (recommended for production)
  - OS keyring backend
  - Software keystore backend
  - Environment backend (development only)
- RESTful API endpoints:
  - Health check endpoint
  - Public key retrieval
  - Transaction signing
  - Prometheus metrics
- Security features:
  - IP allowlisting
  - Chain ID restrictions
  - TLS/SSL support
  - Audit logging
- Configuration management via TOML files
- CLI interface for key management
- Comprehensive logging and tracing
- Integration tests

### Security
- Password-protected key encryption
- Secure credential storage using OS keyring
- TLS certificate validation
- Request validation and sanitization

---

## Release Notes Template

When creating a new release, copy the following template and fill in the details:

```markdown
## [X.Y.Z] - YYYY-DD-MM

### Added
- New features

### Changed
- Changes in existing functionality

### Deprecated
- Features that will be removed in future versions

### Removed
- Features removed in this version

### Fixed
- Bug fixes

### Security
- Security improvements and fixes
```

## Versioning Strategy

This project follows [Semantic Versioning](https://semver.org/):

- **MAJOR** version when you make incompatible API changes
- **MINOR** version when you add functionality in a backwards compatible manner
- **PATCH** version when you make backwards compatible bug fixes

### Pre-release Versions

For pre-release versions, append a pre-release identifier:
- `1.0.0-alpha.1` - Alpha releases
- `1.0.0-beta.1` - Beta releases
- `1.0.0-rc.1` - Release candidates 