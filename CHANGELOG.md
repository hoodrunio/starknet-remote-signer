# Changelog

All notable changes to the Starknet Remote Signer project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Initial release preparation
- GitHub Actions workflow for automated releases
- Cross-platform binary builds (Linux, macOS)
- Docker image builds and publishing
- Release automation script

## [0.1.0] - 2024-XX-XX

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
## [X.Y.Z] - YYYY-MM-DD

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