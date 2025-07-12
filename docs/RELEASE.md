# Release Guide for Starknet Remote Signer

This guide explains the GitHub release process for the `starknet-remote-signer` project.

## 🚀 Quick Start

### Automated Release (Recommended)

```bash
# 1. Run the release script
./scripts/release.sh

# 2. Push changes and tag to GitHub
git push origin main
git push origin v0.1.1  # replace with your version number
```

### Manual Release

```bash
# 1. Update version
vim starknet-remote-signer/Cargo.toml

# 2. Test
cd starknet-remote-signer && cargo test

# 3. Release build
cargo build --release

# 4. Create commit and tag
git add .
git commit -m "Release v0.1.1"
git tag -a v0.1.1 -m "Release version 0.1.1"

# 5. Push
git push origin main
git push origin v0.1.1
```

## 📋 Detailed Release Process

### 1. Preparation

#### Version Determination
Use semantic versioning:
- **MAJOR** (1.0.0): Breaking changes
- **MINOR** (0.1.0): New features (backwards compatible)
- **PATCH** (0.0.1): Bug fixes

#### Document Changes
Update the `CHANGELOG.md` file:

```markdown
## [0.1.1] - 2024-01-15

### Added
- New feature description

### Fixed
- Fixed bug description
```

### 2. Pre-Release Checks

#### Tests
```bash
cd starknet-remote-signer

# Unit tests
cargo test

# Integration tests
./test_integration.sh

# Linting
cargo clippy -- -D warnings

# Format check
cargo fmt --check
```

#### Build Check
```bash
# Debug build
cargo build

# Release build
cargo build --release

# Test for different platforms (optional)
cargo build --target x86_64-unknown-linux-musl
```

### 3. Create Release

#### Option A: Automated Script

```bash
./scripts/release.sh
```

The script does the following:
1. Shows current version
2. Asks for new version
3. Updates `Cargo.toml`
4. Runs tests
5. Creates release build
6. Creates git commit and tag

#### Option B: Manual

```bash
# 1. Update version in Cargo.toml
sed -i 's/version = "0.1.0"/version = "0.1.1"/' Cargo.toml

# 2. Test
cargo test

# 3. Commit and tag
git add Cargo.toml
git commit -m "Release v0.1.1"
git tag -a v0.1.1 -m "Release version 0.1.1"
```

### 4. Push to GitHub

```bash
# Push main branch
git push origin main

# Push tag (this triggers GitHub Actions)
git push origin v0.1.1
```

## 🤖 GitHub Actions Workflow

The `.github/workflows/release.yml` file automatically:

1. **Multi-Platform Build**:
   - Linux (GNU and musl)
   - macOS (Intel and Apple Silicon)

2. **Docker Image**:
   - Pushes to GitHub Container Registry
   - Creates latest and version tags

3. **GitHub Release**:
   - Automatically generates release notes
   - Adds binary files
   - Adds pre-release marker (alpha/beta/rc)

## 📦 Release Contents

Each release includes:

### Binary Files
- `starknet-remote-signer-x86_64-unknown-linux-gnu.tar.gz`
- `starknet-remote-signer-x86_64-unknown-linux-musl.tar.gz`
- `starknet-remote-signer-x86_64-apple-darwin.tar.gz`
- `starknet-remote-signer-aarch64-apple-darwin.tar.gz`

### Docker Image
```bash
# Latest version
docker pull ghcr.io/yourusername/yourrepo/starknet-remote-signer:latest

# Specific version
docker pull ghcr.io/yourusername/yourrepo/starknet-remote-signer:v0.1.1
```

## 🔧 Troubleshooting

### Build Errors

```bash
# Clean dependencies
cd starknet-remote-signer
cargo clean

# Rebuild
cargo build --release
```

### Test Errors

```bash
# Verbose test output
cargo test -- --nocapture

# Run specific test
cargo test test_name
```

### Git Tag Issues

```bash
# List tags
git tag -l

# Delete tag (local)
git tag -d v0.1.1

# Delete tag (remote)
git push origin --delete v0.1.1
```

## 📝 Release Checklist

- [ ] CHANGELOG.md updated
- [ ] Version number is correct
- [ ] All tests passing
- [ ] Build successful
- [ ] Documentation up to date
- [ ] Security audit completed (for major releases)
- [ ] Git tag created
- [ ] Pushed to GitHub
- [ ] GitHub Actions successful
- [ ] Release notes reviewed
- [ ] Docker image tested

## 🔒 Security Notes

For production releases:

1. **Dependency Audit**:
   ```bash
   cargo audit
   ```

2. **Vulnerable Dependencies**:
   ```bash
   cargo outdated
   ```

3. **Code Review**:
   - All changes should be reviewed
   - Security-critical code should be approved by two people

## 📚 Additional Resources

- [Semantic Versioning](https://semver.org/)
- [Keep a Changelog](https://keepachangelog.com/)
- [Rust Release Best Practices](https://doc.rust-lang.org/cargo/reference/publishing.html)
- [GitHub Releases Documentation](https://docs.github.com/en/repositories/releasing-projects-on-github) 