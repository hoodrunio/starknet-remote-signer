# Starknet Remote Signer

A secure, lightweight remote signing service for Starknet transactions. Inspired by [TMKMS](https://github.com/tomtau/tmkms-light) but simplified and focused on security and stability.

## 🔐 Security Features

- **Encrypted key storage**: Private keys encrypted at rest using AES-256-GCM
- **PBKDF2 key derivation**: Strong key derivation with 100,000 iterations
- **Secure memory handling**: Keys zeroized on drop, no plaintext storage
- **Multiple backends**: Software (encrypted), Environment, HSM (planned)

- **HTTPS support**: TLS encryption for secure communications (planned)
- **Non-root execution**: Runs as unprivileged user in containers
- **Input validation**: Comprehensive validation of all inputs

## 🚀 Quick Start

### Method 1: Using Environment Variables (Development)

```bash
# Set your private key (without 0x prefix)
export SIGNER_PRIVATE_KEY="your_private_key_here"

# Start the service
docker-compose up -d
```

### Method 2: Using Configuration File + Encrypted Keystore (Production)

```bash
# 1. Ensure config.toml and keystore.json files exist
# config.toml: Contains server, security, audit, keystore configuration
# keystore.json: Encrypted private key file

# 2. Set passphrase for encrypted keystore
export SIGNER_PASSPHRASE="your_secure_passphrase"

# 3. Start with config file and encrypted keystore
docker-compose up -d
```

### Method 3: Using CLI (Alternative)

```bash
# 1. Create encrypted keystore
./target/release/starknet-remote-signer init \
  --output keystore.json \
  --private-key "your_private_key_here" \
  --passphrase "your_secure_passphrase"

# 2. Start with encrypted keystore
./target/release/starknet-remote-signer start \
  --keystore-backend software \
  --keystore-path keystore.json \
  --passphrase "your_secure_passphrase"
```

### Building from Source

```bash
cargo build --release
```

## 📡 API Endpoints

### Health Check
```bash
GET /health
```
Returns server status and public key.

### Get Public Key
```bash
GET /get_public_key
```
Returns the public key of the signer.

### Sign Transaction
```bash
POST /sign
Content-Type: application/json

{
    "transaction": {
        "type": "INVOKE",
        "sender_address": "0x...",
        "calldata": ["0x1", "0x..."],
        "version": "0x3",
        "signature": [],
        "nonce": "0xbf",
        "resource_bounds": {
            "l1_gas": {
                "max_amount": "0x0",
                "max_price_per_unit": "0x49f83fa3027b"
            },
            "l1_data_gas": {
                "max_amount": "0x600",
                "max_price_per_unit": "0x3948c"
            },
            "l2_gas": {
                "max_amount": "0x1142700",
                "max_price_per_unit": "0x33a8f57f9"
            }
        },
        "tip": "0x0",
        "paymaster_data": [],
        "account_deployment_data": [],
        "nonce_data_availability_mode": "L1",
        "fee_data_availability_mode": "L1"
    },
    "chain_id": "0x534e5f5345504f4c4941"
}
```

### Metrics
```bash
GET /metrics
```
Returns operational metrics for monitoring.

## ⚙️ Configuration

### Command Line Options

```bash
# Get help for all commands
starknet-remote-signer --help

# Initialize keystore
starknet-remote-signer init --help

# Start server
starknet-remote-signer start --help
```

#### Start Command Options

| Option | Environment Variable | Description | Required |
|--------|---------------------|-------------|----------|
| `--keystore-backend` | `SIGNER_KEYSTORE_BACKEND` | Backend: "software", "environment", "hsm" | ❌ (default: environment) |
| `--keystore-path` | `SIGNER_KEYSTORE_PATH` | Path to encrypted keystore file | ✅ (for software) |
| `--env-var` | `SIGNER_ENV_VAR` | Environment variable for private key | ❌ (default: SIGNER_PRIVATE_KEY) |
| `--passphrase` | `SIGNER_PASSPHRASE` | Passphrase for encrypted keystore | ✅ (for software) |
| `--address` | `SIGNER_ADDRESS` | Bind address | ❌ (default: 127.0.0.1) |
| `--port` | `SIGNER_PORT` | Bind port | ❌ (default: 3000) |
| `--config` | `SIGNER_CONFIG` | Config file path | ❌ |
| `--tls` | `SIGNER_TLS` | Enable TLS | ❌ |
| `--tls-cert` | `SIGNER_TLS_CERT` | TLS certificate file | ❌ |
| `--tls-key` | `SIGNER_TLS_KEY` | TLS private key file | ❌ |

#### Init Command Options

| Option | Description | Required |
|--------|-------------|----------|
| `--output` | Output path for encrypted keystore | ✅ |
| `--private-key` | Private key to encrypt (hex, without 0x) | ✅ |
| `--passphrase` | Passphrase for encryption | ✅ |

### Configuration File

Create a `config.toml` file in your project root:

```toml
[server]
address = "0.0.0.0"
port = 3000

[tls]
enabled = false
cert_file = "/path/to/cert.pem"
key_file = "/path/to/key.pem"

[keystore]
backend = "software"  # "software", "environment", "hsm"
path = "./keystore.json"  # For software backend
env_var = "SIGNER_PRIVATE_KEY"   # For environment backend

[security]
# Chain restrictions - only allow specific chains
allowed_chain_ids = ["SN_MAIN"]  # Only mainnet in production
# allowed_ips = ["10.0.0.10", "10.0.0.11"]  # IP allowlist

[audit]
enabled = true
log_path = "/var/log/starknet-signer/audit.log"
rotate_daily = true
```

## 🔒 Security Best Practices

### Production Deployment

1. **Always use HTTPS** in production (TLS support coming soon)

3. **Run behind a reverse proxy** (nginx, traefik)
4. **Use a firewall** to restrict access
5. **Monitor logs** for suspicious activity
6. **Regular security updates**

### Private Key Management

- **Never commit private keys** to version control
- **Use environment variables** or secure configuration management
- **Rotate keys regularly**
- **Use hardware security modules** for high-value deployments

### Example Production Setup

```yaml
# docker-compose.prod.yml
version: '3.8'
services:
  starknet-remote-signer:
    build: .
    environment:
      # Configuration file (mounted as volume)
      - SIGNER_CONFIG=/app/config.toml
      # Keystore backend (software for production security)
      # - SIGNER_KEYSTORE_BACKEND=software
      # - SIGNER_KEYSTORE_PATH=/app/keystore.json
      - SIGNER_PASSPHRASE=${SIGNER_PASSPHRASE}
      - SIGNER_ADDRESS=0.0.0.0
      - RUST_LOG=info
    volumes:
      - ./config.toml:/app/config.toml:ro
      - ./keystore.json:/app/keystore.json:ro
      - ./logs:/var/log/starknet-signer:rw
    ports:
      - "3000:3000"  # Only bind to localhost
    restart: unless-stopped
    read_only: true
    cap_drop:
      - ALL
    security_opt:
      - no-new-privileges:true
    user: "1000:1000"
```

## 📊 Monitoring

The service provides metrics at `/metrics` endpoint:

- `sign_requests`: Total number of signing requests
- `sign_errors`: Total number of signing errors  
- `health_checks`: Total number of health check requests

### Prometheus Configuration

```yaml
# prometheus.yml
global:
  scrape_interval: 15s

scrape_configs:
  - job_name: 'starknet-remote-signer'
    static_configs:
      - targets: ['starknet-remote-signer:3000']
    metrics_path: '/metrics'
```

## 🛠️ Development

### Building

```bash
# Debug build
cargo build

# Release build
cargo build --release

# Run tests
cargo test
```

### Testing

```bash
# Unit tests
cargo test

# Integration tests
cargo test --test integration

# With logging
RUST_LOG=debug cargo test
```

## 🚨 Troubleshooting

### Common Issues

**"Private key is required"**
- Set `SIGNER_PRIVATE_KEY` environment variable (for environment backend)
- Or use encrypted keystore with `SIGNER_PASSPHRASE` (for software backend)
- Ensure `config.toml` specifies correct keystore backend and path

**"Keystore file does not exist"**
- Ensure `keystore.json` file exists in project root
- Check volume mount in `docker-compose.yml`: `./keystore.json:/app/keystore.json:ro`
- Verify `config.toml` keystore path: `path = "./keystore.json"`

**"Failed to read config file"**
- Ensure `config.toml` file exists and is valid TOML format
- Check `SIGNER_CONFIG` environment variable points to correct path
- Verify Docker volume mount: `./config.toml:/app/config.toml:ro`

**"Failed to bind to address"**
- Port might be in use by another process
- Try a different port with `--port` option
- Check firewall settings

### Debug Mode

```bash
RUST_LOG=debug ./target/release/starknet-remote-signer --private-key "..."
```

## 📄 License

Licensed under the Apache License, Version 2.0 ([LICENSE](LICENSE) or http://www.apache.org/licenses/LICENSE-2.0)

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests
5. Submit a pull request

## ⚠️ Disclaimer

This software is provided "as is" without warranty. Use at your own risk, especially in production environments. Always follow security best practices when handling private keys and cryptographic operations. 