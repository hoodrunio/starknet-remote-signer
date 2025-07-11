# Starknet Remote Signer

A secure remote signing service for Starknet validators.

## Quick Start

### 1. Add a Key

Choose one of the keystore backends:

```bash
# File backend (Recommended)
starknet-remote-signer keys add my-key --backend file --keystore-dir ./keystore --private-key YOUR_PRIVATE_KEY

# OS keyring
starknet-remote-signer keys add my-key --private-key YOUR_PRIVATE_KEY

# Software keystore
starknet-remote-signer keys add my-key \
  --backend software \
  --keystore-path my-key.keystore \
  --private-key YOUR_PRIVATE_KEY
```

### 2. Start the Signer

```bash
# Using config file
starknet-remote-signer start --config config.toml

# Using CLI
starknet-remote-signer start --keystore-backend file --keystore-dir ./keystore
```

## Key Management

### Add Keys
```bash
# File backend
starknet-remote-signer keys add validator --backend file --keystore-dir ./keystore

# OS keyring
starknet-remote-signer keys add validator --private-key PRIVATE_KEY

# Software keystore
starknet-remote-signer keys add validator \
  --backend software \
  --keystore-path validator.keystore \
  --private-key PRIVATE_KEY
```

### List Keys
```bash
# File backend
starknet-remote-signer keys list --backend file --keystore-dir ./keystore

# OS keyring
starknet-remote-signer keys list

# Software keystore
starknet-remote-signer keys list --backend software --keystore-path validator.keystore
```

### Delete Keys
```bash
starknet-remote-signer keys delete validator --confirm
```

## Configuration

Create a `config.toml` file:

```toml
[server]
address = "127.0.0.1"
port = 3000

[keystore]
backend = "file"  # or "os_keyring", "software", "environment"
dir = "./keystore"  # for file backend
key_name = "validator"  # optional: specify which key to use

[security]
allowed_chain_ids = ["SN_MAIN"]
allowed_ips = ["10.0.0.1", "10.0.0.2"]

[tls]
enabled = true
cert_file = "/path/to/cert.pem"
key_file = "/path/to/key.pem"

[audit]
enabled = true
log_path = "./logs/audit.log"
```

## Keystore Backends

### File Backend (Recommended)
- Stores encrypted keys in a directory
- Supports multiple keys
- Password-protected encryption
- Similar to Cosmos SDK file keyring

### OS Keyring
- Uses system keyring (Linux/macOS)
- Automatic OS-level encryption
- User session integration

### Software
- Single encrypted keystore file
- Passphrase protection
- Good for simple setups

### Environment (Development Only)
- Private key in environment variable
- Not secure for production

## API Endpoints

- `GET /health` - Health check
- `GET /get_public_key` - Get public key
- `POST /sign` - Sign transaction
- `GET /metrics` - Prometheus metrics

## Security Notes

⚠️ **Production Requirements:**
- Use file, software, or OS keyring backends (never environment)
- Configure IP allowlists
- Configure chain ID restrictions
- Enable TLS
- Enable audit logging

## License

Apache 2.0 