# Starknet Remote Signer

A secure remote signing service for Starknet validators, designed with security-first principles.

## ⚠️ Security Notices

### Critical Security Requirements

1. **Never use environment variable keystore in production** - Environment variables can be visible to other processes and may be logged. Always use encrypted software keystore for production.

2. **Always configure IP allowlists** - Empty IP allowlists allow access from any IP address, which is extremely insecure for production environments.

3. **Always configure chain ID restrictions** - Empty chain ID allowlists allow signing for any chain, which could be exploited.

4. **Enable TLS in production** - Unencrypted communications expose private keys and signatures to network attacks.

5. **Enable audit logging** - Audit logs are required for security monitoring and incident response.

### Security Best Practices

- **Use software keystore**: Store private keys in encrypted files with strong passphrases
- **Configure IP restrictions**: Limit access to known validator IPs only
- **Configure chain restrictions**: Only allow signing for specific chains
- **Enable TLS**: Use proper TLS certificates for all communications
- **Enable audit logging**: Monitor all signing operations
- **Use strong passphrases**: For encrypted keystores, use cryptographically strong passphrases
- **Regular security audits**: Review configurations and logs regularly

## Quick Start

### 1. Add a Key to Keystore

#### Option A: OS Keyring (Recommended for Validators)
```bash
# Add a key to OS keyring (like Cosmos SDK)
starknet-remote-signer keys add validator --private-key YOUR_PRIVATE_KEY
```

#### Option B: Encrypted Software Keystore
```bash
# Create encrypted keystore file
starknet-remote-signer keys add validator \
  --backend software \
  --keystore-path validator.keystore \
  --private-key YOUR_PRIVATE_KEY \
  --passphrase YOUR_STRONG_PASSPHRASE
```

### 2. Configure Security (Required for Production)

Create `config.toml`:

```toml
[server]
address = "127.0.0.1"  # Bind to localhost only
port = 3000

[tls]
enabled = true
cert_file = "/path/to/cert.pem"
key_file = "/path/to/key.pem"

[keystore]
backend = "os_keyring"
key_name = "validator"  # Key you added in step 1

[security]
allowed_chain_ids = ["SN_MAIN"]  # Only allow mainnet
allowed_ips = ["10.0.0.1", "10.0.0.2"]  # Only allow specific IPs

[audit]
enabled = true
log_path = "/var/log/starknet-signer/audit.log"
```

### 3. Start the Signer

```bash
# Using config file
starknet-remote-signer start --config config.toml

# Or using CLI arguments
starknet-remote-signer start \
  --keystore-backend os_keyring \
  --key-name validator \
  --port 3000
```

## Key Management Commands

### Add Keys
```bash
# Add to OS keyring (like Cosmos SDK)
starknet-remote-signer keys add validator --private-key PRIVATE_KEY

# Add to encrypted file
starknet-remote-signer keys add validator \
  --backend software \
  --keystore-path validator.keystore \
  --private-key PRIVATE_KEY \
  --passphrase STRONG_PASSPHRASE
```

### List Keys
```bash
# List OS keyring keys
starknet-remote-signer keys list

# List software keystore
starknet-remote-signer keys list --backend software --keystore-path validator.keystore
```

### Delete Keys
```bash
# Delete from OS keyring
starknet-remote-signer keys delete validator --confirm

# Delete software keystore file
starknet-remote-signer keys delete validator --backend software --keystore-path validator.keystore --confirm
```

## Configuration Options

### Keystore Backends

#### Software (Recommended for Production)
- **Description**: Encrypted keystore files with PBKDF2 + AES-256-GCM
- **Security**: High - requires passphrase to decrypt
- **Use case**: Production environments

```toml
[keystore]
backend = "software"
path = "/secure/path/validator.keystore"
```

#### Environment (Development Only)
- **Description**: Private key stored in environment variable
- **Security**: Low - visible to other processes
- **Use case**: Development and testing only

```toml
[keystore]
backend = "environment"
env_var = "VALIDATOR_PRIVATE_KEY"
```

#### OS Keyring (Recommended for Validators)
- **Description**: Uses system keyring (GNOME Keyring, KDE Wallet, macOS Keychain)
- **Security**: High - OS-level encryption and user authentication
- **Use case**: Validator nodes with user sessions
- **Platforms**: Linux and macOS only

```toml
[keystore]
backend = "os_keyring"
key_name = "validator"  # key name
```

**OS Keyring Features:**
- ✅ **No complex setup** - Just provide a key name
- ✅ **Fixed service name** - Always "starknet-signer"
- ✅ **System-level encryption** - Protected by OS security
- ✅ **User session integration** - Automatic unlock on login
- ✅ **Backup support** - OS keyring backup tools
- ⚠️ **Session dependency** - Requires active user session

**Usage Examples:**
```bash
# Add a key (like Cosmos SDK)
starknet-remote-signer keys add validator --private-key PRIVATE_KEY

# Start server with that key
starknet-remote-signer start --keystore-backend os_keyring --key-name validator

# Delete a key
starknet-remote-signer keys delete validator --confirm

# List keys
starknet-remote-signer keys list
```

### Security Configuration

#### IP Allowlists
Configure which IP addresses can access the signer:

```toml
[security]
allowed_ips = ["10.0.0.1", "192.168.1.100"]
```

**Warning**: Empty allowlists allow ALL IPs - never use in production!

#### Chain ID Restrictions
Configure which chains the signer can sign for:

```toml
[security]
allowed_chain_ids = ["SN_MAIN", "SN_SEPOLIA"]
```

**Warning**: Empty allowlists allow ALL chains - never use in production!

### TLS Configuration

Always enable TLS for production:

```toml
[tls]
enabled = true
cert_file = "/path/to/certificate.pem"
key_file = "/path/to/private-key.pem"
```

### Audit Logging

Enable comprehensive audit logging:

```toml
[audit]
enabled = true
log_path = "/var/log/starknet-signer/audit.log"
rotate_daily = true
```

## API Endpoints

### Health Check
```bash
GET /health
```

### Get Public Key
```bash
GET /get_public_key
```

### Sign Transaction
```bash
POST /sign
Content-Type: application/json

{
  "transaction": { ... },
  "chain_id": "0x534e5f4d41494e"
}
```

### Get Metrics
```bash
GET /metrics
```

## Security Warnings

The signer will display warnings for insecure configurations:

- ⚠️ **Environment keystore in use**: Private keys in environment variables
- ⚠️ **No IP restrictions**: Empty IP allowlists allow access from anywhere
- ⚠️ **No chain restrictions**: Empty chain ID allowlists allow signing for any chain
- ⚠️ **TLS disabled**: Unencrypted communications
- ⚠️ **Audit logging disabled**: No security monitoring

## License

Apache 2.0 