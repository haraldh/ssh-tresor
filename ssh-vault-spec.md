# ssh-vault: SSH Agent-Based Secret Encryption

## Overview

`ssh-vault` is a command-line tool written in Rust that encrypts and decrypts secrets using keys held in an SSH agent. It derives encryption keys by asking the SSH agent to sign a random nonce, then uses the signature as key material for symmetric encryption.

This approach allows secrets to be decrypted only when the corresponding SSH key is loaded in an agent, with no passphrase prompts required at decryption time.

## Use Case

Primary use case: storing encrypted credentials (e.g., IMAP passwords) in configuration files, where decryption happens automatically if the SSH key is available in the agent.

Example integration with meli email client:
```toml
server_password_command = "ssh-vault decrypt ~/.config/meli/imap.vault"
```

Works seamlessly over SSH with agent forwarding (`ssh -A`).

## CLI Interface

```
ssh-vault [OPTIONS] <COMMAND>

Commands:
  encrypt     Encrypt data using an SSH key from the agent
  decrypt     Decrypt data using an SSH key from the agent
  list-keys   List available keys in the SSH agent

Options:
  -h, --help     Print help
  -V, --version  Print version
```

### encrypt

```
ssh-vault encrypt [OPTIONS] [INPUT]

Arguments:
  [INPUT]  Input file (default: stdin, use "-" explicitly for stdin)

Options:
  -k, --key <FINGERPRINT>  SSH key fingerprint to use (default: first available key)
  -o, --output <FILE>      Output file (default: stdout)
  -a, --armor              Output as base64 with header/footer (default: binary)
  -h, --help               Print help
```

### decrypt

```
ssh-vault decrypt [OPTIONS] [INPUT]

Arguments:
  [INPUT]  Input file (default: stdin, use "-" explicitly for stdin)

Options:
  -o, --output <FILE>  Output file (default: stdout)
  -h, --help           Print help
```

Note: The key fingerprint is stored in the encrypted blob, so no `-k` option is needed for decryption.

### list-keys

```
ssh-vault list-keys [OPTIONS]

Options:
  --md5     Show MD5 fingerprints (default: SHA256)
  -h, --help  Print help
```

Output format (one key per line):
```
SHA256:abc123... ED25519 user@host
SHA256:def456... RSA-4096 work-laptop
```

## Cryptographic Design

### Encryption Process

1. Connect to SSH agent via `SSH_AUTH_SOCK` environment variable
2. Select key by fingerprint, or use first available key
3. Generate 32 random bytes as challenge/nonce
4. Request SSH agent to sign the challenge using the selected key
5. Derive AES-256 key: `key = SHA-256(signature)`
6. Generate 12 random bytes as AES-GCM nonce
7. Encrypt plaintext using AES-256-GCM with the derived key
8. Construct output blob (see Wire Format below)

### Decryption Process

1. Connect to SSH agent via `SSH_AUTH_SOCK`
2. Parse input blob, extract key fingerprint and challenge
3. Find matching key in agent by fingerprint
4. Request SSH agent to sign the stored challenge
5. Derive AES-256 key: `key = SHA-256(signature)`
6. Decrypt ciphertext using AES-256-GCM
7. Output plaintext

### Security Properties

- **No key material on disk**: Private keys never leave the SSH agent
- **Deterministic key derivation**: Same challenge + same key = same signature = same AES key
- **Authenticated encryption**: AES-GCM provides confidentiality and integrity
- **Key binding**: Encrypted blob is bound to a specific SSH key via fingerprint

### Signature Algorithm Selection

When requesting a signature from the agent:
- For RSA keys: Use `rsa-sha2-256` signature algorithm
- For Ed25519 keys: Use default `ssh-ed25519`
- For ECDSA keys: Use appropriate `ecdsa-sha2-*` variant

## Wire Format

### Binary Format

```
+------------------+
| Header (8 bytes) |  Magic: "SSHVAULT" (0x53 0x53 0x48 0x56 0x41 0x55 0x4C 0x54)
+------------------+
| Version (1 byte) |  Format version: 0x01
+------------------+
| Fingerprint      |  SHA-256 fingerprint of public key (32 bytes)
+------------------+
| Challenge        |  Random challenge sent to agent (32 bytes)
+------------------+
| GCM Nonce        |  AES-GCM nonce (12 bytes)
+------------------+
| Ciphertext       |  AES-256-GCM encrypted data (variable length)
|                  |  Includes 16-byte auth tag appended by AES-GCM
+------------------+
```

Total overhead: 8 + 1 + 32 + 32 + 12 + 16 = 101 bytes + ciphertext length

### Armored Format

When `--armor` is specified, output is base64-encoded with header/footer:

```
-----BEGIN SSH VAULT-----
U1NIVkFVTFQB... (base64-encoded binary blob)
-----END SSH VAULT-----
```

Decryption automatically detects armored vs binary format.

## Dependencies

```toml
[dependencies]
ssh-agent-client-rs = "0.1"   # SSH agent protocol client
ssh-key = "0.6"               # SSH key types and fingerprinting
aes-gcm = "0.10"              # AES-256-GCM encryption
sha2 = "0.10"                 # SHA-256 for key derivation
rand = "0.8"                  # Cryptographically secure random
base64 = "0.22"               # Armored format encoding
clap = { version = "4", features = ["derive"] }  # CLI parsing
thiserror = "1"               # Error handling
```

Note: Evaluate `ssh-agent-client-rs` vs direct implementation. If the crate is unmaintained or insufficient, implement the agent protocol directly using the `ssh-key` crate for parsing and a Unix socket connection. The SSH agent protocol is simple (RFC 4251 framing + a few message types).

## Error Handling

Exit codes:
- `0`: Success
- `1`: General error (I/O, parsing)
- `2`: Agent connection failed (SSH_AUTH_SOCK not set, socket not accessible)
- `3`: Key not found (specified fingerprint not in agent)
- `4`: Decryption failed (wrong key, corrupted data, tampered ciphertext)

Error messages should be written to stderr and be actionable:
```
Error: SSH agent not available
Hint: Is SSH_AUTH_SOCK set? Try running: eval $(ssh-agent) && ssh-add
```

## Testing Strategy

### Unit Tests
- Wire format serialization/deserialization roundtrip
- Base64 armor/dearmor roundtrip
- Fingerprint parsing and matching

### Integration Tests
- Full encrypt/decrypt cycle with mock agent or real agent
- Key selection by fingerprint
- Stdin/stdout operation
- File input/output operation
- Armored format roundtrip
- Error cases (no agent, key not found, corrupted input)

### Manual Testing
- Verify interop with OpenSSH agent
- Verify interop with gpg-agent in SSH mode
- Test with RSA, Ed25519, and ECDSA keys
- Test over SSH with agent forwarding

## Future Considerations (Out of Scope for v1)

- Multiple recipients (encrypt to several keys)
- Key comment matching (`-k user@host` instead of fingerprint)
- Streaming encryption for large files
- FIDO2/hardware key support (if agent supports it)
- Integration with systemd credentials
- Shell completion scripts

## Example Session

```bash
# List available keys
$ ssh-vault list-keys
SHA256:uNiVztksCsDhcc0u9e8BujQXVUpKZIDTMczCvj3tD2s ED25519 harald@workstation
SHA256:2bGQ+FN/wdGvPwRCJdBe8bMPgIQCk0j8Fq1XVfLbLHs RSA-4096 harald@backup

# Encrypt a password (uses first key by default)
$ echo -n "super-secret-password" | ssh-vault encrypt -a
-----BEGIN SSH VAULT-----
U1NIVkFVTFQBnxqK8mF3vR...
-----END SSH VAULT-----

# Encrypt using specific key, save to file
$ echo -n "super-secret-password" | ssh-vault encrypt -k SHA256:2bGQ+FN -o ~/.secrets/mail.vault

# Decrypt
$ ssh-vault decrypt ~/.secrets/mail.vault
super-secret-password

# Use in a password command
$ ssh-vault decrypt ~/.secrets/mail.vault | xargs -0 some-command
```

## Project Structure

```
ssh-vault/
├── Cargo.toml
├── src/
│   ├── main.rs           # CLI entry point, argument parsing
│   ├── lib.rs            # Public API (encrypt, decrypt, list_keys)
│   ├── agent.rs          # SSH agent connection and protocol
│   ├── crypto.rs         # Key derivation and AES-GCM operations
│   ├── format.rs         # Wire format serialization/deserialization
│   └── error.rs          # Error types
└── tests/
    └── integration.rs    # Integration tests
```

## References

- SSH Agent Protocol: https://datatracker.ietf.org/doc/html/draft-miller-ssh-agent
- AES-GCM: NIST SP 800-38D
- ssh-crypt (Python reference): https://github.com/Sets88/ssh-crypt
- Rust ssh-key crate: https://docs.rs/ssh-key
