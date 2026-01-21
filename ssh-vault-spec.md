# ssh-tresor: SSH Agent-Based Secret Encryption

## Overview

`ssh-tresor` is a command-line tool written in Rust that encrypts and decrypts secrets using keys held in an SSH agent. It derives encryption keys by asking the SSH agent to sign a random nonce, then uses the signature as key material for symmetric encryption.

This approach allows secrets to be decrypted only when the corresponding SSH key is loaded in an agent, with no passphrase prompts required at decryption time.

**Multi-key support:** A tresor can be encrypted for multiple SSH keys (LUKS-style slots). Each slot encrypts a master key, which in turn encrypts the data. Any of the authorized keys can decrypt the tresor.

## Use Case

Primary use case: storing encrypted credentials (e.g., IMAP passwords) in configuration files, where decryption happens automatically if the SSH key is available in the agent.

Example integration with meli email client:
```toml
server_password_command = "ssh-tresor decrypt ~/.config/meli/imap.tresor"
```

Works seamlessly over SSH with agent forwarding (`ssh -A`).

## CLI Interface

```
ssh-tresor [OPTIONS] <COMMAND>

Commands:
  encrypt     Encrypt data using SSH keys from the agent
  decrypt     Decrypt data using an SSH key from the agent
  add-key     Add a key to an existing tresor
  remove-key  Remove a key from an existing tresor
  list-slots  List key slots in a tresor
  list-keys   List available keys in the SSH agent

Options:
  -h, --help     Print help
  -V, --version  Print version
```

### encrypt

```
ssh-tresor encrypt [OPTIONS] [INPUT]

Arguments:
  [INPUT]  Input file (default: stdin, use "-" explicitly for stdin)

Options:
  -k, --key <FINGERPRINT>  SSH key fingerprint(s) to use (can be specified multiple times)
  -o, --output <FILE>      Output file (default: stdout)
  -a, --armor              Output as base64 with header/footer (default: binary)
  -h, --help               Print help
```

If no `-k` is specified, uses the first available key. Multiple `-k` flags create a multi-key tresor.

### decrypt

```
ssh-tresor decrypt [OPTIONS] [INPUT]

Arguments:
  [INPUT]  Input file (default: stdin, use "-" explicitly for stdin)

Options:
  -o, --output <FILE>  Output file (default: stdout)
  -h, --help           Print help
```

Automatically tries all keys in the agent and uses the first matching slot.

### add-key

```
ssh-tresor add-key [OPTIONS] --key <FINGERPRINT> [INPUT]

Arguments:
  [INPUT]  Input tresor file (default: stdin)

Options:
  -k, --key <FINGERPRINT>  SSH key fingerprint to add
  -o, --output <FILE>      Output file (default: stdout)
  -a, --armor              Output as base64 with header/footer
  -h, --help               Print help
```

Requires access to an existing authorized key to decrypt the master key.

### remove-key

```
ssh-tresor remove-key [OPTIONS] --key <FINGERPRINT> [INPUT]

Arguments:
  [INPUT]  Input tresor file (default: stdin)

Options:
  -k, --key <FINGERPRINT>  SSH key fingerprint to remove
  -o, --output <FILE>      Output file (default: stdout)
  -a, --armor              Output as base64 with header/footer
  -h, --help               Print help
```

Cannot remove the last key from a tresor.

### list-slots

```
ssh-tresor list-slots [INPUT]

Arguments:
  [INPUT]  Input tresor file (default: stdin)

Options:
  -h, --help  Print help
```

Shows all key slots and marks which ones are available in the current agent.

### list-keys

```
ssh-tresor list-keys [OPTIONS]

Options:
  --md5       Show MD5 fingerprints (default: SHA256)
  -h, --help  Print help
```

Output format (one key per line):
```
SHA256:abc123... ED25519 user@host
SHA256:def456... RSA-4096 work-laptop
```

## Cryptographic Design

### Encryption Process (Multi-Key)

1. Connect to SSH agent via `SSH_AUTH_SOCK` environment variable
2. Select keys by fingerprint, or use first available key
3. Generate 32 random bytes as **master key**
4. For each selected SSH key:
   a. Generate 32 random bytes as challenge
   b. Request SSH agent to sign the challenge
   c. Derive slot key: `slot_key = HKDF-SHA256(signature, salt="ssh-tresor-v3", info="slot-key-derivation")`
   d. Generate 12 random bytes as slot nonce
   e. Encrypt master key using AES-256-GCM with slot key
5. Generate 12 random bytes as data nonce
6. Encrypt plaintext using AES-256-GCM with master key
7. Construct output blob (see Wire Format below)

### Decryption Process

1. Connect to SSH agent via `SSH_AUTH_SOCK`
2. Parse input blob, enumerate slots
3. For each key in agent:
   a. Check if a matching slot exists (by fingerprint)
   b. If found: sign the slot's challenge, derive slot key, decrypt master key
   c. If master key decryption succeeds, decrypt data and return
4. If no matching slot found, return error

### Security Properties

- **No key material on disk**: Private keys never leave the SSH agent
- **Deterministic key derivation**: Same challenge + same key = same signature = same AES key
- **Authenticated encryption**: AES-GCM provides confidentiality and integrity
- **Key binding**: Each slot is bound to a specific SSH key via fingerprint
- **Master key isolation**: Compromise of one slot key doesn't reveal other slot keys

### Signature Algorithm Selection

When requesting a signature from the agent:
- For RSA keys: Use `rsa-sha2-256` signature algorithm
- For Ed25519 keys: Use default `ssh-ed25519`
- For ECDSA keys: Use appropriate `ecdsa-sha2-*` variant

## Wire Format (v3)

**Note:** v3 uses HKDF-SHA256 for key derivation (v2 used plain SHA-256). v3 is not backwards-compatible with v2.

### Binary Format

```
+---------------------+
| Magic (8 bytes)     |  "SSHTRESR" (0x53 0x53 0x48 0x54 0x52 0x45 0x53 0x52)
+---------------------+
| Version (1 byte)    |  0x03
+---------------------+
| Slot count (1 byte) |  Number of key slots (1-255)
+---------------------+
| Slot 0              |  First key slot (124 bytes)
+---------------------+
| Slot 1              |  Second key slot (124 bytes)
+---------------------+
| ...                 |  Additional slots
+---------------------+
| Data nonce          |  AES-GCM nonce for data (12 bytes)
+---------------------+
| Ciphertext          |  AES-256-GCM encrypted data (variable)
|                     |  Includes 16-byte auth tag
+---------------------+
```

### Slot Format (124 bytes each)

```
+----------------------+
| Fingerprint (32)     |  SHA-256 fingerprint of public key
+----------------------+
| Challenge (32)       |  Random challenge signed by agent
+----------------------+
| Nonce (12)           |  AES-GCM nonce for master key encryption
+----------------------+
| Encrypted key (48)   |  Master key (32) + auth tag (16)
+----------------------+
```

### Size Calculation

- Header: 10 bytes (magic + version + slot count)
- Per slot: 124 bytes
- Data overhead: 12 bytes (nonce) + 16 bytes (auth tag)

Single-key tresor: 10 + 124 + 12 + 16 = 162 bytes + ciphertext
Three-key tresor: 10 + 372 + 12 + 16 = 410 bytes + ciphertext

### Armored Format

When `--armor` is specified, output is base64-encoded with header/footer:

```
-----BEGIN SSH TRESOR-----
U1NIVkFVTFQC... (base64-encoded binary blob)
-----END SSH TRESOR-----
```

Decryption automatically detects armored vs binary format.

## Dependencies

```toml
[dependencies]
ssh-agent-client-rs = "1.1"   # SSH agent protocol client
ssh-key = "0.6"               # SSH key types and fingerprinting
ssh-encoding = "0.2"          # SSH wire format encoding
aes-gcm = "0.10"              # AES-256-GCM encryption
sha2 = "0.10"                 # SHA-256 for HKDF
hkdf = "0.12"                 # HKDF-SHA256 for key derivation
rand = "0.8"                  # Cryptographically secure random
base64 = "0.22"               # Armored format encoding
clap = { version = "4", features = ["derive"] }  # CLI parsing
thiserror = "2"               # Error handling
md5 = "0.7"                   # MD5 fingerprint display
```

## Error Handling

Exit codes:
- `0`: Success
- `1`: General error (I/O, parsing)
- `2`: Agent connection failed (SSH_AUTH_SOCK not set, socket not accessible)
- `3`: Key not found (specified fingerprint not in agent, or no matching slot)
- `4`: Decryption failed (wrong key, corrupted data, tampered ciphertext)

Error messages should be written to stderr and be actionable:
```
Error: SSH agent not available
Hint: Is SSH_AUTH_SOCK set? Try running: eval $(ssh-agent) && ssh-add

Error: No matching slot found
Hint: None of the keys in your SSH agent can decrypt this tresor
```

## Testing Strategy

### Unit Tests
- Wire format serialization/deserialization roundtrip
- Slot format roundtrip
- Base64 armor/dearmor roundtrip
- Fingerprint parsing and matching
- Master key encryption/decryption

### Integration Tests
- Full encrypt/decrypt cycle with real agent
- Multi-key encrypt, decrypt with each key individually
- Add key to existing tresor
- Remove key from tresor
- Key selection by fingerprint
- Stdin/stdout operation
- File input/output operation
- Armored format roundtrip
- Error cases (no agent, key not found, no matching slot, corrupted input)
- Binary data and large files

### Manual Testing
- Verify interop with OpenSSH agent
- Verify interop with gpg-agent in SSH mode
- Test with RSA, Ed25519, and ECDSA keys
- Test over SSH with agent forwarding

## Future Considerations

- Key comment matching (`-k user@host` instead of fingerprint)
- Streaming encryption for large files
- FIDO2/hardware key support (if agent supports it)
- Integration with systemd credentials
- Shell completion scripts

## Example Session

```bash
# List available keys
$ ssh-tresor list-keys
SHA256:uNiVztksCsDhcc0u9e8BujQXVUpKZIDTMczCvj3tD2s ED25519 harald@workstation
SHA256:2bGQ+FN/wdGvPwRCJdBe8bMPgIQCk0j8Fq1XVfLbLHs RSA-4096 harald@backup

# Encrypt a password (uses first key by default)
$ echo -n "super-secret-password" | ssh-tresor encrypt -a
-----BEGIN SSH TRESOR-----
U1NIVkFVTFQCnxqK8mF3vR...
-----END SSH TRESOR-----

# Encrypt for multiple keys
$ echo -n "super-secret-password" | ssh-tresor encrypt -k SHA256:uNiV -k SHA256:2bGQ -o secret.tresor

# List slots in a tresor
$ ssh-tresor list-slots secret.tresor
Vault contains 2 key slot(s):
  Slot 1: SHA256:uNiVztksCsDhcc0u9e8BujQXVUpKZIDTMczCvj3tD2s ED25519 harald@workstation [AVAILABLE]
  Slot 2: SHA256:2bGQ+FN/wdGvPwRCJdBe8bMPgIQCk0j8Fq1XVfLbLHs RSA-4096 harald@backup [AVAILABLE]

# Decrypt (auto-detects matching key)
$ ssh-tresor decrypt secret.tresor
super-secret-password

# Add another key to existing tresor
$ ssh-tresor add-key -k SHA256:newkey < secret.tresor > updated.tresor

# Remove a key from tresor
$ ssh-tresor remove-key -k SHA256:2bGQ < secret.tresor > reduced.tresor

# Use in a password command
$ ssh-tresor decrypt ~/.secrets/mail.tresor | xargs -0 some-command
```

## Project Structure

```
ssh-tresor/
├── Cargo.toml
├── CLAUDE.md             # Claude Code guidance
├── src/
│   ├── main.rs           # CLI entry point, argument parsing
│   ├── lib.rs            # Public API (encrypt, decrypt, add_key, remove_key, list_slots, list_keys)
│   ├── agent.rs          # SSH agent connection and protocol
│   ├── crypto.rs         # Key derivation, master key, and AES-GCM operations
│   ├── format.rs         # Wire format: TresorBlob, Slot serialization
│   └── error.rs          # Error types with exit codes
├── tests/
│   ├── integration.sh    # Shell-based integration tests
│   └── integration_runner.rs  # Cargo test runner for integration tests
└── .github/
    └── workflows/
        └── ci.yml        # GitHub Actions CI
```

## References

- SSH Agent Protocol: https://datatracker.ietf.org/doc/html/draft-miller-ssh-agent
- AES-GCM: NIST SP 800-38D
- ssh-crypt (Python reference): https://github.com/Sets88/ssh-crypt
- Rust ssh-key crate: https://docs.rs/ssh-key
