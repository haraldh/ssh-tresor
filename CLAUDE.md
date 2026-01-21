# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Build Commands

```bash
cargo build                    # Debug build
cargo build --release          # Release build
cargo test --lib               # Unit tests only
cargo test --test integration  # Integration tests (requires ssh-agent)
cargo test                     # All tests
cargo fmt                      # Format code
cargo clippy                   # Lint
```

## Architecture

ssh-tresor encrypts secrets using SSH agent keys. It derives AES-256 keys by having the agent sign a challenge, then uses the signature as key material.

**Multi-key support (LUKS-style slots):** A tresor can have multiple key slots. Each slot encrypts the same master key using a different SSH key. The master key encrypts the actual data.

### Wire Format (v3)

```
Header:     magic (8) + version (1) + slot_count (1)
Slots[]:    fingerprint (32) + challenge (32) + nonce (12) + encrypted_master_key (48)
Data:       nonce (12) + ciphertext (variable, includes 16-byte auth tag)
```

### Module Structure

- **main.rs** - CLI with clap: `encrypt`, `decrypt`, `add-key`, `remove-key`, `list-slots`, `list-keys`
- **lib.rs** - Public API: `encrypt()`, `decrypt()`, `add_key()`, `remove_key()`, `list_slots()`, `list_keys()`
- **agent.rs** - SSH agent connection via `SSH_AUTH_SOCK`, key listing, signing
- **crypto.rs** - AES-256-GCM encryption, master key generation, key derivation from signatures
- **format.rs** - `TresorBlob` and `Slot` serialization/deserialization, armored format
- **error.rs** - Error types with exit codes (0=success, 2=agent, 3=key not found, 4=decrypt fail)

### Key Flow

**Encrypt:** Generate master key → For each SSH key: sign challenge, derive slot key, encrypt master key → Encrypt data with master key

**Decrypt:** For each agent key: check if slot exists → sign challenge, derive slot key, decrypt master key → Decrypt data with master key

## Git Commits

This project uses [Conventional Commits](https://www.conventionalcommits.org/). All commits **must** follow this format:

```
<type>[optional scope]: <description>

[optional body]

[optional footer(s)]
```

**Types:**
- `feat:` - New feature
- `fix:` - Bug fix
- `docs:` - Documentation only
- `refactor:` - Code change that neither fixes a bug nor adds a feature
- `test:` - Adding or updating tests
- `chore:` - Maintenance tasks (deps, CI, etc.)
- `perf:` - Performance improvement

**Breaking Changes:**
Breaking changes **must** be annotated using one of these methods:
- Add `!` after the type: `feat!: remove deprecated API`
- Add a `BREAKING CHANGE:` footer in the commit body

This triggers a major version bump in release-please.

**Examples:**
```
feat: add support for ECDSA keys
fix: handle empty input gracefully
docs: add README for crates.io
chore: update dependencies

feat!: change default encryption algorithm

feat: new wire format

BREAKING CHANGE: v2 format is not compatible with v1
```
