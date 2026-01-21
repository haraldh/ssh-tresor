# ssh-tresor

Encrypt and decrypt secrets using SSH agent keys.

ssh-tresor derives encryption keys by asking the SSH agent to sign a challenge, then uses the signature as key material for AES-256-GCM encryption. Secrets can only be decrypted when the corresponding SSH key is loaded in an agent—no passphrase prompts required.

## Features

- **No key material on disk** – private keys never leave the SSH agent
- **Multi-key support** – encrypt for multiple SSH keys (LUKS-style slots)
- **Works over SSH** – seamless with agent forwarding (`ssh -A`)
- **Armored output** – optional base64 format with headers

## Installation

```bash
cargo install ssh-tresor
```

Or build from source:

```bash
git clone https://github.com/haraldh/ssh-tresor
cd ssh-tresor
cargo build --release
```

### Nix

Run directly:

```bash
nix run github:haraldh/ssh-tresor -- --help
```

Or add to your flake:

```nix
{
  inputs.ssh-tresor.url = "github:haraldh/ssh-tresor";

  outputs = { nixpkgs, ssh-tresor, ... }: {
    nixosConfigurations.myhost = nixpkgs.lib.nixosSystem {
      modules = [{
        nixpkgs.overlays = [ ssh-tresor.overlays.default ];
        environment.systemPackages = with pkgs; [ ssh-tresor ];
      }];
    };
  };
}
```

## Usage

```bash
# List available keys in agent
ssh-tresor list-keys

# Encrypt (uses first available key)
echo -n "secret" | ssh-tresor encrypt -a > secret.tresor

# Encrypt for multiple keys
echo -n "secret" | ssh-tresor encrypt -k SHA256:abc -k SHA256:def -o secret.tresor

# Decrypt (auto-detects matching key)
ssh-tresor decrypt secret.tresor

# List keys that can decrypt a tresor
ssh-tresor list-slots secret.tresor

# Add a key to existing tresor
ssh-tresor add-key -k SHA256:newkey < secret.tresor > updated.tresor

# Add all available keys from agent
ssh-tresor add-key --all < secret.tresor > updated.tresor

# Modify tresor in-place
ssh-tresor add-key -i -k SHA256:newkey secret.tresor
ssh-tresor add-key -ia secret.tresor  # add all keys in-place

# Remove a key from tresor
ssh-tresor remove-key -k SHA256:oldkey < secret.tresor > updated.tresor
ssh-tresor remove-key -i -k SHA256:oldkey secret.tresor  # in-place
```

## Use Cases

Store encrypted credentials in config files, decrypted automatically when your SSH key is available:

```toml
# ~/.config/meli/config.toml
server_password_command = "ssh-tresor decrypt ~/.config/meli/imap.tresor"
```

Use with Claude Code to securely store your API key:

```bash
# Encrypt your API key
echo -n "sk-ant-..." | ssh-tresor encrypt -a > ~/.config/claude/api-key.tresor

# Configure Claude Code (~/.claude/settings.json)
{
  "apiKeyHelper": "ssh-tresor decrypt ~/.config/claude/api-key.tresor"
}
```

## Wire Format (v3)

```
Header:     SSHTRESR (8) + version (1) + slot_count (1)
Slots[]:    fingerprint (32) + challenge (32) + nonce (12) + encrypted_key (48)
Data:       nonce (12) + ciphertext (variable, includes 16-byte auth tag)
```

Each slot encrypts the same master key using a different SSH key. The master key encrypts the actual data. Key derivation uses HKDF-SHA256 for improved security.

## License

MIT OR Apache-2.0
