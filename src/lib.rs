//! ssh-vault: SSH Agent-Based Secret Encryption
//!
//! This library provides functionality to encrypt and decrypt secrets using
//! keys held in an SSH agent. It derives encryption keys by asking the SSH
//! agent to sign a random nonce, then uses the signature as key material
//! for symmetric encryption (AES-256-GCM).

pub mod agent;
pub mod crypto;
pub mod error;
pub mod format;

pub use agent::{AgentConnection, AgentKey};
pub use error::{Error, Result};
pub use format::VaultBlob;

/// Encrypt data using an SSH key from the agent
///
/// # Arguments
/// * `plaintext` - The data to encrypt
/// * `fingerprint` - Optional fingerprint prefix to select a specific key.
///                   If None, uses the first available key.
///
/// # Returns
/// A `VaultBlob` containing the encrypted data and metadata needed for decryption.
pub fn encrypt(plaintext: &[u8], fingerprint: Option<&str>) -> Result<VaultBlob> {
    let mut agent = AgentConnection::connect()?;

    // Select the key to use
    let key = match fingerprint {
        Some(fp) => agent.find_key(fp)?,
        None => agent.first_key()?,
    };

    encrypt_with_key(&mut agent, &key, plaintext)
}

/// Encrypt data using a specific key
fn encrypt_with_key(
    agent: &mut AgentConnection,
    key: &AgentKey,
    plaintext: &[u8],
) -> Result<VaultBlob> {
    // Generate random challenge
    let challenge = crypto::generate_challenge();

    // Request agent to sign the challenge
    let signature = agent.sign(key, &challenge)?;

    // Derive AES key from signature
    let aes_key = agent::derive_key_from_signature(&signature);

    // Generate random nonce for AES-GCM
    let nonce = crypto::generate_nonce();

    // Encrypt the plaintext
    let ciphertext = crypto::encrypt(&aes_key, &nonce, plaintext)?;

    Ok(VaultBlob {
        fingerprint: key.fingerprint_bytes,
        challenge,
        nonce,
        ciphertext,
    })
}

/// Decrypt a vault blob using the SSH agent
///
/// # Arguments
/// * `blob` - The encrypted vault blob
///
/// # Returns
/// The decrypted plaintext data.
pub fn decrypt(blob: &VaultBlob) -> Result<Vec<u8>> {
    let mut agent = AgentConnection::connect()?;

    // Find the key that was used for encryption
    let key = agent.find_key_by_bytes(&blob.fingerprint)?;

    decrypt_with_key(&mut agent, &key, blob)
}

/// Decrypt using a specific key
fn decrypt_with_key(
    agent: &mut AgentConnection,
    key: &AgentKey,
    blob: &VaultBlob,
) -> Result<Vec<u8>> {
    // Request agent to sign the stored challenge
    let signature = agent.sign(key, &blob.challenge)?;

    // Derive AES key from signature (should be the same as during encryption)
    let aes_key = agent::derive_key_from_signature(&signature);

    // Decrypt the ciphertext
    crypto::decrypt(&aes_key, &blob.nonce, &blob.ciphertext)
}

/// List all keys available in the SSH agent
pub fn list_keys() -> Result<Vec<AgentKey>> {
    let mut agent = AgentConnection::connect()?;
    agent.list_keys()
}
