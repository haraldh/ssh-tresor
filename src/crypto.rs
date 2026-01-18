use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use rand::RngCore;

use crate::error::{Error, Result};
use crate::format::{CHALLENGE_SIZE, MASTER_KEY_SIZE, NONCE_SIZE};

/// Generate a random challenge for the SSH agent to sign
pub fn generate_challenge() -> [u8; CHALLENGE_SIZE] {
    let mut challenge = [0u8; CHALLENGE_SIZE];
    rand::thread_rng().fill_bytes(&mut challenge);
    challenge
}

/// Generate a random nonce for AES-GCM
pub fn generate_nonce() -> [u8; NONCE_SIZE] {
    let mut nonce = [0u8; NONCE_SIZE];
    rand::thread_rng().fill_bytes(&mut nonce);
    nonce
}

/// Generate a random master key
pub fn generate_master_key() -> [u8; MASTER_KEY_SIZE] {
    let mut key = [0u8; MASTER_KEY_SIZE];
    rand::thread_rng().fill_bytes(&mut key);
    key
}

/// Encrypt plaintext using AES-256-GCM
pub fn encrypt(key: &[u8; 32], nonce: &[u8; NONCE_SIZE], plaintext: &[u8]) -> Result<Vec<u8>> {
    let cipher = Aes256Gcm::new_from_slice(key).expect("key size is correct");
    let nonce = Nonce::from_slice(nonce);

    cipher
        .encrypt(nonce, plaintext)
        .map_err(|e| Error::DecryptionFailed(format!("encryption failed: {}", e)))
}

/// Decrypt ciphertext using AES-256-GCM
pub fn decrypt(key: &[u8; 32], nonce: &[u8; NONCE_SIZE], ciphertext: &[u8]) -> Result<Vec<u8>> {
    let cipher = Aes256Gcm::new_from_slice(key).expect("key size is correct");
    let nonce = Nonce::from_slice(nonce);

    cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| Error::DecryptionFailed("authentication failed - wrong key or corrupted data".to_string()))
}

/// Encrypt a master key for storage in a slot
pub fn encrypt_master_key(
    slot_key: &[u8; 32],
    nonce: &[u8; NONCE_SIZE],
    master_key: &[u8; MASTER_KEY_SIZE],
) -> Result<Vec<u8>> {
    encrypt(slot_key, nonce, master_key)
}

/// Decrypt a master key from a slot
pub fn decrypt_master_key(
    slot_key: &[u8; 32],
    nonce: &[u8; NONCE_SIZE],
    encrypted_key: &[u8],
) -> Result<[u8; MASTER_KEY_SIZE]> {
    let decrypted = decrypt(slot_key, nonce, encrypted_key)?;

    if decrypted.len() != MASTER_KEY_SIZE {
        return Err(Error::DecryptionFailed(format!(
            "invalid master key size: {} bytes, expected {}",
            decrypted.len(),
            MASTER_KEY_SIZE
        )));
    }

    let mut key = [0u8; MASTER_KEY_SIZE];
    key.copy_from_slice(&decrypted);
    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let key = [0x42u8; 32];
        let nonce = generate_nonce();
        let plaintext = b"Hello, World!";

        let ciphertext = encrypt(&key, &nonce, plaintext).unwrap();
        let decrypted = decrypt(&key, &nonce, &ciphertext).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_wrong_key_fails() {
        let key1 = [0x42u8; 32];
        let key2 = [0x43u8; 32];
        let nonce = generate_nonce();
        let plaintext = b"Hello, World!";

        let ciphertext = encrypt(&key1, &nonce, plaintext).unwrap();
        let result = decrypt(&key2, &nonce, &ciphertext);

        assert!(result.is_err());
    }

    #[test]
    fn test_tampered_ciphertext_fails() {
        let key = [0x42u8; 32];
        let nonce = generate_nonce();
        let plaintext = b"Hello, World!";

        let mut ciphertext = encrypt(&key, &nonce, plaintext).unwrap();
        // Tamper with the ciphertext
        ciphertext[0] ^= 0xff;

        let result = decrypt(&key, &nonce, &ciphertext);
        assert!(result.is_err());
    }

    #[test]
    fn test_challenge_is_random() {
        let c1 = generate_challenge();
        let c2 = generate_challenge();
        assert_ne!(c1, c2);
    }

    #[test]
    fn test_nonce_is_random() {
        let n1 = generate_nonce();
        let n2 = generate_nonce();
        assert_ne!(n1, n2);
    }

    #[test]
    fn test_master_key_is_random() {
        let k1 = generate_master_key();
        let k2 = generate_master_key();
        assert_ne!(k1, k2);
    }

    #[test]
    fn test_master_key_roundtrip() {
        let slot_key = [0x42u8; 32];
        let nonce = generate_nonce();
        let master_key = generate_master_key();

        let encrypted = encrypt_master_key(&slot_key, &nonce, &master_key).unwrap();
        let decrypted = decrypt_master_key(&slot_key, &nonce, &encrypted).unwrap();

        assert_eq!(decrypted, master_key);
    }
}
