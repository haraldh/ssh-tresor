use crate::error::{Error, Result};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};

/// Magic header bytes: "SSHVAULT"
pub const MAGIC: &[u8; 8] = b"SSHVAULT";

/// Current format version
pub const VERSION: u8 = 0x01;

/// Size constants
pub const FINGERPRINT_SIZE: usize = 32;
pub const CHALLENGE_SIZE: usize = 32;
pub const NONCE_SIZE: usize = 12;
pub const AUTH_TAG_SIZE: usize = 16;

/// Header size: magic (8) + version (1) + fingerprint (32) + challenge (32) + nonce (12) = 85
pub const HEADER_SIZE: usize = 8 + 1 + FINGERPRINT_SIZE + CHALLENGE_SIZE + NONCE_SIZE;

/// Total overhead: header (85) + auth tag (16) = 101
pub const OVERHEAD: usize = HEADER_SIZE + AUTH_TAG_SIZE;

const ARMOR_BEGIN: &str = "-----BEGIN SSH TRESOR-----";
const ARMOR_END: &str = "-----END SSH TRESOR-----";

/// Represents the parsed components of an encrypted vault
#[derive(Debug, Clone)]
pub struct VaultBlob {
    /// SHA-256 fingerprint of the public key (raw 32 bytes)
    pub fingerprint: [u8; FINGERPRINT_SIZE],
    /// Random challenge that was signed by the SSH agent
    pub challenge: [u8; CHALLENGE_SIZE],
    /// AES-GCM nonce
    pub nonce: [u8; NONCE_SIZE],
    /// Ciphertext including authentication tag
    pub ciphertext: Vec<u8>,
}

impl VaultBlob {
    /// Serialize the vault blob to binary format
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut output = Vec::with_capacity(HEADER_SIZE + self.ciphertext.len());
        output.extend_from_slice(MAGIC);
        output.push(VERSION);
        output.extend_from_slice(&self.fingerprint);
        output.extend_from_slice(&self.challenge);
        output.extend_from_slice(&self.nonce);
        output.extend_from_slice(&self.ciphertext);
        output
    }

    /// Serialize to armored (base64 with headers) format
    pub fn to_armored(&self) -> String {
        let binary = self.to_bytes();
        let encoded = BASE64.encode(&binary);

        // Wrap at 64 characters
        let wrapped: Vec<&str> = encoded
            .as_bytes()
            .chunks(64)
            .map(|chunk| std::str::from_utf8(chunk).unwrap())
            .collect();

        format!("{}\n{}\n{}\n", ARMOR_BEGIN, wrapped.join("\n"), ARMOR_END)
    }

    /// Parse from bytes (auto-detects armored vs binary format)
    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        // Check if it's armored format
        if let Ok(text) = std::str::from_utf8(data) {
            if text.trim().starts_with(ARMOR_BEGIN) {
                return Self::from_armored(text);
            }
        }

        Self::from_binary(data)
    }

    /// Parse from binary format
    fn from_binary(data: &[u8]) -> Result<Self> {
        // Require at least the header; auth tag validation happens during decryption
        if data.len() < HEADER_SIZE {
            return Err(Error::InvalidFormat(format!(
                "data too short: {} bytes, minimum {} required",
                data.len(),
                HEADER_SIZE
            )));
        }

        // Check magic
        if &data[0..8] != MAGIC {
            return Err(Error::InvalidFormat("invalid magic header".to_string()));
        }

        // Check version
        let version = data[8];
        if version != VERSION {
            return Err(Error::InvalidFormat(format!(
                "unsupported version: {}, expected {}",
                version, VERSION
            )));
        }

        let mut fingerprint = [0u8; FINGERPRINT_SIZE];
        fingerprint.copy_from_slice(&data[9..9 + FINGERPRINT_SIZE]);

        let mut challenge = [0u8; CHALLENGE_SIZE];
        challenge.copy_from_slice(&data[9 + FINGERPRINT_SIZE..9 + FINGERPRINT_SIZE + CHALLENGE_SIZE]);

        let mut nonce = [0u8; NONCE_SIZE];
        nonce.copy_from_slice(
            &data[9 + FINGERPRINT_SIZE + CHALLENGE_SIZE
                ..9 + FINGERPRINT_SIZE + CHALLENGE_SIZE + NONCE_SIZE],
        );

        let ciphertext = data[HEADER_SIZE..].to_vec();

        Ok(VaultBlob {
            fingerprint,
            challenge,
            nonce,
            ciphertext,
        })
    }

    /// Parse from armored format
    fn from_armored(text: &str) -> Result<Self> {
        let text = text.trim();

        // Find and validate header/footer
        let start = text
            .find(ARMOR_BEGIN)
            .ok_or_else(|| Error::InvalidFormat("missing BEGIN header".to_string()))?;
        let end = text
            .find(ARMOR_END)
            .ok_or_else(|| Error::InvalidFormat("missing END footer".to_string()))?;

        if start >= end {
            return Err(Error::InvalidFormat("invalid armor structure".to_string()));
        }

        // Extract base64 content between headers
        let content_start = start + ARMOR_BEGIN.len();
        let base64_content: String = text[content_start..end]
            .chars()
            .filter(|c| !c.is_whitespace())
            .collect();

        let binary = BASE64.decode(&base64_content)?;
        Self::from_binary(&binary)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_roundtrip_binary() {
        let blob = VaultBlob {
            fingerprint: [0x42; FINGERPRINT_SIZE],
            challenge: [0x13; CHALLENGE_SIZE],
            nonce: [0x37; NONCE_SIZE],
            ciphertext: vec![0xde, 0xad, 0xbe, 0xef],
        };

        let bytes = blob.to_bytes();
        let parsed = VaultBlob::from_bytes(&bytes).unwrap();

        assert_eq!(parsed.fingerprint, blob.fingerprint);
        assert_eq!(parsed.challenge, blob.challenge);
        assert_eq!(parsed.nonce, blob.nonce);
        assert_eq!(parsed.ciphertext, blob.ciphertext);
    }

    #[test]
    fn test_roundtrip_armored() {
        let blob = VaultBlob {
            fingerprint: [0x42; FINGERPRINT_SIZE],
            challenge: [0x13; CHALLENGE_SIZE],
            nonce: [0x37; NONCE_SIZE],
            ciphertext: vec![0xde, 0xad, 0xbe, 0xef],
        };

        let armored = blob.to_armored();
        assert!(armored.starts_with(ARMOR_BEGIN));
        assert!(armored.trim().ends_with(ARMOR_END));

        let parsed = VaultBlob::from_bytes(armored.as_bytes()).unwrap();

        assert_eq!(parsed.fingerprint, blob.fingerprint);
        assert_eq!(parsed.challenge, blob.challenge);
        assert_eq!(parsed.nonce, blob.nonce);
        assert_eq!(parsed.ciphertext, blob.ciphertext);
    }

    #[test]
    fn test_invalid_magic() {
        let mut data = vec![0u8; OVERHEAD + 10];
        data[0..8].copy_from_slice(b"NOTVALID");

        let result = VaultBlob::from_bytes(&data);
        assert!(matches!(result, Err(Error::InvalidFormat(_))));
    }

    #[test]
    fn test_data_too_short() {
        let data = vec![0u8; 50];
        let result = VaultBlob::from_bytes(&data);
        assert!(matches!(result, Err(Error::InvalidFormat(_))));
    }
}
