use crate::error::{Error, Result};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};

/// Magic header bytes: "SSHTRESR"
pub const MAGIC: &[u8; 8] = b"SSHTRESR";

/// Current format version
pub const VERSION: u8 = 0x03;

/// Size constants
pub const FINGERPRINT_SIZE: usize = 32;
pub const CHALLENGE_SIZE: usize = 32;
pub const NONCE_SIZE: usize = 12;
pub const AUTH_TAG_SIZE: usize = 16;
pub const MASTER_KEY_SIZE: usize = 32;
pub const ENCRYPTED_KEY_SIZE: usize = MASTER_KEY_SIZE + AUTH_TAG_SIZE; // 48 bytes

/// Slot size: fingerprint (32) + challenge (32) + nonce (12) + encrypted key (48) = 124
pub const SLOT_SIZE: usize = FINGERPRINT_SIZE + CHALLENGE_SIZE + NONCE_SIZE + ENCRYPTED_KEY_SIZE;

/// Header size: magic (8) + version (1) + slot_count (1) = 10
pub const HEADER_SIZE: usize = 10;

/// Maximum tresor file size (100 MB) to prevent DoS via memory exhaustion
pub const MAX_TRESOR_SIZE: usize = 100 * 1024 * 1024;

const ARMOR_BEGIN: &str = "-----BEGIN SSH TRESOR-----";
const ARMOR_END: &str = "-----END SSH TRESOR-----";

/// A single key slot that can decrypt the master key
#[derive(Debug, Clone)]
pub struct Slot {
    /// SHA-256 fingerprint of the public key (raw 32 bytes)
    pub fingerprint: [u8; FINGERPRINT_SIZE],
    /// Random challenge that was signed by the SSH agent
    pub challenge: [u8; CHALLENGE_SIZE],
    /// AES-GCM nonce for encrypting the master key
    pub nonce: [u8; NONCE_SIZE],
    /// Encrypted master key (32 bytes) + auth tag (16 bytes)
    pub encrypted_key: [u8; ENCRYPTED_KEY_SIZE],
}

impl Slot {
    /// Serialize slot to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut output = Vec::with_capacity(SLOT_SIZE);
        output.extend_from_slice(&self.fingerprint);
        output.extend_from_slice(&self.challenge);
        output.extend_from_slice(&self.nonce);
        output.extend_from_slice(&self.encrypted_key);
        output
    }

    /// Parse slot from bytes
    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        if data.len() < SLOT_SIZE {
            return Err(Error::InvalidFormat(format!(
                "slot data too short: {} bytes, need {}",
                data.len(),
                SLOT_SIZE
            )));
        }

        let mut fingerprint = [0u8; FINGERPRINT_SIZE];
        fingerprint.copy_from_slice(&data[0..FINGERPRINT_SIZE]);

        let mut challenge = [0u8; CHALLENGE_SIZE];
        challenge.copy_from_slice(&data[FINGERPRINT_SIZE..FINGERPRINT_SIZE + CHALLENGE_SIZE]);

        let mut nonce = [0u8; NONCE_SIZE];
        nonce.copy_from_slice(
            &data
                [FINGERPRINT_SIZE + CHALLENGE_SIZE..FINGERPRINT_SIZE + CHALLENGE_SIZE + NONCE_SIZE],
        );

        let mut encrypted_key = [0u8; ENCRYPTED_KEY_SIZE];
        encrypted_key.copy_from_slice(
            &data[FINGERPRINT_SIZE + CHALLENGE_SIZE + NONCE_SIZE
                ..FINGERPRINT_SIZE + CHALLENGE_SIZE + NONCE_SIZE + ENCRYPTED_KEY_SIZE],
        );

        Ok(Slot {
            fingerprint,
            challenge,
            nonce,
            encrypted_key,
        })
    }
}

/// Represents the parsed components of an encrypted tresor with multi-key support
#[derive(Debug, Clone)]
pub struct TresorBlob {
    /// Key slots (1-255)
    pub slots: Vec<Slot>,
    /// AES-GCM nonce for the data
    pub data_nonce: [u8; NONCE_SIZE],
    /// Ciphertext including authentication tag
    pub ciphertext: Vec<u8>,
}

impl TresorBlob {
    /// Serialize the vault blob to binary format
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        if self.slots.is_empty() {
            return Err(Error::InvalidFormat("tresor has no key slots".to_string()));
        }
        if self.slots.len() > 255 {
            return Err(Error::InvalidFormat(
                "tresor has too many slots (max 255)".to_string(),
            ));
        }

        let slot_count = self.slots.len() as u8;
        let total_size =
            HEADER_SIZE + (self.slots.len() * SLOT_SIZE) + NONCE_SIZE + self.ciphertext.len();

        let mut output = Vec::with_capacity(total_size);
        output.extend_from_slice(MAGIC);
        output.push(VERSION);
        output.push(slot_count);

        for slot in &self.slots {
            output.extend_from_slice(&slot.to_bytes());
        }

        output.extend_from_slice(&self.data_nonce);
        output.extend_from_slice(&self.ciphertext);
        Ok(output)
    }

    /// Serialize to armored (base64 with headers) format
    pub fn to_armored(&self) -> Result<String> {
        let binary = self.to_bytes()?;
        let encoded = BASE64.encode(&binary);

        // Wrap at 64 characters
        let wrapped: Vec<&str> = encoded
            .as_bytes()
            .chunks(64)
            .map(|chunk| std::str::from_utf8(chunk).unwrap())
            .collect();

        Ok(format!(
            "{}\n{}\n{}\n",
            ARMOR_BEGIN,
            wrapped.join("\n"),
            ARMOR_END
        ))
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
        // Minimum: header (10) + 1 slot (124) + data nonce (12) + auth tag (16)
        let min_size = HEADER_SIZE + SLOT_SIZE + NONCE_SIZE + AUTH_TAG_SIZE;
        if data.len() < min_size {
            return Err(Error::InvalidFormat(format!(
                "data too short: {} bytes, minimum {} required",
                data.len(),
                min_size
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

        let slot_count = data[9] as usize;
        if slot_count == 0 {
            return Err(Error::InvalidFormat("tresor has no key slots".to_string()));
        }

        let slots_end = HEADER_SIZE + (slot_count * SLOT_SIZE);
        if data.len() < slots_end + NONCE_SIZE + AUTH_TAG_SIZE {
            return Err(Error::InvalidFormat(format!(
                "data too short for {} slots",
                slot_count
            )));
        }

        // Parse slots
        let mut slots = Vec::with_capacity(slot_count);
        for i in 0..slot_count {
            let slot_start = HEADER_SIZE + (i * SLOT_SIZE);
            let slot = Slot::from_bytes(&data[slot_start..slot_start + SLOT_SIZE])?;
            slots.push(slot);
        }

        // Parse data nonce
        let mut data_nonce = [0u8; NONCE_SIZE];
        data_nonce.copy_from_slice(&data[slots_end..slots_end + NONCE_SIZE]);

        // Rest is ciphertext
        let ciphertext = data[slots_end + NONCE_SIZE..].to_vec();

        Ok(TresorBlob {
            slots,
            data_nonce,
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

    /// Find a slot by fingerprint bytes
    pub fn find_slot(&self, fingerprint: &[u8; FINGERPRINT_SIZE]) -> Option<&Slot> {
        self.slots.iter().find(|s| &s.fingerprint == fingerprint)
    }

    /// Get fingerprints of all slots
    pub fn slot_fingerprints(&self) -> Vec<[u8; FINGERPRINT_SIZE]> {
        self.slots.iter().map(|s| s.fingerprint).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_test_slot(id: u8) -> Slot {
        Slot {
            fingerprint: [id; FINGERPRINT_SIZE],
            challenge: [id + 1; CHALLENGE_SIZE],
            nonce: [id + 2; NONCE_SIZE],
            encrypted_key: [id + 3; ENCRYPTED_KEY_SIZE],
        }
    }

    #[test]
    fn test_slot_roundtrip() {
        let slot = make_test_slot(0x42);
        let bytes = slot.to_bytes();
        assert_eq!(bytes.len(), SLOT_SIZE);

        let parsed = Slot::from_bytes(&bytes).unwrap();
        assert_eq!(parsed.fingerprint, slot.fingerprint);
        assert_eq!(parsed.challenge, slot.challenge);
        assert_eq!(parsed.nonce, slot.nonce);
        assert_eq!(parsed.encrypted_key, slot.encrypted_key);
    }

    #[test]
    fn test_roundtrip_binary_single_slot() {
        // Ciphertext must include auth tag (16 bytes minimum)
        let blob = TresorBlob {
            slots: vec![make_test_slot(0x42)],
            data_nonce: [0x37; NONCE_SIZE],
            ciphertext: vec![0xde; AUTH_TAG_SIZE + 4], // 20 bytes: 4 data + 16 auth tag
        };

        let bytes = blob.to_bytes().unwrap();
        let parsed = TresorBlob::from_bytes(&bytes).unwrap();

        assert_eq!(parsed.slots.len(), 1);
        assert_eq!(parsed.slots[0].fingerprint, blob.slots[0].fingerprint);
        assert_eq!(parsed.data_nonce, blob.data_nonce);
        assert_eq!(parsed.ciphertext, blob.ciphertext);
    }

    #[test]
    fn test_roundtrip_binary_multiple_slots() {
        let blob = TresorBlob {
            slots: vec![
                make_test_slot(0x01),
                make_test_slot(0x02),
                make_test_slot(0x03),
            ],
            data_nonce: [0x37; NONCE_SIZE],
            ciphertext: vec![0xde; AUTH_TAG_SIZE + 4],
        };

        let bytes = blob.to_bytes().unwrap();
        let parsed = TresorBlob::from_bytes(&bytes).unwrap();

        assert_eq!(parsed.slots.len(), 3);
        for i in 0..3 {
            assert_eq!(parsed.slots[i].fingerprint, blob.slots[i].fingerprint);
        }
    }

    #[test]
    fn test_roundtrip_armored() {
        let blob = TresorBlob {
            slots: vec![make_test_slot(0x42), make_test_slot(0x43)],
            data_nonce: [0x37; NONCE_SIZE],
            ciphertext: vec![0xde; AUTH_TAG_SIZE + 4],
        };

        let armored = blob.to_armored().unwrap();
        assert!(armored.starts_with(ARMOR_BEGIN));
        assert!(armored.trim().ends_with(ARMOR_END));

        let parsed = TresorBlob::from_bytes(armored.as_bytes()).unwrap();

        assert_eq!(parsed.slots.len(), 2);
        assert_eq!(parsed.data_nonce, blob.data_nonce);
        assert_eq!(parsed.ciphertext, blob.ciphertext);
    }

    #[test]
    fn test_find_slot() {
        let blob = TresorBlob {
            slots: vec![make_test_slot(0x01), make_test_slot(0x02)],
            data_nonce: [0x37; NONCE_SIZE],
            ciphertext: vec![0xde; AUTH_TAG_SIZE],
        };

        let fp1 = [0x01u8; FINGERPRINT_SIZE];
        let fp2 = [0x02u8; FINGERPRINT_SIZE];
        let fp3 = [0x03u8; FINGERPRINT_SIZE];

        assert!(blob.find_slot(&fp1).is_some());
        assert!(blob.find_slot(&fp2).is_some());
        assert!(blob.find_slot(&fp3).is_none());
    }

    #[test]
    fn test_invalid_magic() {
        let mut data = vec![0u8; HEADER_SIZE + SLOT_SIZE + NONCE_SIZE + AUTH_TAG_SIZE];
        data[0..8].copy_from_slice(b"NOTVALID");

        let result = TresorBlob::from_bytes(&data);
        assert!(matches!(result, Err(Error::InvalidFormat(_))));
    }

    #[test]
    fn test_data_too_short() {
        let data = vec![0u8; 50];
        let result = TresorBlob::from_bytes(&data);
        assert!(matches!(result, Err(Error::InvalidFormat(_))));
    }

    #[test]
    fn test_zero_slots_rejected() {
        let mut data = vec![0u8; HEADER_SIZE + NONCE_SIZE + AUTH_TAG_SIZE];
        data[0..8].copy_from_slice(MAGIC);
        data[8] = VERSION;
        data[9] = 0; // zero slots

        let result = TresorBlob::from_bytes(&data);
        assert!(matches!(result, Err(Error::InvalidFormat(_))));
    }
}
