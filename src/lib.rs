//! ssh-tresor: SSH Agent-Based Secret Encryption
//!
//! This library provides functionality to encrypt and decrypt secrets using
//! keys held in an SSH agent. It supports multiple keys per tresor (LUKS-style slots),
//! where each slot encrypts a master key that in turn encrypts the data.

pub mod agent;
pub mod crypto;
pub mod error;
pub mod format;

use zeroize::Zeroizing;

pub use agent::{AgentConnection, AgentKey};
pub use error::{Error, Result};
pub use format::{Slot, TresorBlob};

/// Encrypt data using SSH keys from the agent
///
/// # Arguments
/// * `plaintext` - The data to encrypt
/// * `fingerprints` - Fingerprint prefixes to select keys. If empty, uses the first available key.
///
/// # Returns
/// A `TresorBlob` containing the encrypted data and slots for each key.
pub fn encrypt(plaintext: &[u8], fingerprints: &[&str]) -> Result<TresorBlob> {
    let mut agent = AgentConnection::connect()?;

    // Collect keys to use
    let keys: Vec<AgentKey> = if fingerprints.is_empty() {
        vec![agent.first_key()?]
    } else {
        fingerprints
            .iter()
            .map(|fp| agent.find_key(fp))
            .collect::<Result<Vec<_>>>()?
    };

    encrypt_with_keys(&mut agent, &keys, plaintext)
}

/// Encrypt data using specific keys
fn encrypt_with_keys(
    agent: &mut AgentConnection,
    keys: &[AgentKey],
    plaintext: &[u8],
) -> Result<TresorBlob> {
    // Generate master key (zeroized on drop)
    let master_key = crypto::generate_master_key();

    // Create a slot for each key
    let mut slots = Vec::with_capacity(keys.len());
    for key in keys {
        let slot = create_slot(agent, key, &master_key)?;
        slots.push(slot);
    }

    // Encrypt the data with the master key
    let data_nonce = crypto::generate_nonce();
    let ciphertext = crypto::encrypt(&master_key, &data_nonce, plaintext)?;

    Ok(TresorBlob {
        slots,
        data_nonce,
        ciphertext,
    })
}

/// Create a slot for a single key
fn create_slot(agent: &mut AgentConnection, key: &AgentKey, master_key: &[u8; 32]) -> Result<Slot> {
    // Generate random challenge
    let challenge = crypto::generate_challenge();

    // Request agent to sign the challenge
    let signature = agent.sign(key, &challenge)?;

    // Derive AES key from signature (zeroized on drop)
    let slot_key = agent::derive_key_from_signature(&signature);

    // Generate nonce for this slot
    let nonce = crypto::generate_nonce();

    // Encrypt the master key
    let encrypted = crypto::encrypt_master_key(&slot_key, &nonce, master_key)?;

    let mut encrypted_key = [0u8; format::ENCRYPTED_KEY_SIZE];
    encrypted_key.copy_from_slice(&encrypted);

    Ok(Slot {
        fingerprint: key.fingerprint_bytes,
        challenge,
        nonce,
        encrypted_key,
    })
}

/// Decrypt a tresor blob using the SSH agent
///
/// Tries all available keys in the agent and returns success if any slot matches.
/// Security keys (SK-*) are tried last since they may require user presence.
///
/// # Arguments
/// * `blob` - The encrypted tresor blob
///
/// # Returns
/// The decrypted plaintext data.
pub fn decrypt(blob: &TresorBlob) -> Result<Vec<u8>> {
    let mut agent = AgentConnection::connect()?;
    let mut keys = agent.list_keys()?;

    // Sort keys so security keys (SK-*) are tried last, as they may require user presence
    keys.sort_by_key(|k| k.is_security_key());

    // Try each key in the agent
    for key in &keys {
        if let Some(slot) = blob.find_slot(&key.fingerprint_bytes) {
            match decrypt_with_slot(&mut agent, key, slot, blob) {
                Ok(plaintext) => return Ok(plaintext),
                Err(_) => continue, // Try next key
            }
        }
    }

    Err(Error::NoMatchingSlot)
}

/// Decrypt using a specific slot
fn decrypt_with_slot(
    agent: &mut AgentConnection,
    key: &AgentKey,
    slot: &Slot,
    blob: &TresorBlob,
) -> Result<Vec<u8>> {
    // Request agent to sign the stored challenge
    let signature = agent.sign(key, &slot.challenge)?;

    // Derive slot key from signature (zeroized on drop)
    let slot_key = agent::derive_key_from_signature(&signature);

    // Decrypt the master key (zeroized on drop)
    let master_key = crypto::decrypt_master_key(&slot_key, &slot.nonce, &slot.encrypted_key)?;

    // Decrypt the data with the master key
    crypto::decrypt(&master_key, &blob.data_nonce, &blob.ciphertext)
}

/// Add a key to an existing tresor
///
/// # Arguments
/// * `blob` - The existing tresor blob
/// * `new_fingerprint` - Fingerprint prefix of the key to add
///
/// # Returns
/// A new `TresorBlob` with the additional slot.
pub fn add_key(blob: &TresorBlob, new_fingerprint: &str) -> Result<TresorBlob> {
    let mut agent = AgentConnection::connect()?;

    // First, decrypt the master key using an existing slot
    let master_key = recover_master_key(&mut agent, blob)?;

    // Find the new key
    let new_key = agent.find_key(new_fingerprint)?;

    // Check if key already exists
    if blob.find_slot(&new_key.fingerprint_bytes).is_some() {
        return Err(Error::InvalidFormat(
            "key already exists in tresor".to_string(),
        ));
    }

    // Create new slot
    let new_slot = create_slot(&mut agent, &new_key, &master_key)?;

    // Create new blob with additional slot
    let mut new_slots = blob.slots.clone();
    new_slots.push(new_slot);

    Ok(TresorBlob {
        slots: new_slots,
        data_nonce: blob.data_nonce,
        ciphertext: blob.ciphertext.clone(),
    })
}

/// Add all available keys from the agent to an existing tresor
///
/// Skips keys that already exist in the tresor or that cause errors when signing.
///
/// # Arguments
/// * `blob` - The existing tresor blob
///
/// # Returns
/// A tuple of the new `TresorBlob` and the count of keys added.
pub fn add_all_keys(blob: &TresorBlob) -> Result<(TresorBlob, usize)> {
    let mut agent = AgentConnection::connect()?;

    // First, decrypt the master key using an existing slot
    let master_key = recover_master_key(&mut agent, blob)?;

    // Get all available keys
    let keys = agent.list_keys()?;

    let mut new_slots = blob.slots.clone();
    let mut added = 0;

    for key in &keys {
        // Skip if key already exists
        if blob.find_slot(&key.fingerprint_bytes).is_some() {
            continue;
        }

        // Try to create a slot for this key
        match create_slot(&mut agent, key, &master_key) {
            Ok(slot) => {
                new_slots.push(slot);
                added += 1;
            }
            Err(_) => {
                // Skip keys that fail (e.g., signing error)
                continue;
            }
        }
    }

    Ok((
        TresorBlob {
            slots: new_slots,
            data_nonce: blob.data_nonce,
            ciphertext: blob.ciphertext.clone(),
        },
        added,
    ))
}

/// Remove a key from an existing tresor
///
/// # Arguments
/// * `blob` - The existing tresor blob
/// * `fingerprint` - Fingerprint prefix of the key to remove
///
/// # Returns
/// A new `TresorBlob` without the specified slot.
pub fn remove_key(blob: &TresorBlob, fingerprint: &str) -> Result<TresorBlob> {
    let mut agent = AgentConnection::connect()?;

    // First verify we can still decrypt (have access to another key)
    let keys = agent.list_keys()?;

    // Find the key to remove
    let key_to_remove = agent.find_key(fingerprint)?;

    // Count how many slots we can access after removal
    let remaining_accessible = keys.iter().any(|k| {
        k.fingerprint_bytes != key_to_remove.fingerprint_bytes
            && blob.find_slot(&k.fingerprint_bytes).is_some()
    });

    if !remaining_accessible && blob.slots.len() > 1 {
        // We might still be OK if we're removing a slot we don't have access to
        // Check if we have access to any slot
        let have_access = keys
            .iter()
            .any(|k| blob.find_slot(&k.fingerprint_bytes).is_some());
        if !have_access {
            return Err(Error::NoMatchingSlot);
        }
    }

    // Cannot remove the last slot
    if blob.slots.len() == 1 {
        return Err(Error::InvalidFormat(
            "cannot remove the last key from tresor".to_string(),
        ));
    }

    // Remove the slot
    let new_slots: Vec<Slot> = blob
        .slots
        .iter()
        .filter(|s| s.fingerprint != key_to_remove.fingerprint_bytes)
        .cloned()
        .collect();

    if new_slots.len() == blob.slots.len() {
        return Err(Error::KeyNotFound {
            fingerprint: fingerprint.to_string(),
        });
    }

    Ok(TresorBlob {
        slots: new_slots,
        data_nonce: blob.data_nonce,
        ciphertext: blob.ciphertext.clone(),
    })
}

/// List slot fingerprints from a tresor
pub fn list_slots(blob: &TresorBlob) -> Vec<[u8; 32]> {
    blob.slot_fingerprints()
}

/// Recover master key from any accessible slot (zeroized on drop)
fn recover_master_key(
    agent: &mut AgentConnection,
    blob: &TresorBlob,
) -> Result<Zeroizing<[u8; 32]>> {
    let keys = agent.list_keys()?;

    for key in &keys {
        if let Some(slot) = blob.find_slot(&key.fingerprint_bytes) {
            // Request agent to sign the stored challenge
            let signature = agent.sign(key, &slot.challenge)?;

            // Derive slot key from signature (zeroized on drop)
            let slot_key = agent::derive_key_from_signature(&signature);

            // Try to decrypt the master key
            if let Ok(master_key) =
                crypto::decrypt_master_key(&slot_key, &slot.nonce, &slot.encrypted_key)
            {
                return Ok(master_key);
            }
        }
    }

    Err(Error::NoMatchingSlot)
}

/// List all keys available in the SSH agent
pub fn list_keys() -> Result<Vec<AgentKey>> {
    let mut agent = AgentConnection::connect()?;
    agent.list_keys()
}
