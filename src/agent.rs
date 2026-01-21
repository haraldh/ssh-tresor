use crate::error::{Error, Result};
use hkdf::Hkdf;
use sha2::Sha256;
use ssh_agent_client_rs::{Client, Identity};
use ssh_key::public::KeyData;
use ssh_key::{HashAlg, PublicKey};
use std::env;
use std::fmt;
use std::path::Path;

/// Represents an SSH key available in the agent
#[derive(Debug, Clone)]
pub struct AgentKey {
    /// The public key
    pub public_key: PublicKey,
    /// SHA-256 fingerprint (raw 32 bytes)
    pub fingerprint_bytes: [u8; 32],
    /// Human-readable fingerprint string (SHA256:base64...)
    pub fingerprint_str: String,
    /// Key type description (e.g., "ED25519", "RSA-4096")
    pub key_type: String,
    /// Comment (usually user@host)
    pub comment: String,
}

impl AgentKey {
    fn from_public_key(public_key: PublicKey, comment: String) -> Self {
        let fingerprint = public_key.fingerprint(HashAlg::Sha256);
        let fingerprint_str = fingerprint.to_string();

        // Extract raw SHA-256 bytes from the fingerprint
        let fingerprint_bytes: [u8; 32] = fingerprint
            .as_bytes()
            .try_into()
            .expect("SHA-256 fingerprint from ssh-key library must be 32 bytes");

        let key_type = format_key_type(&public_key);

        AgentKey {
            public_key,
            fingerprint_bytes,
            fingerprint_str,
            key_type,
            comment,
        }
    }

    /// Check if this key matches a fingerprint prefix
    pub fn matches_fingerprint(&self, prefix: &str) -> bool {
        // Strip "SHA256:" prefix if present for comparison
        let normalized_prefix = prefix.strip_prefix("SHA256:").unwrap_or(prefix);
        let normalized_fp = self
            .fingerprint_str
            .strip_prefix("SHA256:")
            .unwrap_or(&self.fingerprint_str);

        normalized_fp.starts_with(normalized_prefix)
    }
}

impl fmt::Display for AgentKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} {} {}",
            self.fingerprint_str, self.key_type, self.comment
        )
    }
}

fn format_key_type(key: &PublicKey) -> String {
    match key.key_data() {
        KeyData::Ed25519(_) => "ED25519".to_string(),
        KeyData::Rsa(rsa) => {
            let bits = rsa.n.as_positive_bytes().map(|b| b.len() * 8).unwrap_or(0);
            format!("RSA-{}", bits)
        }
        KeyData::Ecdsa(ecdsa) => {
            let curve = match ecdsa.curve() {
                ssh_key::EcdsaCurve::NistP256 => "256",
                ssh_key::EcdsaCurve::NistP384 => "384",
                ssh_key::EcdsaCurve::NistP521 => "521",
            };
            format!("ECDSA-{}", curve)
        }
        KeyData::Dsa(_) => "DSA".to_string(),
        KeyData::SkEd25519(_) => "SK-ED25519".to_string(),
        KeyData::SkEcdsaSha2NistP256(_) => "SK-ECDSA-256".to_string(),
        _ => "UNKNOWN".to_string(),
    }
}

/// Extract public key and comment from an Identity
fn extract_from_identity(identity: &Identity<'_>) -> (PublicKey, String) {
    match identity {
        Identity::PublicKey(pk) => {
            let public_key: &PublicKey = pk.as_ref();
            (public_key.clone(), public_key.comment().to_string())
        }
        Identity::Certificate(cert) => {
            let cert_ref = cert.as_ref();
            // Extract the public key from the certificate
            // public_key() returns KeyData, we need to construct a PublicKey from it
            let key_data = cert_ref.public_key().clone();
            let public_key = PublicKey::new(key_data, cert_ref.comment());
            (public_key, cert_ref.comment().to_string())
        }
    }
}

/// Connection to the SSH agent
pub struct AgentConnection {
    client: Client,
}

impl AgentConnection {
    /// Connect to the SSH agent using SSH_AUTH_SOCK
    pub fn connect() -> Result<Self> {
        let socket_path = env::var("SSH_AUTH_SOCK").map_err(|_| Error::AgentNotAvailable)?;

        let client = Client::connect(Path::new(&socket_path))
            .map_err(|e| Error::AgentConnection(e.to_string()))?;

        Ok(AgentConnection { client })
    }

    /// List all available keys in the agent
    pub fn list_keys(&mut self) -> Result<Vec<AgentKey>> {
        let identities = self.client.list_all_identities()?;

        let keys: Vec<AgentKey> = identities
            .iter()
            .map(|id| {
                let (public_key, comment) = extract_from_identity(id);
                AgentKey::from_public_key(public_key, comment)
            })
            .collect();

        Ok(keys)
    }

    /// Find a key by fingerprint prefix
    pub fn find_key(&mut self, fingerprint: &str) -> Result<AgentKey> {
        let keys = self.list_keys()?;
        let matches: Vec<_> = keys
            .into_iter()
            .filter(|k| k.matches_fingerprint(fingerprint))
            .collect();

        match matches.len() {
            0 => Err(Error::KeyNotFound {
                fingerprint: fingerprint.to_string(),
            }),
            1 => Ok(matches.into_iter().next().unwrap()),
            n => {
                eprintln!(
                    "Warning: {} keys match prefix '{}', using first match",
                    n, fingerprint
                );
                Ok(matches.into_iter().next().unwrap())
            }
        }
    }

    /// Find a key by its raw SHA-256 fingerprint bytes
    pub fn find_key_by_bytes(&mut self, fingerprint_bytes: &[u8; 32]) -> Result<AgentKey> {
        let keys = self.list_keys()?;

        keys.into_iter()
            .find(|k| &k.fingerprint_bytes == fingerprint_bytes)
            .ok_or_else(|| Error::KeyNotFound {
                fingerprint: format!("SHA256:{}", base64_fingerprint(fingerprint_bytes)),
            })
    }

    /// Get the first available key
    pub fn first_key(&mut self) -> Result<AgentKey> {
        let keys = self.list_keys()?;

        keys.into_iter().next().ok_or(Error::NoKeysAvailable)
    }

    /// Request the agent to sign data with the specified key
    pub fn sign(&mut self, key: &AgentKey, data: &[u8]) -> Result<Vec<u8>> {
        // Sign using the public key directly - the library will find the matching identity
        let signature = self.client.sign(&key.public_key, data)?;

        // Extract raw signature bytes
        Ok(signature.as_bytes().to_vec())
    }
}

/// Derive an AES-256 key from a signature using HKDF-SHA256
pub fn derive_key_from_signature(signature: &[u8]) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(Some(b"ssh-tresor-v3"), signature);
    let mut okm = [0u8; 32];
    hk.expand(b"slot-key-derivation", &mut okm)
        .expect("32 bytes is valid output length for HKDF-SHA256");
    okm
}

fn base64_fingerprint(bytes: &[u8]) -> String {
    use base64::{engine::general_purpose::STANDARD_NO_PAD, Engine};
    STANDARD_NO_PAD.encode(bytes)
}

/// Format fingerprint for MD5 display (hex with colons)
/// MD5 fingerprints are computed by hashing the public key blob
pub fn format_md5_fingerprint(key: &PublicKey) -> String {
    use ssh_encoding::Encode;

    // Encode the public key to its wire format
    let mut key_blob = Vec::new();
    if key.key_data().encode(&mut key_blob).is_err() {
        return "error".to_string();
    }

    // Compute MD5 hash
    let result = md5::compute(&key_blob);

    // Format as colon-separated hex
    result
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect::<Vec<_>>()
        .join(":")
}
