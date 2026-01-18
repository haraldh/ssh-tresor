use std::io;
use std::process::ExitCode;
use thiserror::Error;

/// Exit codes as defined in the spec
pub const EXIT_SUCCESS: u8 = 0;
pub const EXIT_GENERAL_ERROR: u8 = 1;
pub const EXIT_AGENT_CONNECTION_FAILED: u8 = 2;
pub const EXIT_KEY_NOT_FOUND: u8 = 3;
pub const EXIT_DECRYPTION_FAILED: u8 = 4;

#[derive(Error, Debug)]
pub enum Error {
    #[error("SSH agent not available\nHint: Is SSH_AUTH_SOCK set? Try running: eval $(ssh-agent) && ssh-add")]
    AgentNotAvailable,

    #[error("Failed to connect to SSH agent: {0}")]
    AgentConnection(String),

    #[error("SSH agent error: {0}")]
    AgentError(#[from] ssh_agent_client_rs::Error),

    #[error("Key not found: {fingerprint}\nHint: Use 'ssh-vault list-keys' to see available keys")]
    KeyNotFound { fingerprint: String },

    #[error("No keys available in SSH agent\nHint: Try running: ssh-add")]
    NoKeysAvailable,

    #[error(
        "No matching slot found\nHint: None of the keys in your SSH agent can decrypt this vault"
    )]
    NoMatchingSlot,

    #[error("Decryption failed: {0}")]
    DecryptionFailed(String),

    #[error("Invalid vault format: {0}")]
    InvalidFormat(String),

    #[error("I/O error: {0}")]
    Io(#[from] io::Error),

    #[error("Base64 decoding error: {0}")]
    Base64(#[from] base64::DecodeError),
}

impl Error {
    pub fn exit_code(&self) -> ExitCode {
        let code = match self {
            Error::AgentNotAvailable | Error::AgentConnection(_) | Error::AgentError(_) => {
                EXIT_AGENT_CONNECTION_FAILED
            }
            Error::KeyNotFound { .. } | Error::NoKeysAvailable | Error::NoMatchingSlot => {
                EXIT_KEY_NOT_FOUND
            }
            Error::DecryptionFailed(_) => EXIT_DECRYPTION_FAILED,
            Error::InvalidFormat(_) | Error::Io(_) | Error::Base64(_) => EXIT_GENERAL_ERROR,
        };
        ExitCode::from(code)
    }
}

pub type Result<T> = std::result::Result<T, Error>;
