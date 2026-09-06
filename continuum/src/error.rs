use thiserror::Error;

#[derive(Error, Debug)]
pub enum ContinuumError {
    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    #[error("Invalid signature")]
    InvalidSignature,

    #[error("Signature verification failed")]
    VerificationFailed,

    #[error("Kernel hash mismatch: expected {expected}, got {actual}")]
    HashMismatch { expected: String, actual: String },

    #[error("Handoff not loaded: tools are locked until kernel is verified")]
    HandoffNotLoaded,

    #[error("Invalid kernel: {0}")]
    InvalidKernel(String),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Hex decode error: {0}")]
    HexDecode(#[from] hex::FromHexError),

    #[error("Cryptographic error: {0}")]
    Crypto(String),
}
