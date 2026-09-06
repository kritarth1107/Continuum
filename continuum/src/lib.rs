//! Continuum: Portable judgment kernel + continuity seal for agent identity persistence
//!
//! This crate provides the core primitives for maintaining agent identity across model swaps:
//! - Kernel v0 schema defining agent judgment parameters
//! - Cryptographic sealing (SHA-256 hash + Ed25519 signatures)
//! - Handoff packets for runtime verification
//! - Diff receipts for auditable kernel changes

pub mod diff;
pub mod error;
pub mod handoff;
pub mod kernel;
pub mod seal;

pub use diff::DiffReceipt;
pub use error::ContinuumError;
pub use handoff::{HandoffPacket, RuntimeGuard};
pub use kernel::Kernel;
pub use seal::{ContinuitySeal, KeyPair};

pub type Result<T> = std::result::Result<T, ContinuumError>;
