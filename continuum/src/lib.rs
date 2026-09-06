//! # Continuum
//!
//! Portable judgment kernel + continuity seal for agent identity persistence.
//!
//! This crate provides the core primitives for maintaining agent identity across model swaps:
//! - [`Kernel`] v0 schema defining agent judgment parameters
//! - Cryptographic sealing with [`ContinuitySeal`] (SHA-256 hash + Ed25519 signatures)
//! - [`HandoffPacket`] for runtime verification
//! - [`RuntimeGuard`] enforcing "refuse until loaded" semantics
//! - [`DiffReceipt`] for auditable kernel changes
//!
//! ## Quick Example
//!
//! ```rust
//! use continuum::{Kernel, KeyPair, ContinuitySeal, HandoffPacket, RuntimeGuard};
//!
//! // Create and seal a kernel
//! let kernel = Kernel::new("my-agent");
//! let keypair = KeyPair::generate();
//! let seal = ContinuitySeal::create(&kernel, &keypair).unwrap();
//! let packet = HandoffPacket::new(kernel, seal);
//!
//! // Verify the seal
//! assert!(packet.verify().unwrap());
//!
//! // Use RuntimeGuard to enforce tool access
//! let mut guard = RuntimeGuard::new();
//! assert!(guard.check_access("any_tool").is_err()); // Locked!
//! guard.load_packet(packet).unwrap();
//! assert!(guard.check_access("any_tool").is_ok()); // Unlocked!
//! ```
//!
//! See the `refuse_until_loaded` example for a complete walkthrough.

pub mod diff;
pub mod error;
pub mod handoff;
pub mod kernel;
pub mod seal;

pub use diff::DiffReceipt;
pub use error::ContinuumError;
pub use handoff::{HandoffPacket, RuntimeGuard};
pub use kernel::{Kernel, RiskAppetite, TrustLevel};
pub use seal::{ContinuitySeal, KeyPair};

pub type Result<T> = std::result::Result<T, ContinuumError>;
