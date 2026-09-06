use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{ContinuitySeal, ContinuumError, Kernel, Result};

/// Handoff packet: sealed kernel with metadata for runtime verification
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HandoffPacket {
    /// Unique identifier for this kernel instance
    pub kernel_id: String,

    /// Version of this kernel (incremented on changes)
    pub version: u64,

    /// When this packet was created
    pub created_at: DateTime<Utc>,

    /// The kernel configuration
    pub kernel: Kernel,

    /// Cryptographic seal binding the kernel
    pub seal: ContinuitySeal,
}

impl HandoffPacket {
    /// Create a new handoff packet (version 1)
    pub fn new(kernel: Kernel, seal: ContinuitySeal) -> Self {
        Self {
            kernel_id: Uuid::new_v4().to_string(),
            version: 1,
            created_at: Utc::now(),
            kernel,
            seal,
        }
    }

    /// Create a new version of the packet (preserves kernel_id, bumps version)
    pub fn new_version(&self, kernel: Kernel, seal: ContinuitySeal) -> Self {
        Self {
            kernel_id: self.kernel_id.clone(),
            version: self.version + 1,
            created_at: Utc::now(),
            kernel,
            seal,
        }
    }

    /// Verify the packet's seal matches the kernel
    pub fn verify(&self) -> Result<bool> {
        self.seal.verify(&self.kernel)
    }

    /// Serialize to JSON
    pub fn to_json(&self) -> Result<String> {
        Ok(serde_json::to_string_pretty(self)?)
    }

    /// Parse from JSON
    pub fn from_json(json: &str) -> Result<Self> {
        let packet: Self = serde_json::from_str(json)?;
        Ok(packet)
    }
}

/// Runtime guard that enforces kernel loading before tool access
///
/// Example usage:
/// ```
/// use continuum::{RuntimeGuard, HandoffPacket, Kernel, ContinuitySeal, KeyPair};
///
/// let mut guard = RuntimeGuard::new();
///
/// // Tools are locked until kernel is loaded
/// assert!(guard.check_access("file_write").is_err());
///
/// // Load and verify a handoff packet
/// let kernel = Kernel::new("test");
/// let keypair = KeyPair::generate();
/// let seal = ContinuitySeal::create(&kernel, &keypair).unwrap();
/// let packet = HandoffPacket::new(kernel, seal);
///
/// guard.load_packet(packet).unwrap();
///
/// // Now tools are accessible (subject to kernel trust levels)
/// assert!(guard.check_access("file_write").is_ok());
/// ```
#[derive(Debug, Default)]
pub struct RuntimeGuard {
    loaded_packet: Option<HandoffPacket>,
}

impl RuntimeGuard {
    /// Create a new guard with no packet loaded
    pub fn new() -> Self {
        Self {
            loaded_packet: None,
        }
    }

    /// Load and verify a handoff packet
    pub fn load_packet(&mut self, packet: HandoffPacket) -> Result<()> {
        packet.verify()?;
        self.loaded_packet = Some(packet);
        Ok(())
    }

    /// Check if a packet is loaded
    pub fn is_loaded(&self) -> bool {
        self.loaded_packet.is_some()
    }

    /// Get the loaded kernel (if any)
    pub fn kernel(&self) -> Option<&Kernel> {
        self.loaded_packet.as_ref().map(|p| &p.kernel)
    }

    /// Get the loaded packet (if any)
    pub fn packet(&self) -> Option<&HandoffPacket> {
        self.loaded_packet.as_ref()
    }

    /// Check tool access - fails if no packet loaded
    pub fn check_access(&self, tool_name: &str) -> Result<crate::kernel::TrustLevel> {
        let kernel = self.kernel().ok_or(ContinuumError::HandoffNotLoaded)?;

        let trust = kernel.get_tool_trust(tool_name);

        if trust == crate::kernel::TrustLevel::Blocked {
            return Err(ContinuumError::InvalidKernel(format!(
                "tool '{}' is blocked by kernel policy",
                tool_name
            )));
        }

        Ok(trust)
    }

    /// Unload the current packet
    pub fn unload(&mut self) {
        self.loaded_packet = None;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::KeyPair;

    fn create_test_packet() -> HandoffPacket {
        let kernel = Kernel::new("test");
        let keypair = KeyPair::generate();
        let seal = ContinuitySeal::create(&kernel, &keypair).unwrap();
        HandoffPacket::new(kernel, seal)
    }

    #[test]
    fn test_packet_roundtrip() {
        let packet = create_test_packet();
        let json = packet.to_json().unwrap();
        let parsed = HandoffPacket::from_json(&json).unwrap();
        assert_eq!(packet.kernel_id, parsed.kernel_id);
        assert_eq!(packet.version, parsed.version);
    }

    #[test]
    fn test_packet_verification() {
        let packet = create_test_packet();
        assert!(packet.verify().unwrap());
    }

    #[test]
    fn test_version_bump() {
        let packet1 = create_test_packet();
        let keypair = KeyPair::generate();
        let mut kernel2 = packet1.kernel.clone();
        kernel2.spend_ceiling_usd = 50.0;
        let seal2 = ContinuitySeal::create(&kernel2, &keypair).unwrap();

        let packet2 = packet1.new_version(kernel2, seal2);
        assert_eq!(packet1.kernel_id, packet2.kernel_id);
        assert_eq!(packet2.version, 2);
    }

    #[test]
    fn test_guard_refuses_until_loaded() {
        let guard = RuntimeGuard::new();
        assert!(guard.check_access("any_tool").is_err());
    }

    #[test]
    fn test_guard_allows_after_load() {
        let mut guard = RuntimeGuard::new();
        let packet = create_test_packet();
        guard.load_packet(packet).unwrap();
        assert!(guard.check_access("any_tool").is_ok());
    }

    #[test]
    fn test_guard_unload() {
        let mut guard = RuntimeGuard::new();
        guard.load_packet(create_test_packet()).unwrap();
        assert!(guard.is_loaded());
        guard.unload();
        assert!(!guard.is_loaded());
        assert!(guard.check_access("any_tool").is_err());
    }
}
