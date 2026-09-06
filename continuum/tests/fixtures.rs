//! Fixture loader helpers and validation tests using test fixtures

use continuum::{ContinuitySeal, DiffReceipt, HandoffPacket, Kernel, KeyPair, RuntimeGuard};
use std::fs;
use std::path::PathBuf;

fn fixtures_dir() -> PathBuf {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    PathBuf::from(manifest_dir).join("tests").join("fixtures")
}

fn workspace_root() -> PathBuf {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    PathBuf::from(manifest_dir).parent().unwrap().to_path_buf()
}

fn load_fixture(name: &str) -> String {
    let path = fixtures_dir().join(name);
    fs::read_to_string(&path).unwrap_or_else(|e| panic!("Failed to load fixture {}: {}", name, e))
}

fn load_kernel_fixture(name: &str) -> Result<Kernel, continuum::ContinuumError> {
    let json = load_fixture(name);
    Kernel::from_json(&json)
}

mod valid_fixtures {
    use super::*;

    #[test]
    fn test_minimal_kernel_loads() {
        let kernel = load_kernel_fixture("valid_minimal.json").expect("Should load minimal kernel");
        assert_eq!(kernel.name, "minimal");
        assert_eq!(kernel.schema_version, "0");
        assert!(kernel.escalation_rules.is_empty());
        assert!(kernel.refusal_classes.is_empty());
        assert!(kernel.tool_trust.is_empty());
    }

    #[test]
    fn test_maximal_kernel_loads() {
        let kernel = load_kernel_fixture("valid_maximal.json").expect("Should load maximal kernel");
        assert_eq!(kernel.name, "maximal");
        assert!(kernel.description.is_some());
        assert_eq!(kernel.escalation_rules.len(), 5);
        assert_eq!(kernel.refusal_classes.len(), 8);
        assert_eq!(kernel.tool_trust.len(), 7);
        assert_eq!(kernel.spend_ceiling_usd, 10000.0);
    }

    #[test]
    fn test_edge_threshold_kernel_loads() {
        let kernel =
            load_kernel_fixture("valid_edge_threshold.json").expect("Should load edge threshold");
        assert_eq!(kernel.confidence_threshold, 1.0);
        assert_eq!(kernel.escalation_rules.len(), 1);
    }

    fn kernels_dir() -> PathBuf {
        workspace_root().join("kernels")
    }

    #[test]
    fn test_golden_kernel_conservative_ops() {
        let path = kernels_dir().join("conservative_ops.json");
        let json = fs::read_to_string(&path).unwrap();
        let kernel = Kernel::from_json(&json).expect("Should load conservative_ops");
        assert_eq!(kernel.name, "conservative_ops");
        assert!(kernel.spend_ceiling_usd <= 100.0);
    }

    #[test]
    fn test_golden_kernel_aggressive_research() {
        let path = kernels_dir().join("aggressive_research.json");
        let json = fs::read_to_string(&path).unwrap();
        let kernel = Kernel::from_json(&json).expect("Should load aggressive_research");
        assert_eq!(kernel.name, "aggressive_research");
    }

    #[test]
    fn test_golden_kernel_customer_support() {
        let path = kernels_dir().join("customer_support.json");
        let json = fs::read_to_string(&path).unwrap();
        let kernel = Kernel::from_json(&json).expect("Should load customer_support");
        assert_eq!(kernel.name, "customer_support");
    }
}

mod invalid_fixtures {
    use super::*;

    #[test]
    fn test_invalid_confidence_high_rejected() {
        let result = load_kernel_fixture("invalid_confidence_high.json");
        assert!(result.is_err(), "Should reject confidence > 1.0");
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("confidence"),
            "Error should mention confidence: {}",
            err
        );
    }

    #[test]
    fn test_invalid_confidence_negative_rejected() {
        let result = load_kernel_fixture("invalid_confidence_negative.json");
        assert!(result.is_err(), "Should reject negative confidence");
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("confidence"),
            "Error should mention confidence: {}",
            err
        );
    }

    #[test]
    fn test_invalid_schema_version_rejected() {
        let result = load_kernel_fixture("invalid_schema_version.json");
        assert!(result.is_err(), "Should reject unsupported schema version");
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("schema") || err.contains("version"),
            "Error should mention schema/version: {}",
            err
        );
    }

    #[test]
    fn test_invalid_negative_spend_rejected() {
        let result = load_kernel_fixture("invalid_negative_spend.json");
        assert!(result.is_err(), "Should reject negative spend ceiling");
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("spend") || err.contains("negative"),
            "Error should mention spend: {}",
            err
        );
    }
}

mod seal_roundtrip {
    use super::*;

    #[test]
    fn test_seal_roundtrip_minimal() {
        let kernel = load_kernel_fixture("valid_minimal.json").unwrap();
        let keypair = KeyPair::generate();

        let seal = ContinuitySeal::create(&kernel, &keypair).unwrap();
        assert!(seal.verify(&kernel).unwrap());
    }

    #[test]
    fn test_seal_roundtrip_maximal() {
        let kernel = load_kernel_fixture("valid_maximal.json").unwrap();
        let keypair = KeyPair::generate();

        let seal = ContinuitySeal::create(&kernel, &keypair).unwrap();
        assert!(seal.verify(&kernel).unwrap());
    }

    #[test]
    fn test_seal_detects_any_field_change() {
        let kernel = load_kernel_fixture("valid_minimal.json").unwrap();
        let keypair = KeyPair::generate();
        let seal = ContinuitySeal::create(&kernel, &keypair).unwrap();

        let mut tampered = kernel.clone();
        tampered.name = "modified".to_string();

        assert!(
            seal.verify(&tampered).is_err(),
            "Seal should detect name change"
        );
    }

    #[test]
    fn test_handoff_packet_roundtrip() {
        let kernel = load_kernel_fixture("valid_maximal.json").unwrap();
        let keypair = KeyPair::generate();
        let seal = ContinuitySeal::create(&kernel, &keypair).unwrap();

        let packet = HandoffPacket::new(kernel.clone(), seal);
        assert!(packet.verify().unwrap());

        let json = packet.to_json().unwrap();
        let restored = HandoffPacket::from_json(&json).unwrap();

        assert_eq!(packet.kernel_id, restored.kernel_id);
        assert_eq!(packet.version, restored.version);
        assert!(restored.verify().unwrap());
    }
}

mod runtime_guard {
    use super::*;
    use continuum::kernel::TrustLevel;

    fn create_packet_with_trust(trust_map: Vec<(&str, TrustLevel)>) -> HandoffPacket {
        let mut kernel = Kernel::new("test");
        for (tool, level) in trust_map {
            kernel.tool_trust.insert(tool.to_string(), level);
        }
        let keypair = KeyPair::generate();
        let seal = ContinuitySeal::create(&kernel, &keypair).unwrap();
        HandoffPacket::new(kernel, seal)
    }

    #[test]
    fn test_guard_refuses_all_before_load() {
        let guard = RuntimeGuard::new();
        assert!(guard.check_access("any_tool").is_err());
        assert!(guard.check_access("file_read").is_err());
        assert!(guard.check_access("shell_exec").is_err());
    }

    #[test]
    fn test_guard_respects_blocked_tools() {
        let mut guard = RuntimeGuard::new();
        let packet = create_packet_with_trust(vec![("dangerous", TrustLevel::Blocked)]);
        guard.load_packet(packet).unwrap();

        assert!(guard.check_access("dangerous").is_err());
        assert!(guard.check_access("other_tool").is_ok());
    }

    #[test]
    fn test_guard_returns_correct_trust_levels() {
        let mut guard = RuntimeGuard::new();
        let packet = create_packet_with_trust(vec![
            ("trusted_tool", TrustLevel::Trusted),
            ("restricted_tool", TrustLevel::Restricted),
        ]);
        guard.load_packet(packet).unwrap();

        assert_eq!(
            guard.check_access("trusted_tool").unwrap(),
            TrustLevel::Trusted
        );
        assert_eq!(
            guard.check_access("restricted_tool").unwrap(),
            TrustLevel::Restricted
        );
        assert_eq!(
            guard.check_access("unknown_tool").unwrap(),
            TrustLevel::Standard
        );
    }

    #[test]
    fn test_guard_rejects_invalid_packet() {
        let mut guard = RuntimeGuard::new();

        let kernel = Kernel::new("test");
        let keypair1 = KeyPair::generate();
        let keypair2 = KeyPair::generate();

        let seal = ContinuitySeal::create(&kernel, &keypair1).unwrap();
        let mut bad_packet = HandoffPacket::new(kernel, seal);
        bad_packet.seal.public_key = keypair2.public_key_hex();

        assert!(guard.load_packet(bad_packet).is_err());
        assert!(!guard.is_loaded());
    }
}

mod diff_receipts {
    use super::*;

    #[test]
    fn test_diff_receipt_captures_changes() {
        let keypair = KeyPair::generate();

        let old = load_kernel_fixture("valid_minimal.json").unwrap();
        let old_seal = ContinuitySeal::create(&old, &keypair).unwrap();

        let mut new = old.clone();
        new.spend_ceiling_usd = 500.0;
        new.confidence_threshold = 0.9;
        let new_seal = ContinuitySeal::create(&new, &keypair).unwrap();

        let receipt =
            DiffReceipt::create("kernel-test", 1, &old, &old_seal, &new, &new_seal, &keypair)
                .unwrap();

        assert_eq!(receipt.from_version, 1);
        assert_eq!(receipt.to_version, 2);
        assert!(receipt.changes.len() >= 2);
        assert!(receipt.verify().unwrap());
    }

    #[test]
    fn test_diff_receipt_serialization() {
        let keypair = KeyPair::generate();

        let old = Kernel::new("test");
        let old_seal = ContinuitySeal::create(&old, &keypair).unwrap();

        let mut new = old.clone();
        new.name = "updated".to_string();
        let new_seal = ContinuitySeal::create(&new, &keypair).unwrap();

        let receipt =
            DiffReceipt::create("kernel-test", 1, &old, &old_seal, &new, &new_seal, &keypair)
                .unwrap();

        let json = receipt.to_json().unwrap();
        let restored = DiffReceipt::from_json(&json).unwrap();

        assert_eq!(receipt.kernel_id, restored.kernel_id);
        assert!(restored.verify().unwrap());
    }

    #[test]
    fn test_diff_receipt_human_readable() {
        let keypair = KeyPair::generate();

        let old = Kernel::new("test");
        let old_seal = ContinuitySeal::create(&old, &keypair).unwrap();

        let mut new = old.clone();
        new.spend_ceiling_usd = 100.0;
        let new_seal = ContinuitySeal::create(&new, &keypair).unwrap();

        let receipt =
            DiffReceipt::create("kernel-test", 1, &old, &old_seal, &new, &new_seal, &keypair)
                .unwrap();

        let readable = receipt.to_human_readable();
        assert!(readable.contains("Kernel Change Receipt"));
        assert!(readable.contains("spend_ceiling_usd"));
        assert!(readable.contains("Signature:"));
    }
}
