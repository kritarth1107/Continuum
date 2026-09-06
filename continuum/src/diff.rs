use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::{ContinuitySeal, Kernel, KeyPair, Result};

/// A single field change in a kernel
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FieldChange {
    /// JSON path to the changed field (e.g., "risk_appetite", "escalation_rules[0].trigger")
    pub path: String,
    /// Previous value (JSON)
    pub old_value: serde_json::Value,
    /// New value (JSON)
    pub new_value: serde_json::Value,
}

impl std::fmt::Display for FieldChange {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "  {} : {} → {}",
            self.path, self.old_value, self.new_value
        )
    }
}

/// Signed diff receipt documenting a kernel change
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiffReceipt {
    /// Kernel ID this diff applies to
    pub kernel_id: String,

    /// Version before the change
    pub from_version: u64,

    /// Version after the change
    pub to_version: u64,

    /// Timestamp of the change
    pub changed_at: DateTime<Utc>,

    /// Hash of the old kernel
    pub old_kernel_hash: String,

    /// Hash of the new kernel
    pub new_kernel_hash: String,

    /// Human-readable list of changes
    pub changes: Vec<FieldChange>,

    /// Signature of the diff content
    pub signature: String,

    /// Public key that signed this diff
    pub public_key: String,
}

impl DiffReceipt {
    /// Create a diff receipt between two kernel versions
    pub fn create(
        kernel_id: &str,
        from_version: u64,
        old_kernel: &Kernel,
        old_seal: &ContinuitySeal,
        new_kernel: &Kernel,
        new_seal: &ContinuitySeal,
        keypair: &KeyPair,
    ) -> Result<Self> {
        let changes = compute_diff(old_kernel, new_kernel)?;

        let mut receipt = Self {
            kernel_id: kernel_id.to_string(),
            from_version,
            to_version: from_version + 1,
            changed_at: Utc::now(),
            old_kernel_hash: old_seal.kernel_hash.clone(),
            new_kernel_hash: new_seal.kernel_hash.clone(),
            changes,
            signature: String::new(),
            public_key: keypair.public_key_hex(),
        };

        let content = receipt.signable_content()?;
        let sig = keypair.sign(content.as_bytes());
        receipt.signature = hex::encode(sig.to_bytes());

        Ok(receipt)
    }

    /// Get the content that is signed
    fn signable_content(&self) -> Result<String> {
        Ok(format!(
            "{}:{}:{}:{}:{}:{}",
            self.kernel_id,
            self.from_version,
            self.to_version,
            self.old_kernel_hash,
            self.new_kernel_hash,
            serde_json::to_string(&self.changes)?
        ))
    }

    /// Verify the diff receipt signature
    pub fn verify(&self) -> Result<bool> {
        let content = self.signable_content()?;
        crate::seal::verify_detached(content.as_bytes(), &self.signature, &self.public_key)
    }

    /// Serialize to JSON
    pub fn to_json(&self) -> Result<String> {
        Ok(serde_json::to_string_pretty(self)?)
    }

    /// Parse from JSON
    pub fn from_json(json: &str) -> Result<Self> {
        Ok(serde_json::from_str(json)?)
    }

    /// Human-readable summary of the diff
    pub fn to_human_readable(&self) -> String {
        let mut out = String::new();
        out.push_str(&format!(
            "Kernel Change Receipt\n\
             =====================\n\
             Kernel ID: {}\n\
             Version:   {} → {}\n\
             Changed:   {}\n\
             \n\
             Changes:\n",
            self.kernel_id,
            self.from_version,
            self.to_version,
            self.changed_at.format("%Y-%m-%d %H:%M:%S UTC")
        ));

        if self.changes.is_empty() {
            out.push_str("  (no changes)\n");
        } else {
            for change in &self.changes {
                out.push_str(&format!("{}\n", change));
            }
        }

        out.push_str(&format!(
            "\nSignature: {}...{}\n",
            &self.signature[..8],
            &self.signature[self.signature.len() - 8..]
        ));

        out
    }
}

/// Compute diff between two kernels
fn compute_diff(old: &Kernel, new: &Kernel) -> Result<Vec<FieldChange>> {
    let old_value = serde_json::to_value(old)?;
    let new_value = serde_json::to_value(new)?;

    let mut changes = Vec::new();
    diff_values("", &old_value, &new_value, &mut changes);
    Ok(changes)
}

/// Recursively diff JSON values
fn diff_values(
    path: &str,
    old: &serde_json::Value,
    new: &serde_json::Value,
    changes: &mut Vec<FieldChange>,
) {
    if old == new {
        return;
    }

    match (old, new) {
        (serde_json::Value::Object(old_map), serde_json::Value::Object(new_map)) => {
            let mut all_keys: std::collections::HashSet<_> = old_map.keys().collect();
            all_keys.extend(new_map.keys());

            for key in all_keys {
                let old_val = old_map.get(key).unwrap_or(&serde_json::Value::Null);
                let new_val = new_map.get(key).unwrap_or(&serde_json::Value::Null);
                let new_path = if path.is_empty() {
                    key.to_string()
                } else {
                    format!("{}.{}", path, key)
                };
                diff_values(&new_path, old_val, new_val, changes);
            }
        }
        (serde_json::Value::Array(old_arr), serde_json::Value::Array(new_arr)) => {
            let max_len = old_arr.len().max(new_arr.len());
            for i in 0..max_len {
                let old_val = old_arr.get(i).unwrap_or(&serde_json::Value::Null);
                let new_val = new_arr.get(i).unwrap_or(&serde_json::Value::Null);
                diff_values(&format!("{}[{}]", path, i), old_val, new_val, changes);
            }
        }
        _ => {
            changes.push(FieldChange {
                path: path.to_string(),
                old_value: old.clone(),
                new_value: new.clone(),
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kernel::RiskAppetite;

    #[test]
    fn test_compute_diff_simple() {
        let mut old = Kernel::new("test");
        old.risk_appetite = RiskAppetite::Conservative;

        let mut new = old.clone();
        new.risk_appetite = RiskAppetite::Aggressive;

        let changes = compute_diff(&old, &new).unwrap();
        assert_eq!(changes.len(), 1);
        assert_eq!(changes[0].path, "risk_appetite");
    }

    #[test]
    fn test_compute_diff_multiple() {
        let mut old = Kernel::new("test");
        old.spend_ceiling_usd = 100.0;
        old.confidence_threshold = 0.8;

        let mut new = old.clone();
        new.spend_ceiling_usd = 200.0;
        new.confidence_threshold = 0.9;

        let changes = compute_diff(&old, &new).unwrap();
        assert_eq!(changes.len(), 2);
    }

    #[test]
    fn test_diff_receipt_roundtrip() {
        let keypair = KeyPair::generate();

        let old = Kernel::new("test");
        let old_seal = ContinuitySeal::create(&old, &keypair).unwrap();

        let mut new = old.clone();
        new.spend_ceiling_usd = 50.0;
        let new_seal = ContinuitySeal::create(&new, &keypair).unwrap();

        let receipt =
            DiffReceipt::create("kernel-123", 1, &old, &old_seal, &new, &new_seal, &keypair)
                .unwrap();

        let json = receipt.to_json().unwrap();
        let parsed = DiffReceipt::from_json(&json).unwrap();

        assert_eq!(receipt.kernel_id, parsed.kernel_id);
        assert!(parsed.verify().unwrap());
    }

    #[test]
    fn test_human_readable() {
        let keypair = KeyPair::generate();

        let old = Kernel::new("test");
        let old_seal = ContinuitySeal::create(&old, &keypair).unwrap();

        let mut new = old.clone();
        new.spend_ceiling_usd = 50.0;
        let new_seal = ContinuitySeal::create(&new, &keypair).unwrap();

        let receipt =
            DiffReceipt::create("kernel-123", 1, &old, &old_seal, &new, &new_seal, &keypair)
                .unwrap();

        let readable = receipt.to_human_readable();
        assert!(readable.contains("Kernel Change Receipt"));
        assert!(readable.contains("spend_ceiling_usd"));
    }
}
