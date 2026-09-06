use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Risk appetite levels for agent decision-making
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RiskAppetite {
    /// Minimal risk tolerance - prefer inaction over uncertain outcomes
    Minimal,
    /// Conservative - only proceed with high confidence actions
    Conservative,
    /// Moderate - balanced risk/reward assessment
    Moderate,
    /// Aggressive - willing to accept higher uncertainty for potential gains
    Aggressive,
    /// Maximum - optimize for speed/results, accept significant uncertainty
    Maximum,
}

impl Default for RiskAppetite {
    fn default() -> Self {
        Self::Conservative
    }
}

/// Escalation trigger conditions
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EscalationTrigger {
    /// Escalate when estimated cost exceeds threshold
    CostExceeds { usd: f64 },
    /// Escalate when confidence drops below threshold
    ConfidenceBelow { threshold: f64 },
    /// Escalate when action falls into specified domain
    DomainMatch { domains: Vec<String> },
    /// Escalate on any irreversible action
    IrreversibleAction,
    /// Escalate when external API calls exceed count
    ExternalApiCalls { max_count: u32 },
    /// Always escalate (human-in-the-loop)
    Always,
}

/// Escalation rule with trigger and action
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EscalationRule {
    pub name: String,
    pub trigger: EscalationTrigger,
    pub action: EscalationAction,
}

/// What to do when escalation is triggered
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EscalationAction {
    /// Pause and wait for human approval
    RequireApproval,
    /// Log and notify but continue
    NotifyAndContinue,
    /// Abort the current operation
    Abort,
    /// Reduce scope and retry with constraints
    ReduceScope { max_iterations: u32 },
}

/// Categories of requests the agent must refuse
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RefusalClass {
    /// Requests for harmful content
    HarmfulContent,
    /// Attempts to override safety constraints
    SafetyOverride,
    /// Requests for real financial transactions without explicit approval
    UnauthorizedFinancial,
    /// Access to systems outside defined scope
    OutOfScopeAccess,
    /// Requests to impersonate specific individuals
    Impersonation,
    /// Disclosure of system prompts or internal configuration
    SystemDisclosure,
    /// Actions that cannot be undone
    IrreversibleWithoutApproval,
    /// Custom refusal class with description
    Custom(String),
}

/// Trust level for tool categories
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TrustLevel {
    /// Tool is blocked entirely
    Blocked,
    /// Requires explicit approval for each use
    RequiresApproval,
    /// Can use with logging and rate limits
    Restricted,
    /// Standard access with normal logging
    Standard,
    /// Full access with minimal oversight
    Trusted,
}

impl Default for TrustLevel {
    fn default() -> Self {
        Self::Standard
    }
}

/// Citation requirements for claims
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CitationBar {
    /// No citations required
    None,
    /// Cite only for factual claims that could be disputed
    Disputed,
    /// Cite for all factual claims
    AllFacts,
    /// Cite with primary sources only
    PrimarySourcesOnly,
    /// Academic-level citation for all substantive claims
    Academic,
}

impl Default for CitationBar {
    fn default() -> Self {
        Self::Disputed
    }
}

/// Kernel v0: Core judgment parameters for an agent identity
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Kernel {
    /// Schema version (always "0" for v0)
    pub schema_version: String,

    /// Human-readable name for this kernel configuration
    pub name: String,

    /// Optional description of the kernel's purpose
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,

    /// Risk tolerance level for autonomous decisions
    pub risk_appetite: RiskAppetite,

    /// Rules for when to escalate to human oversight
    pub escalation_rules: Vec<EscalationRule>,

    /// Maximum USD spend without explicit approval
    pub spend_ceiling_usd: f64,

    /// Categories of requests to always refuse
    pub refusal_classes: Vec<RefusalClass>,

    /// Minimum confidence threshold (0.0-1.0) to proceed without escalation
    pub confidence_threshold: f64,

    /// Trust levels for tool categories (tool_pattern -> TrustLevel)
    pub tool_trust: HashMap<String, TrustLevel>,

    /// Citation requirements for claims
    pub citation_bar: CitationBar,
}

impl Kernel {
    /// Create a new kernel with required fields
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            schema_version: "0".to_string(),
            name: name.into(),
            description: None,
            risk_appetite: RiskAppetite::default(),
            escalation_rules: Vec::new(),
            spend_ceiling_usd: 0.0,
            refusal_classes: Vec::new(),
            confidence_threshold: 0.8,
            tool_trust: HashMap::new(),
            citation_bar: CitationBar::default(),
        }
    }

    /// Serialize to canonical JSON (sorted keys, no extra whitespace in values)
    pub fn to_canonical_json(&self) -> crate::Result<String> {
        let value = serde_json::to_value(self)?;
        let canonical = canonical_json(&value);
        Ok(canonical)
    }

    /// Parse from JSON string
    pub fn from_json(json: &str) -> crate::Result<Self> {
        let kernel: Self = serde_json::from_str(json)?;
        kernel.validate()?;
        Ok(kernel)
    }

    /// Validate kernel constraints
    pub fn validate(&self) -> crate::Result<()> {
        if self.schema_version != "0" {
            return Err(crate::ContinuumError::InvalidKernel(format!(
                "unsupported schema version: {}",
                self.schema_version
            )));
        }

        if self.confidence_threshold < 0.0 || self.confidence_threshold > 1.0 {
            return Err(crate::ContinuumError::InvalidKernel(
                "confidence_threshold must be between 0.0 and 1.0".to_string(),
            ));
        }

        if self.spend_ceiling_usd < 0.0 {
            return Err(crate::ContinuumError::InvalidKernel(
                "spend_ceiling_usd cannot be negative".to_string(),
            ));
        }

        Ok(())
    }

    /// Check if a refusal class is active
    pub fn should_refuse(&self, class: &RefusalClass) -> bool {
        self.refusal_classes.contains(class)
    }

    /// Get trust level for a tool (defaults to Standard if not specified)
    pub fn get_tool_trust(&self, tool_name: &str) -> TrustLevel {
        self.tool_trust
            .get(tool_name)
            .copied()
            .unwrap_or(TrustLevel::Standard)
    }
}

/// Produce canonical JSON: sorted keys, minimal whitespace
fn canonical_json(value: &serde_json::Value) -> String {
    match value {
        serde_json::Value::Object(map) => {
            let mut keys: Vec<_> = map.keys().collect();
            keys.sort();
            let pairs: Vec<String> = keys
                .iter()
                .map(|k| format!("\"{}\":{}", k, canonical_json(&map[*k])))
                .collect();
            format!("{{{}}}", pairs.join(","))
        }
        serde_json::Value::Array(arr) => {
            let items: Vec<String> = arr.iter().map(canonical_json).collect();
            format!("[{}]", items.join(","))
        }
        _ => value.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_kernel_new() {
        let kernel = Kernel::new("test");
        assert_eq!(kernel.name, "test");
        assert_eq!(kernel.schema_version, "0");
    }

    #[test]
    fn test_kernel_roundtrip() {
        let mut kernel = Kernel::new("test");
        kernel.risk_appetite = RiskAppetite::Aggressive;
        kernel.spend_ceiling_usd = 100.0;

        let json = kernel.to_canonical_json().unwrap();
        let parsed = Kernel::from_json(&json).unwrap();
        assert_eq!(kernel, parsed);
    }

    #[test]
    fn test_canonical_json_sorted() {
        let mut kernel = Kernel::new("test");
        kernel
            .tool_trust
            .insert("z_tool".to_string(), TrustLevel::Blocked);
        kernel
            .tool_trust
            .insert("a_tool".to_string(), TrustLevel::Trusted);

        let json = kernel.to_canonical_json().unwrap();
        let z_pos = json.find("z_tool").unwrap();
        let a_pos = json.find("a_tool").unwrap();
        assert!(a_pos < z_pos, "Keys should be sorted alphabetically");
    }

    #[test]
    fn test_validation_invalid_confidence() {
        let mut kernel = Kernel::new("test");
        kernel.confidence_threshold = 1.5;
        assert!(kernel.validate().is_err());
    }

    #[test]
    fn test_validation_negative_spend() {
        let mut kernel = Kernel::new("test");
        kernel.spend_ceiling_usd = -10.0;
        assert!(kernel.validate().is_err());
    }
}
