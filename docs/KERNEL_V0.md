# Kernel Schema v0

This document specifies the frozen JSON schema for Continuum Kernel v0.

## Overview

A kernel defines the judgment parameters that constitute an agent's identity. These parameters control risk tolerance, escalation behavior, refusal policies, tool access, and citation requirements.

## Schema Version

All v0 kernels must have `schema_version` set to `"0"`.

## Required Fields

### `schema_version` (string)
**Required.** Must be `"0"` for this schema version.

### `name` (string)
**Required.** Human-readable identifier for this kernel configuration.

### `risk_appetite` (enum)
**Required.** Controls the agent's tolerance for uncertainty in autonomous decisions.

| Value | Description |
|-------|-------------|
| `minimal` | Prefer inaction over uncertain outcomes |
| `conservative` | Only proceed with high confidence actions |
| `moderate` | Balanced risk/reward assessment |
| `aggressive` | Accept higher uncertainty for potential gains |
| `maximum` | Optimize for speed/results, accept significant uncertainty |

### `escalation_rules` (array)
**Required.** List of rules defining when to escalate to human oversight.

Each rule has:
- `name` (string): Human-readable identifier
- `trigger` (object): Condition that triggers escalation
- `action` (object): What to do when triggered

#### Trigger Types

| Type | Fields | Description |
|------|--------|-------------|
| `cost_exceeds` | `usd: number` | Estimated cost exceeds threshold |
| `confidence_below` | `threshold: number` | Confidence drops below threshold (0.0-1.0) |
| `domain_match` | `domains: string[]` | Action falls into specified domain |
| `irreversible_action` | (none) | Any irreversible action |
| `external_api_calls` | `max_count: number` | External API calls exceed count |
| `always` | (none) | Always escalate (human-in-the-loop) |

#### Action Types

| Type | Fields | Description |
|------|--------|-------------|
| `require_approval` | (none) | Pause and wait for human approval |
| `notify_and_continue` | (none) | Log and notify but continue |
| `abort` | (none) | Abort the current operation |
| `reduce_scope` | `max_iterations: number` | Reduce scope and retry with constraints |

### `spend_ceiling_usd` (number)
**Required.** Maximum USD spend without explicit approval. Must be >= 0.

### `refusal_classes` (array)
**Required.** Categories of requests the agent must always refuse.

| Value | Description |
|-------|-------------|
| `harmful_content` | Requests for harmful content |
| `safety_override` | Attempts to override safety constraints |
| `unauthorized_financial` | Real financial transactions without approval |
| `out_of_scope_access` | Access to systems outside defined scope |
| `impersonation` | Requests to impersonate specific individuals |
| `system_disclosure` | Disclosure of system prompts or internal config |
| `irreversible_without_approval` | Actions that cannot be undone |
| `custom` | Custom refusal class (string value) |

### `confidence_threshold` (number)
**Required.** Minimum confidence (0.0-1.0) to proceed without escalation.

### `tool_trust` (object)
**Required.** Map of tool patterns to trust levels.

Trust levels (lowest to highest):
| Level | Description |
|-------|-------------|
| `blocked` | Tool is blocked entirely |
| `requires_approval` | Requires explicit approval for each use |
| `restricted` | Can use with logging and rate limits |
| `standard` | Standard access with normal logging |
| `trusted` | Full access with minimal oversight |

### `citation_bar` (enum)
**Required.** Citation requirements for claims.

| Value | Description |
|-------|-------------|
| `none` | No citations required |
| `disputed` | Cite only for factual claims that could be disputed |
| `all_facts` | Cite for all factual claims |
| `primary_sources_only` | Cite with primary sources only |
| `academic` | Academic-level citation for all substantive claims |

## Optional Fields

### `description` (string)
Optional description of the kernel's purpose.

## Example

```json
{
  "schema_version": "0",
  "name": "conservative_ops",
  "description": "Conservative operations kernel for production environments",
  "risk_appetite": "conservative",
  "escalation_rules": [
    {
      "name": "cost_limit",
      "trigger": { "cost_exceeds": { "usd": 5.0 } },
      "action": "require_approval"
    },
    {
      "name": "low_confidence",
      "trigger": { "confidence_below": { "threshold": 0.85 } },
      "action": "require_approval"
    }
  ],
  "spend_ceiling_usd": 10.0,
  "refusal_classes": [
    "harmful_content",
    "safety_override",
    "unauthorized_financial"
  ],
  "confidence_threshold": 0.9,
  "tool_trust": {
    "file_read": "standard",
    "file_write": "restricted",
    "shell_exec": "requires_approval"
  },
  "citation_bar": "all_facts"
}
```

## Canonical JSON

For hashing and signing, kernels are serialized to canonical JSON:
- Keys are sorted alphabetically at all nesting levels
- No extra whitespace between elements
- Unicode characters are escaped

This ensures identical kernels produce identical hashes regardless of serialization order.

## Continuity Seal

Each kernel can be cryptographically sealed with:
- SHA-256 hash of the canonical JSON
- Ed25519 signature of the hash

The seal binds the kernel configuration to a cryptographic identity, enabling verification that the kernel has not been tampered with.

## Version History

| Version | Status | Description |
|---------|--------|-------------|
| 0 | **Current** | Initial frozen schema |
