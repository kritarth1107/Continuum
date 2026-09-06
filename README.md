# Continuum

[![CI](https://github.com/kritarth1107/Continuum/actions/workflows/ci.yml/badge.svg)](https://github.com/kritarth1107/Continuum/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

Portable judgment kernel + continuity seal so an agent identity survives model swaps.

## Status

**v0.1.0** — Initial release. Core primitives are stable: kernel schema v0, seal/verify, handoff packets, diff receipts, and RuntimeGuard. API may evolve in future minor releases.

## What is Continuum?

Continuum provides an identity/judgment layer for long-lived agents. When you swap the underlying model—whether upgrading to a new version, switching providers, or recovering from failures—the agent's core judgment parameters persist cryptographically sealed.

This is **not** AGI. It's a practical tool for:
- Maintaining consistent agent behavior across model changes
- Cryptographic verification that judgment parameters haven't been tampered with
- Auditable change history for compliance and debugging
- Runtime enforcement of "refuse until loaded" semantics

## Quick Start

```bash
# Generate a signing key
continuum keygen -o my-agent.key

# Initialize a kernel from a template
continuum init -t conservative_ops -o kernel.json

# Seal the kernel (creates a handoff packet)
continuum seal -i kernel.json -k my-agent.key -o packet.json

# Verify a packet
continuum verify -p packet.json -v

# Show kernel details
continuum show packet.json
```

## Kernel Schema v0

The kernel defines judgment parameters:

| Field | Description |
|-------|-------------|
| `risk_appetite` | Tolerance for uncertainty (minimal → maximum) |
| `escalation_rules` | When to escalate to human oversight |
| `spend_ceiling_usd` | Maximum autonomous spend |
| `refusal_classes` | Categories to always refuse |
| `confidence_threshold` | Minimum confidence to proceed |
| `tool_trust` | Trust levels per tool category |
| `citation_bar` | Citation requirements |

See [docs/KERNEL_V0.md](docs/KERNEL_V0.md) for the complete specification.

## Golden Kernels

Three pre-built templates for common use cases:

- **conservative_ops**: Production environments with strict safety guardrails
- **aggressive_research**: Exploratory work with higher autonomy
- **customer_support**: Optimized for helpful, safe customer interactions

```bash
continuum init -t conservative_ops -o kernel.json
```

## Continuity Seal

Each kernel is sealed with:
1. SHA-256 hash of the canonical JSON
2. Ed25519 signature binding it to a cryptographic identity

```bash
# Create sealed handoff packet
continuum seal -i kernel.json -k my-agent.key -o packet.json

# Verify the seal
continuum verify -p packet.json
```

## Diff Receipts

When kernel parameters change, create a signed diff receipt:

```bash
continuum diff --old old-packet.json --new new-packet.json -k my-agent.key -o diff.json
```

Output:
```
Kernel Change Receipt
=====================
Kernel ID: abc123
Version:   1 → 2
Changed:   2026-09-06 12:00:00 UTC

Changes:
  spend_ceiling_usd : 10.0 → 50.0
  risk_appetite : "conservative" → "moderate"

Signature: a1b2c3d4...
```

## Runtime Guard

The `RuntimeGuard` enforces "refuse until loaded" semantics—tools are locked until a verified handoff packet is loaded:

```rust
use continuum::{RuntimeGuard, HandoffPacket};

let mut guard = RuntimeGuard::new();

// Tools are locked
assert!(guard.check_access("file_write").is_err());

// Load the handoff packet
guard.load_packet(packet)?;

// Now tools are accessible (subject to trust levels)
let trust = guard.check_access("file_write")?;
```

See the [refuse_until_loaded](continuum/examples/refuse_until_loaded.rs) example for a complete walkthrough:

```bash
cargo run --example refuse_until_loaded
```

## Installation

```bash
cargo install continuum-cli
```

Or build from source:

```bash
git clone https://github.com/kritarth1107/Continuum
cd Continuum
cargo build --release
```

## Library Usage

Add to your `Cargo.toml`:

```toml
[dependencies]
continuum = "0.1"
```

```rust
use continuum::{Kernel, KeyPair, ContinuitySeal, HandoffPacket, RiskAppetite};

// Create a kernel
let mut kernel = Kernel::new("my-agent");
kernel.risk_appetite = RiskAppetite::Conservative;
kernel.spend_ceiling_usd = 100.0;

// Seal it
let keypair = KeyPair::generate();
let seal = ContinuitySeal::create(&kernel, &keypair)?;
let packet = HandoffPacket::new(kernel, seal);

// Verify
assert!(packet.verify()?);
```

## Documentation

- [Kernel Schema v0](docs/KERNEL_V0.md) — Complete field specification
- [Threat Model](docs/THREAT_MODEL.md) — Security analysis and assumptions
- [WASM Notes](docs/WASM.md) — WebAssembly portability considerations
- [Contributing](CONTRIBUTING.md) — Development guidelines
- [Security Policy](SECURITY.md) — Vulnerability reporting

## License

MIT
