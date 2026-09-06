# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-09-06

### Added

- Initial release of Continuum
- Kernel schema v0 with frozen field definitions:
  - `risk_appetite` enum (minimal, conservative, moderate, aggressive, maximum)
  - `escalation_rules` with trigger/action pairs
  - `spend_ceiling_usd` for cost limits
  - `refusal_classes` for policy enforcement
  - `confidence_threshold` for autonomous decision-making
  - `tool_trust` ranks for tool access control
  - `citation_bar` for citation requirements
- Continuity seal with SHA-256 hash and Ed25519 signatures
- Handoff packet for runtime verification with refuse-until-loaded semantics
- Diff receipts for auditable kernel changes
- Three golden kernel templates:
  - `conservative_ops` - Production environments with strict safety
  - `aggressive_research` - Exploratory work with higher autonomy
  - `customer_support` - Helpful, safe customer interactions
- CLI with commands: `keygen`, `seal`, `verify`, `diff`, `verify-diff`, `hash`, `init`, `show`
- Comprehensive test suite with fixture-based validation tests
- Criterion benchmarks for cryptographic hot paths
- Documentation:
  - SECURITY.md with vulnerability reporting policy
  - THREAT_MODEL.md with security analysis
  - CONTRIBUTING.md with development guidelines
  - WASM.md with portability notes
- Test fixtures for edge-case kernel validation
- CI workflow with format, clippy, test, and benchmark checks
- MIT License
