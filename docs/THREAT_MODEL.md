# Continuum Threat Model

This document describes the security assumptions, threat actors, and mitigations for Continuum's cryptographic sealing and handoff mechanisms.

## Overview

Continuum provides cryptographic continuity for agent identities across model swaps. The system binds judgment parameters (kernels) to cryptographic identities using Ed25519 signatures and SHA-256 hashes.

## Assets

### Primary Assets

| Asset | Description | Confidentiality | Integrity | Availability |
|-------|-------------|-----------------|-----------|--------------|
| Private signing keys | Ed25519 secret keys | HIGH | HIGH | MEDIUM |
| Sealed kernels | Signed judgment parameters | LOW | HIGH | HIGH |
| Handoff packets | Runtime-verified kernel bundles | LOW | HIGH | HIGH |
| Diff receipts | Signed change audit trail | LOW | HIGH | MEDIUM |

### Secondary Assets

- Public keys (integrity matters, not confidentiality)
- Kernel templates (public reference configurations)
- Audit logs (integrity and availability)

## Trust Boundaries

```
┌─────────────────────────────────────────────────────────────┐
│                    Trusted Environment                       │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────┐  │
│  │ Private Key │  │RuntimeGuard │  │ Verified Handoff    │  │
│  │   Storage   │  │   (loaded)  │  │     Packet          │  │
│  └─────────────┘  └─────────────┘  └─────────────────────┘  │
└─────────────────────────────────────────────────────────────┘
                           │
                    Trust Boundary
                           │
┌─────────────────────────────────────────────────────────────┐
│                   Untrusted Environment                      │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────┐  │
│  │  Network    │  │  Storage    │  │  Unverified Input   │  │
│  │  Transport  │  │   (disk)    │  │     (JSON files)    │  │
│  └─────────────┘  └─────────────┘  └─────────────────────┘  │
└─────────────────────────────────────────────────────────────┘
```

## Threat Actors

### T1: External Attacker

- **Capabilities**: Network access, can inject malformed input
- **Goals**: Forge seals, bypass verification, cause denial of service
- **Mitigations**: Ed25519 signature verification, input validation

### T2: Malicious Insider

- **Capabilities**: Access to sealed packets, may have old keys
- **Goals**: Tamper with kernel parameters, forge audit trail
- **Mitigations**: Cryptographic binding, diff receipts, key rotation

### T3: Compromised Runtime

- **Capabilities**: Control over execution environment
- **Goals**: Bypass RuntimeGuard, execute without valid kernel
- **Mitigations**: Refuse-until-loaded semantics (partial; see limitations)

## Threats and Mitigations

### TH1: Kernel Tampering

**Threat**: Attacker modifies kernel JSON after sealing to change agent behavior.

**Mitigation**: SHA-256 hash of canonical JSON is signed with Ed25519. Any modification invalidates the seal.

**Residual Risk**: LOW - SHA-256 collision resistance is well-established.

### TH2: Signature Forgery

**Threat**: Attacker creates valid signature without private key.

**Mitigation**: Ed25519 signatures require the private key. 128-bit security level.

**Residual Risk**: LOW - Ed25519 is cryptographically sound.

### TH3: Key Compromise

**Threat**: Attacker obtains private signing key.

**Mitigation**: 
- Keys stored in hex format, should be protected by filesystem permissions
- Users advised to use secure key storage practices
- Old keys should be rotated after suspected compromise

**Residual Risk**: MEDIUM - Key management is user responsibility.

### TH4: Replay Attacks

**Threat**: Attacker replays old, valid handoff packet to rollback parameters.

**Mitigation**:
- Version numbers in handoff packets
- Timestamps in packets and diff receipts
- Diff receipts create audit trail

**Residual Risk**: MEDIUM - Application must check versions; Continuum provides the fields but does not enforce monotonic versions.

### TH5: Diff Receipt Manipulation

**Threat**: Attacker creates false audit trail by forging diff receipts.

**Mitigation**: Diff receipts are signed with Ed25519. Must match known public key.

**Residual Risk**: LOW - Requires key compromise.

### TH6: RuntimeGuard Bypass

**Threat**: Code executes tools without loading a valid kernel.

**Mitigation**: `RuntimeGuard::check_access()` returns error if no packet loaded.

**Residual Risk**: MEDIUM - Rust's type system helps but cannot prevent all bypass scenarios. Callers must use the guard consistently.

### TH7: Hash Canonicalization Issues

**Threat**: Same kernel produces different hashes due to JSON formatting.

**Mitigation**: Canonical JSON with sorted keys and minimal whitespace.

**Residual Risk**: LOW - Deterministic serialization is tested.

### TH8: Malformed Input

**Threat**: Crafted JSON causes crashes, memory issues, or unexpected behavior.

**Mitigation**:
- `serde_json` handles parsing safely
- Kernel validation checks field constraints
- Rust's memory safety prevents buffer overflows

**Residual Risk**: LOW - Standard safe parsing practices.

### TH9: Timing Attacks

**Threat**: Attacker learns information from verification timing.

**Mitigation**: 
- `ed25519-dalek` uses constant-time operations
- Hash comparison could potentially leak timing info (not currently addressed)

**Residual Risk**: LOW - Signature verification is constant-time.

## Security Assumptions

1. **Secure Random Number Generation**: `OsRng` provides cryptographic randomness
2. **Cryptographic Primitive Soundness**: SHA-256 and Ed25519 remain secure
3. **Private Key Protection**: Users protect their private keys appropriately
4. **Trusted Build**: The compiled binary is not tampered with
5. **Correct Usage**: Applications use RuntimeGuard correctly

## Limitations

1. **No Hardware Security Module (HSM) Support**: Keys are stored as files
2. **No Key Revocation**: Compromised keys require manual rotation
3. **No Time-Stamping Authority**: Timestamps are system time, not verified
4. **Rust-Only Enforcement**: RuntimeGuard is a Rust construct, not OS-level

## Recommendations

### For Operators

1. Store private keys with restricted filesystem permissions (600)
2. Rotate keys periodically and after any suspected compromise
3. Verify handoff packets before loading in production
4. Maintain diff receipt audit trail for compliance
5. Pin dependency versions to avoid supply chain attacks

### For Developers

1. Always call `guard.load_packet()` before `check_access()`
2. Validate kernel constraints match your application requirements
3. Log verification failures for security monitoring
4. Consider additional application-level version checks

## Version History

| Version | Date | Changes |
|---------|------|---------|
| 1.0 | 2026-09-06 | Initial threat model |
