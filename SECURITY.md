# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 0.1.x   | :white_check_mark: |

## Reporting a Vulnerability

We take security vulnerabilities seriously. If you discover a security issue in Continuum, please report it responsibly.

### How to Report

**Do NOT open a public GitHub issue for security vulnerabilities.**

Instead, please email security concerns directly to:

- **Email**: singhalkritarth@gmail.com
- **Subject line**: `[SECURITY] Continuum: <brief description>`

### What to Include

Please include the following in your report:

1. **Description**: Clear description of the vulnerability
2. **Reproduction steps**: Minimal steps to reproduce the issue
3. **Impact assessment**: What could an attacker achieve?
4. **Affected versions**: Which versions are affected?
5. **Suggested fix**: If you have ideas for remediation (optional)

### Response Timeline

- **Acknowledgment**: Within 48 hours of report
- **Initial assessment**: Within 7 days
- **Fix timeline**: Depends on severity; critical issues prioritized

### Scope

Security issues we're interested in:

- **Cryptographic vulnerabilities**: Issues in seal/signature verification, key handling, hash computation
- **Signature bypass**: Ways to forge or bypass Ed25519 signature verification
- **Hash collision attacks**: Practical attacks on SHA-256 kernel hashing
- **Key material exposure**: Unintended disclosure of private keys
- **Handoff packet tampering**: Ways to modify sealed packets without detection
- **Runtime guard bypass**: Circumventing refuse-until-loaded semantics
- **Denial of service**: Resource exhaustion or crashes from malformed input

### Out of Scope

- Issues in dependencies (report to upstream maintainers)
- Social engineering attacks
- Physical access attacks
- Issues requiring already-compromised systems

## Security Design

Continuum uses well-established cryptographic primitives:

- **Ed25519**: Digital signatures (via `ed25519-dalek`)
- **SHA-256**: Content hashing (via `sha2`)
- **Canonical JSON**: Deterministic serialization for signing

See [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) for the complete threat model.

## Disclosure Policy

We follow coordinated disclosure:

1. Reporter submits vulnerability privately
2. We acknowledge and assess the report
3. We develop and test a fix
4. We release the fix and publish an advisory
5. Reporter may publish their findings after the fix is released

We credit reporters in security advisories unless they prefer anonymity.
