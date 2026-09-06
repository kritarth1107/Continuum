# Contributing to Continuum

Thank you for your interest in contributing to Continuum! This document provides guidelines for contributing to the project.

## Development Setup

### Prerequisites

- Rust 1.70+ (stable toolchain)
- Git

### Building

```bash
# Clone the repository
git clone https://github.com/kritarth1107/Continuum.git
cd Continuum

# Build the workspace
cargo build

# Run tests
cargo test --all

# Run clippy
cargo clippy --all-targets -- -D warnings

# Format code
cargo fmt --all
```

### Project Structure

```
Continuum/
├── continuum/           # Core library crate
│   └── src/
│       ├── lib.rs       # Public exports
│       ├── kernel.rs    # Kernel v0 schema + validation
│       ├── seal.rs      # Ed25519 + SHA-256 sealing
│       ├── handoff.rs   # Handoff packets + RuntimeGuard
│       ├── diff.rs      # Diff receipts
│       └── error.rs     # Error types
├── continuum-cli/       # CLI binary crate
│   └── src/
│       └── main.rs      # CLI commands
├── kernels/             # Golden kernel templates (JSON)
├── tests/               # Integration tests
│   └── fixtures/        # Test fixtures
├── docs/                # Documentation
└── benches/             # Benchmarks (if present)
```

## Making Changes

### Commit Style

- Write clear, concise commit messages
- Use imperative mood: "Add feature" not "Added feature"
- One logical change per commit
- Keep commits atomic and focused

Good examples:
```
Add kernel validation tests
Fix seal verification edge case
Expand diff receipt coverage
```

### Code Style

- Follow Rust idioms and best practices
- Run `cargo fmt` before committing
- Ensure `cargo clippy -- -D warnings` passes
- Add tests for new functionality
- Document public APIs with doc comments

### Pull Request Process

1. Fork the repository
2. Create a feature branch from `main`
3. Make your changes with clear commits
4. Ensure CI passes (fmt, clippy, test)
5. Submit a pull request with a clear description

## Adding Kernels

### Golden Kernels

Golden kernels in `kernels/` are reference configurations. To add one:

1. Create a JSON file following the kernel v0 schema
2. Ensure all required fields are present
3. Document the use case in the `description` field
4. Test that it loads and validates:

```bash
# Validate the kernel
cargo run -- show kernels/your_kernel.json

# Seal and verify
cargo run -- keygen -o test.key
cargo run -- seal -i kernels/your_kernel.json -k test.key -o packet.json
cargo run -- verify -p packet.json
```

### Test Fixtures

Test fixtures go in `tests/fixtures/`. These include:

- **Valid kernels**: Edge cases that should pass validation
- **Invalid kernels**: Malformed JSON for testing error handling
- **Sample packets**: Pre-sealed packets for testing

Naming convention:
- `valid_*.json` - Valid kernel configurations
- `invalid_*.json` - Invalid configurations (should fail validation)
- `packet_*.json` - Pre-sealed handoff packets

## Adding Tests

### Unit Tests

Add unit tests in the same file as the code:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_your_feature() {
        // ...
    }
}
```

### Integration Tests

Add integration tests in `tests/`:

```rust
// tests/integration_test.rs
use continuum::{Kernel, KeyPair, ContinuitySeal};

#[test]
fn test_full_workflow() {
    // ...
}
```

### Running Tests

```bash
# All tests
cargo test --all

# Specific test
cargo test test_name

# With output
cargo test -- --nocapture
```

## Documentation

- Update README.md for user-facing changes
- Update docs/KERNEL_V0.md for schema changes
- Add doc comments to public APIs:

```rust
/// Creates a new kernel with the given name.
///
/// # Examples
///
/// ```
/// use continuum::Kernel;
/// let kernel = Kernel::new("my-agent");
/// ```
pub fn new(name: impl Into<String>) -> Self {
    // ...
}
```

## Questions?

Open an issue for questions about contributing. We're happy to help!
