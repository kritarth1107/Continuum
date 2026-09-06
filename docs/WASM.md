# WebAssembly (WASM) Support

This document describes the current WASM compatibility status of Continuum and plans for browser/WASM targets.

## Current Status

**WASM support is planned but not yet implemented.**

The `continuum` crate currently targets native platforms only. WASM compilation has not been tested or feature-gated.

## Portability Considerations

### Dependencies That Affect WASM Compatibility

| Dependency | WASM Status | Notes |
|------------|-------------|-------|
| `sha2` | ✅ Compatible | Pure Rust, no platform dependencies |
| `ed25519-dalek` | ⚠️ Partial | Requires `getrandom` configuration for WASM |
| `rand` | ⚠️ Partial | Needs WASM-compatible RNG source |
| `getrandom` | ⚠️ Partial | Requires `js` feature for browser WASM |
| `chrono` | ⚠️ Partial | Time functions need attention in WASM |
| `serde` / `serde_json` | ✅ Compatible | Pure Rust |
| `uuid` | ⚠️ Partial | `v4` feature needs random source |

### Core Library (`continuum`)

The core cryptographic operations should work in WASM with appropriate feature flags:

```toml
# Hypothetical WASM configuration (not yet implemented)
[target.'cfg(target_arch = "wasm32")'.dependencies]
getrandom = { version = "0.2", features = ["js"] }
```

Key operations expected to work:
- Kernel parsing and validation
- Canonical JSON serialization
- SHA-256 hashing
- Ed25519 signing and verification (with JS random source)
- Handoff packet creation and verification

### CLI (`continuum-cli`)

The CLI binary uses filesystem operations and is **not suitable for WASM**. Browser applications should use the `continuum` library directly.

## Future WASM Support

### Planned Feature Flag

```toml
[features]
default = []
wasm = ["getrandom/js"]
```

### Implementation Steps

1. **Add WASM feature flag** to `continuum/Cargo.toml`
2. **Configure getrandom** for browser JavaScript RNG
3. **Test in wasm32-unknown-unknown target**
4. **Add wasm-pack support** for npm distribution (optional)
5. **Document browser usage patterns**

### Example Browser Usage (Future)

```javascript
// Hypothetical wasm-pack generated API
import init, { Kernel, KeyPair, ContinuitySeal } from 'continuum-wasm';

await init();

const kernel = Kernel.new("browser-agent");
kernel.set_risk_appetite("conservative");

const keypair = KeyPair.generate();
const seal = ContinuitySeal.create(kernel, keypair);
```

## Testing WASM Locally

Once WASM support is added:

```bash
# Install wasm-pack
cargo install wasm-pack

# Build for WASM
wasm-pack build continuum --target web

# Test in browser
wasm-pack test --headless --firefox continuum
```

## Limitations

Even with WASM support:

1. **No filesystem access**: Keys must be managed differently (IndexedDB, external storage)
2. **Browser crypto**: Consider using Web Crypto API for production browser apps
3. **Performance**: WASM crypto may be slower than native; consider web workers for heavy operations
4. **Bundle size**: Full crypto dependencies increase WASM bundle size

## Contributing WASM Support

If you're interested in adding WASM support, see [CONTRIBUTING.md](../CONTRIBUTING.md). Key areas:

1. Feature-flag WASM-incompatible code paths
2. Configure random number generation for browsers
3. Add wasm-pack build configuration
4. Create browser-specific examples
5. Document any API differences
