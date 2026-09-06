# Release Checklist

Steps to publish a new version of Continuum.

## Pre-release

1. **Update version numbers**
   - Edit `Cargo.toml` workspace version
   - Versions are inherited by `continuum` and `continuum-cli`

2. **Update CHANGELOG.md**
   - Move items from `[Unreleased]` to new version section
   - Add release date in `YYYY-MM-DD` format
   - Ensure all notable changes are documented

3. **Run full test suite**
   ```bash
   cargo fmt --all -- --check
   cargo clippy --all-targets -- -D warnings
   cargo test --workspace
   cargo build -p continuum --benches
   ```

4. **Verify examples compile and run**
   ```bash
   cargo run --example refuse_until_loaded
   ```

5. **Test CLI workflow**
   ```bash
   cargo build --release
   ./target/release/continuum keygen -o test.key
   ./target/release/continuum init -t conservative_ops -o kernel.json
   ./target/release/continuum seal -i kernel.json -k test.key -o packet.json
   ./target/release/continuum verify -p packet.json -v
   ```

## Tag and Release

1. **Create annotated tag**
   ```bash
   git tag -a vX.Y.Z -m "Release vX.Y.Z"
   git push origin vX.Y.Z
   ```

2. **Create GitHub Release**
   - Go to Releases → Draft a new release
   - Select the tag
   - Title: `vX.Y.Z`
   - Copy relevant CHANGELOG section to release notes
   - Publish

## Publish to crates.io

1. **Publish library crate first** (has no internal dependencies)
   ```bash
   cargo publish -p continuum
   ```

2. **Wait for crates.io to index**, then publish CLI
   ```bash
   cargo publish -p continuum-cli
   ```

## Post-release

1. Update CHANGELOG.md with new `[Unreleased]` section
2. Consider bumping to next dev version if appropriate
