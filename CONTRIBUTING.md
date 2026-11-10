# Contributing to OpenAPPA Enhanced

Thank you for your interest in contributing to OpenAPPA Enhanced! This document provides guidelines for contributing to the project.

## Code of Conduct

This project adheres to the [Contributor Covenant Code of Conduct](CODE_OF_CONDUCT.md). By participating, you are expected to uphold this code.

## How to Contribute

### Reporting Bugs

Before submitting a bug report:
1. Check existing issues to avoid duplicates
2. Use the bug report template
3. Include:
   - Rust version (`rustc --version`)
   - OS and version
   - Steps to reproduce
   - Expected vs actual behavior
   - Relevant logs or error messages

### Suggesting Enhancements

1. Check existing issues and discussions
2. Open a feature request with:
   - Clear description of the enhancement
   - Use case and motivation
   - Potential implementation approach
   - Any breaking changes

### Pull Requests

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/your-feature-name`
3. Make your changes following the guidelines below
4. Run tests and benchmarks locally
5. Submit a PR with a clear description

## Development Setup

### Prerequisites

- **Rust 1.89+** (2024 Edition)
- **Cargo**
- **Git**

### Recommended Tools

```bash
# Install Rust toolchain
rustup install stable
rustup component add rustfmt clippy

# Install security/audit tools
cargo install cargo-audit cargo-deny cargo-cyclonedx

# Install benchmark runner (for benches/)
pip3 install --user --break-system-packages pytest
```

### Building

```bash
# Build all crates
cargo build --workspace

# Build runtime with daemon features
cargo build --release --package appa --features daemon

# Build specific crate
cargo build -p appa-engine
```

### Testing

```bash
# Run all tests
cargo test --workspace

# Run specific crate tests
cargo test -p appa-runtime
cargo test -p appa-engine

# Run with daemon features (integration tests)
cargo test --features daemon -p appa-runtime

# Run sanitizer tests specifically
cargo test -p appa-runtime builtins::tests::redact
```

### Benchmarking

```bash
# Run all benchmarks
cargo bench --bench regression

# Run specific benchmark group
cargo bench --bench regression -- policy_parsing

# Run regression detection
cd benches
python3 run_benchmarks.py --threshold 0.05

# Update baseline
python3 run_benchmarks.py --update-baseline
```

### Formatting & Linting

```bash
# Format all code
cargo fmt --all

# Check formatting (CI)
cargo fmt --all -- --check

# Lint
cargo clippy --workspace -- -D warnings

# Lint specific crate
cargo clippy -p appa-runtime -- -D warnings
```

## Code Style Guidelines

### Rust Guidelines

- **Edition:** 2024
- **Formatting:** `rustfmt` (default config)
- **Linting:** `clippy` with `-D warnings`
- **Naming:** Follow [Rust API Guidelines](https://rust-lang.github.io/api-guidelines/)
- **Documentation:** Public APIs must have doc comments
- **Error Handling:** Use `thiserror` for error types, `anyhow` for application errors
- **Async:** Use `tokio` with explicit `.await`; avoid blocking in async contexts

### Architecture Principles

From `CLAUDE.md`:

1. **IFC Monoids First** — Prefer Information Flow Control monoids (trust lattice, audience chain) over imperative workarounds
2. **Effects Are a Hack** — History/effect tracking is an escape hatch, not primary algebra
3. **Autonomous Execution** — Avoid `attention` marks where trust/audience bounding works; use `blocked` only for outright denial
4. **Agentic Terminology** — Use *trajectory*, *flow*, *turn*, *tool call*, *emission*, *actor/agent*, *harness*
5. **No History** — Docs describe current model only; no retired rules, no "formerly"
6. **Spend Cleverness Budget** — On the model, not the implementation

### Sanitizer Guidelines

When adding new sanitizers:

1. **Follow existing pattern** — Word-by-word scanning with regex
2. **Deterministic only** — No ML, no external calls
3. **Trust decision model** — Registration = trust decision, not verification
4. **Replacement tokens** — Use `[redacted-<category>]` format
5. **Add to REFUSED_MODULE_NAMES** — Prevent module naming conflicts
6. **Comprehensive tests** — Cover positive, negative, edge cases
7. **Document patterns** — List all regex patterns in comments

### Benchmark Guidelines

When adding benchmarks:

1. **Use Criterion.rs** — Statistical rigor, cargo integration
2. **Black-box inputs** — Use `criterion::black_box` for all inputs
3. **Throughput measurement** — Set `Throughput::Bytes` for byte-processing benchmarks
4. **Multiple sizes** — Test small, medium, large inputs
5. **Descriptive names** — Use `BenchmarkId::new("group", "variant")`
6. **Baseline tracking** — Add to `benches/run_benchmarks.py` baseline

---

## Pull Request Process

### Before Submitting

- [ ] `cargo fmt --all -- --check` passes
- [ ] `cargo clippy --workspace -- -D warnings` passes
- [ ] `cargo test --workspace` passes
- [ ] `cargo bench --bench regression` runs without regressions (or baseline updated)
- [ ] New code has doc comments for public APIs
- [ ] New sanitizers/benchmarks have tests
- [ ] CHANGELOG.md updated (if applicable)

### PR Template

```markdown
## Description
Brief description of changes

## Type of Change
- [ ] Bug fix
- [ ] New feature
- [ ] Enhancement
- [ ] Documentation
- [ ] Benchmark
- [ ] CI/CD

## Testing
- [ ] Unit tests pass
- [ ] Integration tests pass (if applicable)
- [ ] Benchmarks run without regression
- [ ] Manual testing performed

## Checklist
- [ ] Code formatted with `cargo fmt`
- [ ] Linting passes with `cargo clippy`
- [ ] Doc comments for public APIs
- [ ] CHANGELOG.md updated
- [ ] No breaking changes (or clearly documented)
```

### Review Process

1. **Automated checks** must pass (CI)
2. **Code review** by maintainer(s)
3. **Security review** for sanitizer/policy changes
4. **Performance review** for engine/benchmark changes
5. **Merge** after approval

---

## Adding New African Language Support

To add a new African language to `redact-african-pii`:

1. **Add name prefixes** to the `prefixes` array in `is_african_name_pattern()`:
   ```rust
   let prefixes = [
       // ... existing
       "NewPrefix1", "NewPrefix2", // Add new language prefixes
   ];
   ```

2. **Add phone patterns** to `is_african_phone()` if country not covered:
   ```rust
   let patterns = [
       // ... existing
       r"^\+XXX[Y]\d{Z}$", // New country code + format
   ];
   ```

3. **Add national ID patterns** to `is_african_national_id()`:
   ```rust
   let patterns = [
       // ... existing
       r"^\d{N}$", // New ID format
   ];
   ```

4. **Add passport patterns** to `is_african_passport()` if needed

5. **Add test cases** in `redact_african_pii_masks_african_pii_only` test

6. **Run tests** and verify all pass

---

## Adding New Mobile Money Providers

To add a new mobile money provider to `redact-mobile-money`:

1. **Add transaction ID patterns** to `is_mobile_money_ref()`:
   ```rust
   let patterns = [
       // ... existing
       r"^NEWPROV\d{8,10}$", // New provider pattern
   ];
   ```

2. **Add test cases** in `redact_mobile_money_masks_mobile_money_refs_only` test

3. **Document** in DESIGN_DOCUMENT.md and PORTFOLIO_CASE_STUDY.md

---

## Adding New FinTech Identifiers

To add a new FinTech identifier to `redact-fintech`:

1. **Add patterns** to `is_fintech_identifier()`:
   ```rust
   let patterns = [
       // ... existing
       r"^NEWFORMAT\d{8,16}$", // New format
   ];
   ```

2. **Add test cases** in `redact_fintech_masks_fintech_identifiers_only` test

---

## Release Process

### Versioning

Semantic Versioning (MAJOR.MINOR.PATCH):
- **MAJOR** — Breaking changes to policy format, engine API, or sanitizer behavior
- **MINOR** — New sanitizers, annotators, authorities, benchmark groups, non-breaking features
- **PATCH** — Bug fixes, documentation, CI/CD, test improvements

### Release Steps

1. Update version in `Cargo.toml` (workspace)
2. Update `CHANGELOG.md`
3. Run full test suite: `cargo test --workspace`
4. Run benchmarks: `cargo bench --bench regression`
5. Update baseline: `cd benches && python3 run_benchmarks.py --update-baseline`
5. Create release tag: `git tag v0.XX.0`
6. Push tag: `git push origin v0.XX.0`
7. GitHub Actions builds and publishes release

---

## Getting Help

- **Discussions:** GitHub Discussions for questions and ideas
- **Issues:** Bug reports and feature requests
- **Security:** security@gictafrica.com for vulnerabilities
- **Maintainer:** George Nakisisa (nakisisageorge@gmail.com)

---

## Recognition

Contributors will be recognized in:
- `CONTRIBUTORS.md`
- Release notes
- GitHub contributors graph

Thank you for contributing to OpenAPPA Enhanced! 🚀