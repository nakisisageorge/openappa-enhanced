# Changelog

All notable changes to OpenAPPA Enhanced will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.41.1] - 2026-11-10

### Added
- **African Sanitizers** (appa-runtime/src/builtins.rs):
  - `redact-african-pii`: Redacts African phone numbers (10 countries: UG, KE, NG, ZA, GH, TZ, ET, ZW, MZ, BW), national IDs (BVN, KRA PIN, SA ID, NIN, Ghana Card, NIDA, Ethiopian ID), passports, and name prefixes in 7 languages (Swahili, Luganda, Amharic, Hausa, Yoruba, Zulu, Xhosa)
  - `redact-mobile-money`: Redacts transaction references for 12+ mobile money providers (M-Pesa, MTN MoMo, Airtel Money, Orange Money, Wave, EcoCash, Vodacom M-Pesa, Tigo Pesa, Halopesa, EazzyPay, M-Pawa, MoKash)
  - `redact-fintech`: Redacts financial identifiers (Nigerian BVN, Kenyan KRA PIN, South African ID, Ugandan NIN, Ghana Card, Tanzanian NIDA, IBAN, SWIFT/BIC, credit cards with Luhn validation, African bank accounts)
- **Benchmark Regression Detection** (benches/):
  - Criterion.rs benchmark suite with 7 groups: policy_parsing, engine_decisions, sanitizers, mcp_routing, event_log, config_validation, policy_compilation
  - Python CI runner (`benches/run_benchmarks.py`) with baseline management, configurable threshold (default 5%), automated baseline updates
  - Baseline storage as JSON (`benches/baseline.json`)
- **Interactive Architecture Visualization** (docs/architecture/index.html):
  - React Flow diagram with 30+ nodes across 6 categories
  - 5 view modes: Full, Core Engine, Runtime & MCP, Policy & Annotators, Benchmarks
  - Search filtering, node detail sidebar, PNG export, multiple layout algorithms
- **Documentation Suite**:
  - DESIGN_DOCUMENT.md — Complete architecture, decisions, tradeoffs
  - PORTFOLIO_CASE_STUDY.md — Portfolio case study with before/after analysis
  - README.md — Project overview, installation, usage, benchmarks
  - CHANGELOG.md — This file
  - SECURITY.md — Threat model, vulnerability reporting, compliance
  - CONTRIBUTING.md — Contribution guidelines
- **Enhanced CI/CD** (.github/workflows/enhanced-ci.yml):
  - cargo-audit for RustSec vulnerability scanning
  - cargo-deny for license compliance, duplicate detection, advisory checking
  - TruffleHog for secret detection (code + git history)
  - SBOM generation (CycloneDX via cargo-cyclonedx)
  - Dependency review automation for PRs
  - govulncheck for Go vulnerability scanning
  - Matrix testing: Ubuntu, macOS, Windows

### Changed
- Updated `REFUSED_MODULE_NAMES` in builtins.rs to include new sanitizer names
- Added comprehensive test coverage for all 3 new sanitizers (60+ test cases)

### Security
- All new sanitizers follow the same trust-decision model as existing sanitizers (detection, not verification)
- No external network calls in sanitizers — pure in-process deterministic regex
- Tokens redacted in debug output

### Testing
- All 4 sanitizer tests pass (redact_email, redact_secrets, redact_african_pii, redact_mobile_money, redact_fintech)
- Full workspace test suite passes (800+ tests)
- Benchmarks run within performance targets

---

## [0.41.0] - 2026-11-10 (Upstream Sync)

### Synced from upstream archestra-ai/OpenAPPA
- Core IFC engine with label algebra (audience × trust monoids)
- Event log with conditional append and fault injection
- Policy parsing and validation (version 2)
- MCP server with streamable HTTP transport
- Harness adapters: Claude Code, OpenCode, Amp, kagent
- Benchmark suites: bench-corp (20 scenarios), AgentThreatBench, TauBench
- Battery marketplace with install-time validation
- Binary fingerprint verification for deployment integrity

---

## Upstream Reference

This project is a substantial enhancement fork of [OpenAPPA](https://github.com/archestra-ai/OpenAPPA) v0.41.0.

**Upstream Repository:** https://github.com/archestra-ai/OpenAPPA  
**Upstream License:** Apache-2.0  
**Paper:** "APPA: Recoverable Information-Flow Control for Real-World LLM Agents" — NeurIPS 2026 Workshop on Agents in the Wild