# OpenAPPA Enhanced

<div align="center">

![OpenAPPA](https://img.shields.io/badge/OpenAPPA-Enhanced-58a6ff?style=for-the-badge&logo=rust&logoColor=white)
![License](https://img.shields.io/badge/License-Apache--2.0-green?style=for-the-badge)
![Rust](https://img.shields.io/badge/Rust-2024%20Edition-de4027?style=for-the-badge&logo=rust&logoColor=white)
![CI](https://img.shields.io/badge/CI-GitHub%20Actions-238636?style=for-the-badge&logo=githubactions&logoColor=white)

**Deterministic guardrails for AI agents — now with African domain support**

[Architecture Visualization](docs/architecture/index.html) · [Benchmarks](benches/) · [Design Document](DESIGN_DOCUMENT.md) · [Case Study](PORTFOLIO_CASE_STUDY.md) · [Security](SECURITY.md)

</div>

---

## Overview

OpenAPPA Enhanced is a substantial enhancement fork of [OpenAPPA](https://github.com/archestra-ai/OpenAPPA) — the deterministic guardrails system for AI agents based on **APPA (Agentic Permissions Policy Algebra)**.

### What Makes It Different

| Traditional Guardrails | OpenAPPA Enhanced |
|------------------------|-------------------|
| Probabilistic classifiers | **Deterministic IFC algebra** |
| Prompt filtering | **Label algebra (audience × trust monoids)** |
| False positives/negatives | **Provable flow decisions** |
| Generic PII detection | **African domain sanitizers** (10 countries, 7 languages, 12+ mobile money providers) |
| No performance tracking | **Criterion benchmark regression detection** |

### Key Enhancements

- 🌍 **African Sanitizers**: Phone numbers (+256 UG, +254 KE, +234 NG, +27 ZA, +233 GH, +255 TZ, +251 ET, +263 ZW, +258 MZ, +267 BW), national IDs (BVN, KRA PIN, SA ID, NIN, Ghana Card, NIDA), passports, name prefixes (Swahili, Luganda, Amharic, Hausa, Yoruba, Zulu, Xhosa)
- 💰 **Mobile Money Sanitizers**: 12+ providers (M-Pesa, MTN MoMo, Airtel Money, Orange Money, Wave, EcoCash, Vodacom M-Pesa, Tigo Pesa, Halopesa, EazzyPay, M-Pawa, MoKash)
- 🏦 **FinTech Sanitizers**: BVN, KRA PIN, SA ID, NIN, Ghana Card, NIDA, IBAN, SWIFT/BIC, credit cards (Luhn), African bank accounts
- 📊 **Benchmark Regression Detection**: Criterion.rs suite with 7 benchmark groups, 5% threshold, CI integration
- 🎨 **Interactive Architecture Visualization**: React Flow diagram (30+ nodes, 5 view modes)
- 📚 **Documentation Suite**: Design doc, case study, README, changelog, security, contributing
- 🔒 **Enhanced CI/CD**: cargo-audit, cargo-deny, TruffleHog, SBOM, dependency review

---

## Quick Start

### Prerequisites
- Rust 1.89+ (2024 Edition)
- Cargo

### Installation

```bash
# Clone the repository
git clone https://github.com/nakisisageorge/openappa-enhanced.git
cd openappa-enhanced

# Build the runtime
cargo build --release --package appa --features daemon

# The binary is at target/release/appa
```

### Running the Runtime

```bash
# Create a policy file (appa.toml)
cat > appa.toml << 'EOF'
version = 2
trust_chain = ["suspicious", "untrusted", "internal", "trusted"]

[[tool]]
name = "read_file"
description = "Read a file"
delta = { trust = "internal", audience = ["self"] }

[[tool]]
name = "write_file"
description = "Write a file"
delta = { trust = "trusted", audience = ["self", "internal"] }
requires = { trust = "internal" }

[[tool]]
name = "send_email"
description = "Send an email"
delta = { trust = "trusted", audience = ["internal"] }
requires = { trust = "trusted", audience = { contains = ["internal"] } }

[[annotator]]
name = "classifier"
builtin = "llm"
hint = "Classify content sensitivity"

[[sanitizer]]
name = "redact-african-pii"
on = ["tool_output"]

[[sanitizer]]
name = "redact-mobile-money"
on = ["tool_output"]

[[sanitizer]]
name = "redact-fintech"
on = ["tool_output"]

[deployment]
starting_label = { trust = "trusted", audience = "self" }
assumed_tools = ["read_file"]
EOF

# Start the runtime
./target/release/appa runtime --config appa.toml

# Runtime serves on http://127.0.0.1:8787
# Endpoints: /hook, /mcp, /health, /batteries, management routes
```

### Using the Sanitizers

The new sanitizers are automatically available when declared in your policy:

```toml
[[sanitizer]]
name = "redact-african-pii"
on = ["tool_output"]

[[sanitizer]]
name = "redact-mobile-money"
on = ["tool_output"]

[[sanitizer]]
name = "redact-fintech"
on = ["tool_output"]
```

**Example redaction:**
```
Input:  "Call +256700123456 or Mzee Juma at BVN 12345678901, tx MP1234567890"
Output: "Call [redacted-african-pii] or [redacted-african-pii] at [redacted-fintech], tx [redacted-mobile-money]"
```

### Running Benchmarks

```bash
# Run all benchmarks
cargo bench --bench regression

# Run regression detection with baseline comparison
cd benches
python3 run_benchmarks.py --threshold 0.05

# Update baseline
python3 run_benchmarks.py --update-baseline
```

### Architecture Visualization

Open `docs/architecture/index.html` in a browser for an interactive architecture diagram with:
- 5 view modes (Full, Core, Runtime, Policy, Benchmarks)
- Search filtering
- Node detail sidebar
- PNG export
- Multiple layout algorithms

---

## Project Structure

```
openappa-enhanced/
├── appa-engine/           # Core IFC engine, label algebra
├── appa-policy/           # Policy parsing, validation, compilation
├── appa-runtime/          # Daemon, MCP server, builtins (sanitizers)
│   └── src/builtins.rs    # ← African sanitizers
├── appa-eventlog/         # SQLite trajectory store
├── appa-builtin/          # External module ABI
├── appa-runtime-api/      # Shared types (hooks, MCP)
├── appa-package/          # Battery marketplace
├── appa-adapter-*/        # Harness adapters (Claude, OpenCode, Amp, kagent)
├── benches/               # Regression detection suite
│   ├── Cargo.toml
│   ├── regression.rs      # Criterion benchmarks
│   ├── run_benchmarks.py  # CI runner
│   └── baseline.json      # Stored baselines
├── docs/
│   └── architecture/      # Interactive React Flow diagram
│       └── index.html
├── .github/workflows/
│   └── enhanced-ci.yml    # Enhanced CI/CD
├── DESIGN_DOCUMENT.md
├── PORTFOLIO_CASE_STUDY.md
├── README.md
├── CHANGELOG.md
├── SECURITY.md
└── CONTRIBUTING.md
```

---

## Policy Configuration

### Policy TOML Structure (Version 2)

```toml
version = 2
trust_chain = ["suspicious", "untrusted", "internal", "trusted"]
boundary = { trust = "trusted", audience = ["self"] }

[[tool]]
name = "tool_name"
description = "Human-readable description"
delta = { trust = "internal", audience = ["self"] }
forwards = { trust = "trusted", audience = ["internal"] }
requires = { trust = "internal", audience = { contains = ["internal"] } }
effects = ["egress"]

[[annotator]]
name = "semantic_analyzer"
builtin = "llm"  # or "claude-code", "jev", "archestra"
hint = "Instruction for the annotator"
inputs = { content = "$tool_call.arguments.text" }

[[authority]]
name = "approver"
permits = { trust_below = "trusted", audience_missing = ["internal"] }

[[sanitizer]]
name = "redact-african-pii"
on = ["tool_output"]
permits = { audience = { from = ["internal"], to = ["self"] } }

[deployment]
starting_label = { trust = "trusted", audience = "self" }
assumed_tools = ["read_file"]
provider_run_tools = ["search_web"]
confined_results = ["send_email"]
```

### Available Builtin Annotators
- `claude-code` — Claude Code hook integration
- `llm` — Generic LLM transport
- `jev` — TypeSafe Jev classifier
- `archestra` — Archestra platform (feature-gated)

### Available Builtin Sanitizers
- `redact-email` — Email address redaction
- `redact-secrets` — Credential/key/token redaction
- `redact-african-pii` — **NEW** African PII (phone, IDs, passports, names)
- `redact-mobile-money` — **NEW** Mobile money transaction refs (12+ providers)
- `redact-fintech` — **NEW** FinTech identifiers (BVN, KRA PIN, IBAN, SWIFT, cards)

### Available Builtin Authorities
- `approve` — Approves all requests

---

## Benchmarks

### Regression Detection Suite

The `benches/` package contains a comprehensive Criterion.rs benchmark suite:

```bash
# Run all benchmarks
cargo bench --bench regression

# Run specific benchmark group
cargo bench --bench regression -- policy_parsing
cargo bench --bench regression -- sanitizers

# CI regression detection
cd benches
python3 run_benchmarks.py --threshold 0.05 --fail-on-regression
```

**Benchmark Groups:**
| Group | Benchmarks | Purpose |
|-------|------------|---------|
| `policy_parsing` | simple, complex | Parse time, throughput |
| `engine_decisions` | single, batch (10/50/100) | Decision latency, scaling |
| `sanitizers` | email, secrets, african-pii, mobile-money, fintech | Redaction speed, throughput |
| `mcp_routing` | list, lookup | Tool router performance |
| `event_log` | append, read | Trajectory store ops |
| `config_validation` | minimal, with_annotators | Validation latency |
| `policy_compilation` | full | End-to-end compile time |

---

## Architecture Visualization

The interactive architecture diagram at `docs/architecture/index.html` provides:

- **30+ nodes** across 6 categories (Core, Policy, Security, Runtime, Benchmarks, External)
- **24 edges** showing data flow
- **5 view modes**: Full, Core Engine, Runtime & MCP, Policy & Annotators, Benchmarks
- **Search filtering** by component name or crate
- **Node detail sidebar** with descriptions and crate info
- **PNG export** for documentation
- **Layout algorithms**: Dagre (hierarchical), ELK, Force-directed

Open in any modern browser — no build step required.

---

## Enhanced CI/CD

The `.github/workflows/enhanced-ci.yml` includes:

| Check | Tool | Purpose |
|-------|------|---------|
| **Vulnerability Scanning** | `cargo-audit` | RustSec database |
| **License/Dependency Policy** | `cargo-deny` | Allowlist, duplicates, advisories |
| **Secret Detection** | `TruffleHog` | Code + git history |
| **SBOM Generation** | `cargo-cyclonedx` | CycloneDX format |
| **Dependency Review** | GitHub Action | PR automated checking |
| **Go Vulnerabilities** | `govulncheck` | Go components |
| **Multi-platform** | Matrix | Ubuntu, macOS, Windows |

---

## Security

### Threat Model

| Threat | Mitigation |
|--------|------------|
| Sanitizer bypass | Deterministic regex; registration = trust decision |
| Policy tampering | Binary fingerprint verification; loopback-only reload |
| MCP hijacking | Allowed-hosts config; loopback-only management |
| Supply chain | cargo-audit, cargo-deny, TruffleHog, SBOM |
| Secret leakage | TruffleHog scans history; tokens redacted in logs |

### Reporting Vulnerabilities

See [SECURITY.md](SECURITY.md) for responsible disclosure process.

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

### Development Setup

```bash
# Install Rust toolchain
rustup install stable
rustup component add rustfmt clippy

# Install additional tools
cargo install cargo-audit cargo-deny cargo-cyclonedx

# Run tests
cargo test --workspace

# Run benchmarks
cargo bench --bench regression

# Format code
cargo fmt --all

# Lint
cargo clippy --workspace -- -D warnings
```

---

## License

This project is licensed under the **Apache License 2.0** — see [LICENSE.md](LICENSE.md) for details.

This is a substantial enhancement fork of [OpenAPPA](https://github.com/archestra-ai/OpenAPPA) (Apache-2.0), with clear attribution maintained throughout.

---

## Attribution

**Original Project:** [OpenAPPA](https://github.com/archestra-ai/OpenAPPA) by Archestra AI  
**License:** Apache-2.0  
**Paper:** "APPA: Recoverable Information-Flow Control for Real-World LLM Agents" — NeurIPS 2026 Workshop on Agents in the Wild

**Enhanced By:** George Nakisisa, GICT Africa Technologies  
**Repository:** https://github.com/nakisisageorge/openappa-enhanced  
**Contact:** nakisisageorge@gmail.com | Kampala, Uganda 🇺🇬

---

## Acknowledgments

- Archestra AI team for the original OpenAPPA and APPA formalism
- Rust community for excellent tooling (criterion, rmcp, axum)
- African FinTech innovators inspiring the domain-specific sanitizers
- NeurIPS 2026 Workshop on Agents in the Wild for publishing the APPA paper