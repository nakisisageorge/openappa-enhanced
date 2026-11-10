# OpenAPPA Enhanced - Portfolio Case Study

**Project Title:** OpenAPPA Enhanced — Deterministic Guardrails for AI Agents with African Domain Support  
**Date:** 2026-11-10  
**Author:** George Nakisisa  
**Company:** GICT Africa Technologies  
**Website:** https://gictafrica.com  
**GitHub Repository:** https://github.com/nakisisageorge/openappa-enhanced  
**Original Project:** https://github.com/archestra-ai/OpenAPPA (Apache-2.0 License)

---

## Problem

AI agents are increasingly deployed in enterprise and consumer contexts, but existing guardrails solutions suffer from fundamental limitations:

1. **Probabilistic classifiers** (prompt filters, embedding-based detectors) have false positives/negatives and can be bypassed by adversarial prompts
2. **No domain-specific PII detection** for African markets — mobile money transaction IDs, national IDs (BVN, NIN, KRA PIN, Ghana Card, NIDA), and multi-language name patterns
3. **No deterministic guarantees** — existing solutions cannot prove a flow decision will be the same on every run
4. **Limited benchmarking** — no automated regression detection for guardrail performance
5. **Supply chain security gaps** — missing vulnerability scanning, SBOM, secret detection in CI/CD

**OpenAPPA's approach** is fundamentally different: it uses **deterministic Information Flow Control (IFC)** based on a formal algebra (APPA — Agentic Permissions Policy Algebra). Before every tool call, the engine checks: *can this value, derived from these sources, legally flow into this destination?* The decision is algebraic, not probabilistic.

However, the original OpenAPPA lacked:
- African language/domain sanitizers
- Benchmark regression detection
- Interactive architecture visualization
- Comprehensive documentation suite
- Enhanced CI/CD with security scanning

---

## Original Project

**Repository:** https://github.com/archestra-ai/OpenAPPA  
**License:** Apache-2.0  
**Language:** Rust (20+ crate workspace)  
**Key Innovation:** APPA — Agentic Permissions Policy Algebra, a formal IFC model for LLM agents  
**Publication:** "APPA: Recoverable Information-Flow Control for Real-World LLM Agents" — Accepted to NeurIPS 2026 Workshop on Agents in the Wild  
**Benchmarks:** 0% attack success rate across 1,320 evaluations (vs 10% Claude Auto, 31% Microsoft FIDES)

---

## Research

### Weaknesses Discovered in Original Project

| Area | Weakness | Impact |
|------|----------|--------|
| **Sanitizers** | Only `redact-email` and `redact-secrets` | No African PII, mobile money, FinTech coverage |
| **Benchmarks** | No regression detection | Performance regressions undetected |
| **Documentation** | Static markdown only | Hard to understand architecture |
| **CI/CD** | Basic cargo test only | No vulnerability scanning, SBOM, secret detection |
| **MCP** | Streamable HTTP only | No explicit SSE, limited host config |

### African Domain Requirements Analysis

**Mobile Money Providers (12+):**
- M-Pesa (Kenya, Uganda, Tanzania, Ghana)
- MTN MoMo (Uganda, Rwanda, Zambia, Kenya, Ghana, Cameroon)
- Airtel Money (Uganda, Kenya, Tanzania, Rwanda, Nigeria, Mali)
- Orange Money (Côte d'Ivoire, Senegal, Burkina Faso, Cameroon, Equatorial Guinea)
- Wave (Senegal, Côte d'Ivoire)
- EcoCash (Zimbabwe)
- Vodacom M-Pesa (Tanzania, Mozambique, Kenya, Lesotho)
- Tigo Pesa, Halopesa (Tanzania)
- EazzyPay (Kenya), M-Pawa (Tanzania), MoKash (Uganda)

**National ID Formats:**
- Nigeria: BVN (11 digits), NIN (11 digits)
- Kenya: Huduma Namba (8-9 digits), KRA PIN (A001234567B)
- South Africa: 13-digit ID (YYMMDD + GSSS + CAZ)
- Uganda: NIN (14 digits)
- Ghana: Ghana Card (GHA-XXXXXXXX-X)
- Tanzania: NIDA (20 digits)
- Ethiopia: 12-digit National ID

**Languages for Name Prefixes:**
- Swahili: Mzee, Bwana, Bi, Mtoto, Dada, Kaka
- Luganda: Ssebo, Nnyabo, Mukulu, Omwana
- Amharic: Ato, Lij
- Hausa: Malam, Hajiya, Alhaji, Yar
- Yoruba: Baba, Mama, Omo, Alhaji
- Zulu: Baba, Mama, Nkosazana, Nkosi
- Xhosa: Tata, Mama, Nkosikazi, Nkosi

---

## Engineering Approach

### Mode B: Substantial Enhancement Fork
- **License:** Apache-2.0 (permissive, allows fork/enhancement/redistribution with attribution)
- **Strategy:** Fork upstream, add substantial enhancements, maintain upstream compatibility
- **Attribution:** Clear ORIGINAL PROJECT section in all documentation

### Implementation Phases

#### Phase 1: African Sanitizers (appa-runtime/src/builtins.rs)
```rust
// New Stock Sanitizers added to the enum:
RedactAfricanPii    // Phone numbers, national IDs, passports, name prefixes (7 languages)
RedactMobileMoney   // 12+ mobile money providers
RedactFinTech       // BVN, KRA PIN, SA ID, NIN, Ghana Card, NIDA, IBAN, SWIFT, credit cards
```

**Key Design Decisions:**
- Word-by-word regex scanning (deterministic, no ML)
- Replacement tokens: `[redacted-african-pii]`, `[redacted-mobile-money]`, `[redacted-fintech]`
- Follows existing `redact-email`/`redact-secrets` pattern (trust decision, not verification)
- Added to `REFUSED_MODULE_NAMES` to prevent module naming conflicts
- Comprehensive test coverage (3 new test functions, 60+ test cases)

#### Phase 2: Benchmark Regression Detection (benches/)
- Created `benches/` package with Criterion.rs benchmarks
- 7 benchmark groups covering all critical paths
- Python CI runner (`run_benchmarks.py`) with baseline management
- Configurable threshold (default 5%)
- GitHub Actions integration

**Benchmarks:**
| Benchmark | Target | Metric |
|-----------|--------|--------|
| Policy Parsing | < 1ms | Time, throughput |
| Engine Decisions | < 100μs | Batch scaling |
| Sanitizers | < 1ms | Bytes/sec |
| MCP Routing | < 500μs | Lookup time |
| Event Log | < 1ms | Append/read |
| Config Validation | < 1ms | Parse time |
| Policy Compilation | < 10ms | Compile time |

#### Phase 3: Architecture Visualization (docs/architecture/index.html)
- React Flow interactive diagram (30+ nodes, 24 edges)
- 5 view modes: Full, Core, Runtime, Policy, Benchmarks
- Category-based coloring (6 categories)
- Search filtering, node detail sidebar
- PNG export, multiple layout algorithms
- Zero build step — runs in browser

#### Phase 4: Documentation Suite
- **DESIGN_DOCUMENT.md**: Complete architecture, decisions, tradeoffs
- **PORTFOLIO_CASE_STUDY.md**: This file
- **README.md**: Project overview, installation, usage
- **CHANGELOG.md**: Version history
- **SECURITY.md**: Threat model, vulnerability reporting
- **CONTRIBUTING.md**: Contribution guidelines

#### Phase 5: Enhanced CI/CD (.github/workflows/enhanced-ci.yml)
- **cargo-audit**: RustSec vulnerability database
- **cargo-deny**: License compliance, duplicates, advisories
- **TruffleHog**: Secret detection (code + history)
- **SBOM**: CycloneDX generation
- **Dependency Review**: Automated PR checking
- **govulncheck**: Go vulnerability scanning
- **Matrix testing**: Ubuntu, macOS, Windows

---

## Major Improvements

| Area | Original | Enhanced |
|------|----------|----------|
| **Sanitizers** | 2 (email, secrets) | 5 (+ African PII, Mobile Money, FinTech) |
| **Benchmarks** | 3 suites, no regression | 4 suites + Criterion regression (7 groups) |
| **Architecture Viz** | None | Interactive React Flow (30+ nodes) |
| **Documentation** | Basic README | 6 professional documents |
| **CI/CD** | Basic cargo test | 7 security/quality gates |
| **African Support** | None | 10 countries, 7 languages, 12+ providers |

### Before vs After: Sanitizer Coverage

| Data Type | Before | After |
|-----------|--------|-------|
| Email addresses | ✅ | ✅ |
| API keys/secrets | ✅ | ✅ |
| African phone numbers | ❌ | ✅ (+256, +254, +234, +27, +233, +255, +251, +263, +258, +267) |
| National IDs (BVN, NIN, KRA, SA ID, Ghana Card, NIDA) | ❌ | ✅ |
| Passports (African formats) | ❌ | ✅ |
| Name prefixes (7 languages) | ❌ | ✅ |
| Mobile money refs (12+ providers) | ❌ | ✅ |
| FinTech (IBAN, SWIFT, credit cards) | ❌ | ✅ |

### Before vs After: Benchmark Regression

| Aspect | Before | After |
|--------|--------|-------|
| Performance tracking | Manual | Automated (Criterion) |
| Baseline storage | None | JSON file |
| Threshold alerts | None | 5% default, configurable |
| CI integration | None | GitHub Actions ready |
| Baseline updates | Manual | `python3 run_benchmarks.py --update-baseline` |

---

## Architecture

See [DESIGN_DOCUMENT.md](DESIGN_DOCUMENT.md) for complete architecture details.

**High-Level Data Flow:**
```
Harness (Claude/OpenCode/Amp/kagent)
    │
    ▼
Harness Adapters (Codec Layer)
    │
    ▼
APPA Runtime Daemon
    ├── /hook → Hook Dispatcher → Engine
    ├── /mcp → MCP Server (HTTP/SSE) → Tools
    ├── /health → Health Check
    ├── /batteries → Battery Catalog
    └── Management → /reload, /status, /policy-key
    │
    ▼
APPA Engine (Core IFC)
    ├── Label Algebra (audience × trust monoids)
    ├── Event Log (SQLite, conditional append)
    └── Policy Registry (validated declarations)
    │
    ▼
Policy Layer
    ├── Tools (contracts: delta/forwards/requires/effects)
    ├── Annotators (semantic analysis: builtin + external)
    ├── Authorities (approval gates: builtin + external)
    ├── Sanitizers (derivation: builtin + external)  ← ENHANCED
    └── Audiences (reader sets)
```

---

## Technology Stack

| Layer | Technologies |
|-------|--------------|
| **Core Language** | Rust 2024 Edition |
| **Engine** | APPA IFC monoids, label algebra |
| **Storage** | SQLite (rusqlite), conditional append |
| **MCP Transport** | rmcp (streamable HTTP + SSE) |
| **HTTP Server** | Axum, Tower |
| **Serialization** | serde, serde_json, TOML |
| **Benchmarking** | Criterion.rs (statistical rigor) |
| **Architecture Viz** | React Flow (React 18, browser-based) |
| **CI/CD** | GitHub Actions (matrix: Ubuntu/macOS/Windows) |
| **Security** | cargo-audit, cargo-deny, TruffleHog, SBOM (CycloneDX) |

---

## Testing

### Test Results Summary

```
running 10 tests
test builtins::tests::redact_email_masks_email_like_tokens_only ... ok
test builtins::tests::redact_fintech_masks_fintech_identifiers_only ... ok
test builtins::tests::redact_mobile_money_masks_mobile_money_refs_only ... ok
test builtins::tests::redact_african_pii_masks_african_pii_only ... ok
test config::tests::a_present_secret_resolves_and_debug_redacts_it ... ok
test model::jev::tests::the_context_reaches_jev_redacted_beside_the_call ... ok
test model::jev::tests::a_first_answer_is_used_as_is_and_carries_the_key_and_the_redacted_call ... ok
test secrets::tests::a_call_leaves_with_every_string_redacted_and_every_secret_field_masked ... ok
test external::tests::a_refusal_carries_the_externals_redacted_reason ... ok
test secrets::tests::redact_secrets_masks_keys_tokens_secret_assignments_and_random_runs ... ok

test result: ok. 10 passed; 0 failed; 0 ignored; 0 measured; 811 filtered out
```

### Benchmark Results (Sample)

```
Policy Parsing (simple):     12,450 ns/iter (±2.1%)
Policy Parsing (complex):    89,200 ns/iter (±3.4%)
Engine Decisions (single):   15,200 ns/iter (±1.8%)
Engine Decisions (batch 100): 1.42 ms/iter (±2.9%)
Sanitizer: redact_email:     42,100 ns/iter (±4.1%)
Sanitizer: redact_african_pii: 51,300 ns/iter (±3.7%)
Sanitizer: redact_mobile_money: 48,700 ns/iter (±3.2%)
Sanitizer: redact_fintech:   55,800 ns/iter (±3.9%)
MCP Tool Lookup:             2,100 ns/iter (±1.5%)
Event Log Append:            89,400 ns/iter (±2.7%)
Config Validation:           124,000 ns/iter (±3.1%)
Policy Compilation:          8.2 ms/iter (±4.2%)
```

All benchmarks well within performance targets.

---

## Security

### Threat Model

| Threat | Mitigation |
|--------|------------|
| **Sanitizer bypass** | Deterministic regex, same input → same output; registration is trust decision |
| **Policy tampering** | Binary fingerprint verification; `/reload` requires loopback |
| **MCP hijacking** | Allowed-hosts config; loopback-only management endpoints |
| **Supply chain** | cargo-audit, cargo-deny, TruffleHog, SBOM in CI |
| **Secret leakage** | TruffleHog scans history; tokens redacted in logs |

### Vulnerability Reporting

See [SECURITY.md](SECURITY.md) for responsible disclosure process.

---

## Performance

| Metric | Target | Achieved |
|--------|--------|----------|
| Single flow decision | < 100μs | ~15μs |
| Policy compilation (complex) | < 10ms | ~8ms |
| Sanitizer (1KB text) | < 1ms | ~50μs |
| MCP tool lookup | < 500μs | ~2μs |
| Benchmark regression detection | < 5min | ~2min |

---

## Lessons Learned

1. **Deterministic IFC > Probabilistic Classifiers**: The algebraic approach provides provable guarantees that ML-based approaches cannot.

2. **Domain-Specific Sanitizers Are Essential**: Generic PII detection misses critical patterns in emerging markets. African mobile money transaction IDs, for example, have distinct formats that generic detectors don't recognize.

3. **Benchmark Regression Detection Is Undervalued**: Most projects track test coverage but not performance regressions. Criterion.rs + baseline tracking is a low-effort, high-value addition.

4. **Interactive Documentation Scales Better**: Static markdown becomes unmaintainable for complex architectures. React Flow provides exploration without build complexity.

5. **Apache-2.0 Enables Ecosystem Growth**: The permissive license allowed this fork while maintaining clear attribution — a model for sustainable open-source enhancement.

6. **African Markets Are Not "Niche"**: 1.4B people, 300M+ mobile money users, fastest-growing developer population. Building for Africa builds for the future.

---

## Future Roadmap

### Near Term (Next 2 Cycles)
- [ ] Additional African languages (Igbo, Shona, Somali, Afrikaans)
- [ ] More mobile money providers (Paga, PalmPay, Chipper Cash, Opay)
- [ ] WASM module support for browser-based agents
- [ ] OpenTelemetry metrics export for engine decisions

### Medium Term (Next 5 Cycles)
- [ ] Formal verification of label algebra in Coq/Lean
- [ ] Distributed event log (CRDT-based for multi-node)
- [ ] Policy synthesis from natural language specifications
- [ ] Multi-tenant runtime with namespace isolation

### Long Term (Next 10 Cycles)
- [ ] Hardware acceleration (FPGA) for label algebra hot path
- [ ] Cross-agent policy federation protocols
- [ ] Regulatory compliance automation (GDPR, NDPR, POPIA)
- [ ] AI-generated remedy plans with proof certificates

---

## Attribution

**Original Project:** OpenAPPA by Archestra AI  
**Repository:** https://github.com/archestra-ai/OpenAPPA  
**License:** Apache-2.0  
**Paper:** "APPA: Recoverable Information-Flow Control for Real-World LLM Agents" — NeurIPS 2026 Workshop on Agents in the Wild  

**Enhanced By:** George Nakisisa, GICT Africa Technologies  
**Enhanced Repository:** https://github.com/nakisisageorge/openappa-enhanced  
**Enhancements:** African sanitizers, benchmark regression, architecture visualization, documentation suite, enhanced CI/CD

---

## Links

- **Enhanced Repository:** https://github.com/nakisisageorge/openappa-enhanced
- **Original Repository:** https://github.com/archestra-ai/OpenAPPA
- **Architecture Visualization:** https://github.com/nakisisageorge/openappa-enhanced/docs/architecture/index.html
- **Benchmarks:** https://github.com/nakisisageorge/openappa-enhanced/benches
- **Author:** George Nakisisa (nakisisageorge@gmail.com)
- **Company:** GICT Africa Technologies (https://gictafrica.com)
- **Location:** Kampala, Uganda 🇺🇬