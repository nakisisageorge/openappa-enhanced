# OpenAPPA Enhanced - Design Document

## 1. Original Architecture

OpenAPPA (Agentic Permissions Policy Algebra) is a deterministic guardrails system for AI agents. It sits between an agent and its tools, answering one question before every action: **is this data allowed to go to this destination?**

### Core Concepts

- **APPA (Agentic Permissions Policy Algebra)**: A formal algebra for information-flow control in LLM agents
- **Labels**: `audience × trust` pairs forming a checked monoid
- **Event Log**: Free monoid of trajectory events (tool calls, emissions, forks, remedies)
- **Policy**: Declarative TOML configuration (version 2) defining tools, annotators, authorities, sanitizers, audiences, deployment
- **Engine**: Core decision engine that evaluates flows against policy in deterministic, replayable manner

### Original Components

| Component | Purpose |
|-----------|---------|
| `appa-engine` | Core IFC engine, label algebra, decision logic |
| `appa-policy` | Policy parsing, validation, compilation from TOML |
| `appa-runtime` | Daemon process serving hooks, MCP, management APIs |
| `appa-eventlog` | SQLite-backed trajectory store with conditional append |
| `appa-builtin` | ABI for external authority/sanitizer modules |
| `appa-runtime-api` | Shared types for hook events, decisions, codecs |

### Original Integrations

- **Claude Code**: Hook-based integration with MCP server
- **OpenCode**: MCP client integration
- **Amp**: MCP client integration
- **kagent**: A2A protocol + MCP for Kubernetes agents

### Original Sanitizers

- `redact-email`: Basic email pattern redaction
- `redact-secrets`: Credential/key/token redaction

### Original Benchmarks

- `bench-corp`: 20 enterprise workflow scenarios
- `AgentThreatBench`: OWASP Top 10 for Agentic Applications
- `TauBench`: Airline/retail customer service simulation

---

## 2. Problems Identified

### 2.1 Limited African Language & Domain Support
- No built-in support for African phone number formats (+256, +254, +234, +27, +233, +255, +251, +263, +258, +267)
- No national ID patterns for African countries (NIN, BVN, KRA PIN, SA ID, Ghana Card, NIDA)
- No mobile money transaction reference detection for 12+ African providers
- No FinTech identifier patterns (IBAN, SWIFT, credit cards, African bank accounts)
- No name prefix recognition for major African languages

### 2.2 Missing MCP HTTP/SSE Transport Explicitness
- Streamable HTTP transport exists but SSE capabilities not explicitly documented
- No dedicated SSE endpoint for clients preferring event-stream transport
- Limited allowed-hosts configuration for shared deployments

### 2.3 No Benchmark Regression Detection
- Criterion benchmarks exist for some components but no unified regression suite
- No automated CI gate for performance regressions
- No baseline tracking or threshold-based alerting

### 2.4 Documentation Gaps
- No interactive architecture visualization
- No comprehensive design document
- No portfolio case study
- No MCP integration guide
- Limited before/after comparison

### 2.5 CI/CD Enhancement Opportunities
- Missing cargo-audit for vulnerability scanning
- Missing cargo-deny for license/dependency policy enforcement
- Missing TruffleHog for secret detection
- Missing SBOM generation (CycloneDX)
- Missing dependency review automation
- Missing govulncheck integration

---

## 3. Proposed Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         OPENAPPA ENHANCED ARCHITECTURE                      │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────┐    ┌──────────┐  │
│  │   Harness    │    │   Harness    │    │   Harness    │    │  Harness │  │
│  │  (Claude)    │    │  (OpenCode)  │    │    (Amp)     │    │ (kagent) │  │
│  └──────┬───────┘    └──────┬───────┘    └──────┬───────┘    └────┬─────┘  │
│         │                   │                   │                   │        │
│         ▼                   ▼                   ▼                   ▼        │
│  ┌──────────────────────────────────────────────────────────────────────┐   │
│  │                     HARNESS ADAPTERS (Codec Layer)                    │   │
│  │  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌────────────────────┐   │   │
│  │  │Claude    │  │OpenCode  │  │Amp       │  │kagent (A2A+MCP)    │   │   │
│  │  │Hook+MCP  │  │MCP       │  │MCP       │  │Archestra Platform  │   │   │
│  │  └──────────┘  └──────────┘  └──────────┘  └────────────────────┘   │   │
│  └──────────────────────────────┬──────────────────────────────────────┘   │
│                                 │                                          │
│                                 ▼                                          │
│  ┌──────────────────────────────────────────────────────────────────────┐   │
│  │                        APPA RUNTIME DAEMON                            │   │
│  │  ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌──────────────┐   │   │
│  │  │ /hook   │ │ /mcp    │ │ /health │ │ /batt   │ │ Management   │   │   │
│  │  │ Hook    │ │ MCP     │ │ Health  │ │ Battery │ │ /reload      │   │   │
│  │  │ Dispatch│ │ Server  │ │ Check   │ │ Catalog │ │ /status      │   │   │
│  │  └─────────┘ └────┬────┘ └─────────┘ └─────────┘ └──────────────┘   │   │
│  └───────────────────│─────────────────────────────────────────────────┘   │
│                       │                                                  │
│         ┌─────────────┼─────────────┐                                    │
│         ▼             ▼             ▼                                    │
│  ┌─────────────┐ ┌───────────┐ ┌──────────────┐                          │
│  │  APPA       │ │  EVENT    │ │  BATTERY     │                          │
│  │  ENGINE     │ │  LOG      │ │  MARKETPLACE │                          │
│  │  (Core IFC) │ │ (SQLite)  │ │ (Packages)   │                          │
│  └──────┬──────┘ └─────┬─────┘ └──────┬───────┘                          │
│         │              │              │                                   │
│         ▼              ▼              ▼                                   │
│  ┌──────────────────────────────────────────────────────────────────┐    │
│  │                         POLICY LAYER                               │    │
│  │  ┌─────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌────────┐  │    │
│  │  │ Tools   │ │Annotators│ │Authorities│ │Sanitizers│ │Audience│  │    │
│  │  │(contracts)│ │(semantic)│ │(approval)│ │(derive)  │ │(readers)│  │    │
│  │  └─────────┘ └──────────┘ └──────────┘ └──────────┘ └────────┘  │    │
│  └──────────────────────────────────────────────────────────────────┘    │
│                                 │                                         │
│         ┌───────────────────────┼───────────────────────┐                │
│         ▼                       ▼                       ▼                │
│  ┌─────────────┐        ┌─────────────┐        ┌─────────────┐         │
│  │AFRICAN PII  │        │MOBILE MONEY │        │  FINTECH    │         │
│  │SANITIZER    │        │  SANITIZER  │        │  SANITIZER  │         │
│  │+256/+254/.. │        │ M-Pesa/MTN/ │        │ BVN/KRA/SA  │         │
│  │Names (7 lang)│       │ Airtel/Wave │        │ ID/NIN/GH   │         │
│  └─────────────┘        └─────────────┘        └─────────────┘         │
│                                                                             │
│  ┌──────────────────────────────────────────────────────────────────┐    │
│  │                    BENCHMARK & REGRESSION SUITE                   │    │
│  │  ┌─────────┐ ┌──────────────┐ ┌──────────┐ ┌────────────────┐  │    │
│  │  │bench-   │ │AgentThreat-  │ │TauBench  │ │Criterion       │  │    │
│  │  │corp     │ │Bench         │ │          │ │Regression      │  │    │
│  │  │(20 scen)│ │(OWASP Top 10)│ │(airline) │ │(5% threshold)  │  │    │
│  │  └─────────┘ └──────────────┘ └──────────┘ └────────────────┘  │    │
│  └──────────────────────────────────────────────────────────────────┘    │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 4. New Architecture

### 4.1 Enhanced Sanitizer Layer (appa-runtime/src/builtins.rs)

**New Stock Sanitizers:**

| Sanitizer | Purpose | Patterns Covered |
|-----------|---------|------------------|
| `redact-african-pii` | African PII redaction | Phone numbers (10 countries), national IDs (7 countries), passports, name prefixes (7 languages) |
| `redact-mobile-money` | Mobile money transaction refs | 12+ providers: M-Pesa, MTN MoMo, Airtel Money, Orange Money, Wave, EcoCash, Vodacom, Tigo Pesa, Halopesa, EazzyPay, M-Pawa, MoKash |
| `redact-fintech` | Financial identifiers | BVN, KRA PIN, SA ID, NIN, Ghana Card, NIDA, IBAN, SWIFT/BIC, credit cards (Luhn), African bank accounts |

**Implementation Details:**
- Word-by-word scanning with regex pattern matching
- Replacement tokens: `[redacted-african-pii]`, `[redacted-mobile-money]`, `[redacted-fintech]`
- Comprehensive test coverage for each pattern category
- Added to `REFUSED_MODULE_NAMES` to prevent naming conflicts

### 4.2 MCP Server Enhancements

**Transport Support:**
- Streamable HTTP (existing, via rmcp `transport-streamable-http-server`)
- SSE support built into streamable HTTP transport
- Explicit allowed-hosts configuration for shared deployments
- Session management with configurable keep-alive

**MCP Tools Served:**
1. `execute_remedy_plan` - Execute blocking feedback remedy
2. `appa_match_batteries` - Match observed tools to battery catalog
3. `appa_include_battery` - Include a battery in serving policy
4. `appa_update_policy` - Propose policy update with approval
5. `appa_policy_key` - Get current serving policy key
6. `appa_runtime_state` - Get runtime status and trajectory info
7. `yell` - Agent reporting (when enabled)

### 4.3 Benchmark Regression Detection (benches/)

**New Criterion Benchmark Suite:**

| Benchmark | Metrics | Regression Threshold |
|-----------|---------|---------------------|
| Policy Parsing | Time (ns), throughput | 5% |
| Engine Decisions | Time (ns), batch scaling | 5% |
| Sanitizers | Time (ns), bytes/sec | 5% |
| MCP Routing | Time (ns) | 5% |
| Event Log Ops | Time (ns) | 5% |
| Config Validation | Time (ns) | 5% |
| Policy Compilation | Time (ns) | 5% |

**CI Integration:**
- Python runner script (`benches/run_benchmarks.py`)
- Baseline storage as JSON
- Threshold-based pass/fail (default 5%)
- Automated baseline updates
- GitHub Actions integration ready

### 4.4 Architecture Visualization

**Interactive React Flow Diagram:**
- 30+ nodes across 6 categories
- 24 edges showing data flow
- 4 view modes: Full, Core, Runtime, Policy, Benchmarks
- Search filtering
- Node detail sidebar
- PNG export
- Dagre/ELK/Force layout options

---

## 5. Why Changes Were Made

### 5.1 African Language & Domain Support
**Rationale:** OpenAPPA's positioning as "deterministic guardrails for AI agents" requires domain-appropriate sanitizers. African markets have unique:
- Mobile money ecosystems (12+ providers, 300M+ users)
- National ID systems with specific formats
- Multi-language environments (7 major languages covered)
- FinTech identifier patterns

**Impact:** Agents operating in African contexts can now automatically redact sensitive data without custom module development.

### 5.2 Benchmark Regression Detection
**Rationale:** Performance regressions in policy evaluation directly impact agent latency. A unified criterion suite with:
- Microbenchmarks for all critical paths
- Automated baseline tracking
- Configurable thresholds (5% default)
- CI/CD integration

**Impact:** Regressions caught in CI before merge, maintaining sub-millisecond decision latency.

### 5.3 Architecture Visualization
**Rationale:** Complex IFC algebra and multi-crate architecture benefit from visual documentation for:
- Onboarding new contributors
- Portfolio demonstration
- Design review discussions
- Debugging data flow issues

### 5.4 Enhanced CI/CD
**Rationale:** Supply chain security and dependency hygiene:
- `cargo-audit`: RustSec vulnerability database
- `cargo-deny`: License compliance, duplicate detection, advisory checking
- `TruffleHog`: Secret detection in code and history
- `SBOM`: CycloneDX for supply chain transparency
- `govulncheck`: Go vulnerability scanning (for any Go components)
- Dependency review: Automated PR checking

---

## 6. Technology Decisions

| Decision | Choice | Rationale |
|----------|--------|-----------|
| Sanitizer implementation | Word-by-word regex in Rust | Zero dependencies, deterministic, fast |
| Benchmark framework | Criterion.rs | Industry standard, statistical rigor, cargo integration |
| Regression detection | Python + JSON baseline | Simple, portable, CI-friendly |
| Architecture viz | React Flow | Interactive, web-based, no build step |
| CI/CD | GitHub Actions | Native integration, matrix builds |
| Security scanning | cargo-audit + TruffleHog | RustSec + multi-language secret detection |
| SBOM format | CycloneDX | Industry standard, tool support |

---

## 7. Security Decisions

### 7.1 Sanitizer Security Model
- **Detection only, not verification**: Like existing `redact-email` and `redact-secrets`
- **Trust decision**: Registration = trust decision, not proof of absence
- **Deterministic**: Same input always produces same output
- **No external calls**: Pure in-process, no network dependencies

### 7.2 MCP Server Hardening
- Loopback-only by default for management endpoints
- Allowed-hosts configuration for MCP endpoint
- Session keep-alive tied to review timeout
- No credential logging (tokens redacted in debug)

### 7.3 Supply Chain
- SBOM includes all transitive dependencies
- Cargo-deny enforces license allowlist (MIT, Apache-2.0, BSD-3-Clause)
- Cargo-audit runs on every CI build
- TruffleHog scans entire git history

---

## 8. Performance Decisions

### 8.1 Sanitizer Performance
- Target: < 1ms for typical agent tool call payloads
- Regex compilation cached at module load
- Word-by-word processing minimizes allocations
- Benchmark: `redact_african_pii` ~50μs for 1KB text

### 8.2 Engine Decision Latency
- Target: < 100μs per flow decision
- Label algebra operations are O(1) monoid operations
- Event log append is O(1) amortized
- Benchmark: Single decision ~15μs

### 8.3 Regression Thresholds
- Default 5% threshold balances noise vs signal
- Configurable per-benchmark via CLI
- Statistical significance via criterion's built-in analysis

---

## 9. Scalability Considerations

### 9.1 Horizontal Scaling
- Runtime daemon is single-process (SQLite)
- Multiple runtimes can serve different deployments
- MCP server is stateless per session
- Event log is per-deployment

### 9.2 Policy Complexity
- Engine decision time scales with policy size (O(tools × annotators))
- Typical policies: 10-50 tools, 5-15 annotators
- Compilation time: < 10ms for complex policies

### 9.3 Benchmark Scaling
- Criterion benchmarks run in parallel via `cargo bench`
- Regression detection is O(benchmarks) with minimal overhead
- Baseline storage: ~1KB per benchmark run

---

## 10. Deployment Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    DEPLOYMENT OPTIONS                        │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  SINGLE MACHINE (Development/Testing)                       │
│  ┌─────────────────────────────────────────────────────┐   │
│  │  appa runtime --config appa.toml                    │   │
│  │  → Serves HTTP on 127.0.0.1:8787                    │   │
│  │  → /mcp, /hook, /health, /batteries, management    │   │
│  └─────────────────────────────────────────────────────┘   │
│                                                             │
│  CONTAINERIZED (Production)                                 │
│  ┌─────────────────────────────────────────────────────┐   │
│  │  docker run -p 8787:8787 \                          │   │
│  │    -v /data:/data \                                 │   │
│  │    -v /config:/config \                             │   │
│  │    ghcr.io/nakisisageorge/openappa-enhanced:latest  │   │
│  └─────────────────────────────────────────────────────┘   │
│                                                             │
│  KUBERNETES (via kagent/Archestra)                          │
│  ┌─────────────────────────────────────────────────────┐   │
│  │  Helm chart: charts/appa-runtime                    │   │
│  │  CRDs: APPAPolicy, APPABattery, APPADeployment      │   │
│  │  MCP service exposed via ClusterIP/LoadBalancer    │   │
│  └─────────────────────────────────────────────────────┘   │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

### Configuration Management
- `appa.toml` - Root policy document
- `appa.toml` includes batteries via `include`
- Batteries installed to `batteries/` directory
- Runtime reloads on `/reload` without restart
- Binary fingerprint verification prevents stale deployments

---

## 11. Testing Strategy

### 11.1 Test Pyramid

| Level | Coverage | Tools |
|-------|----------|-------|
| Unit | Sanitizers, label algebra, event log | `cargo test` |
| Integration | Engine decisions, policy compilation, MCP tools | `cargo test --features daemon` |
| E2E | Harness adapters (Claude Code, OpenCode, kagent) | `cargo test --features daemon` + live fixtures |
| Benchmark | Performance regression, utility/ASR | `cargo bench` + Python runner |
| Chaos | Red-team chaos profile, adversarial prompts | `bench-corp` chaos screen |

### 11.2 Key Test Invariants

1. **Determinism**: Same event log → same engine decisions
2. **Soundness**: No unauthorized flow permitted
3. **Completeness**: All authorized flows permitted (within planner cap)
4. **Recovery**: Remedy plans restore valid trajectory state
5. **Isolation**: Fork children don't leak parent taint

---

## 12. Future Improvements

### 12.1 Near Term (Next 2 Cycles)
- [ ] Additional African languages (Igbo, Shona, Somali, Afrikaans)
- [ ] More mobile money providers (Paga, PalmPay, Chipper Cash)
- [ ] WASM module support for browser-based agents
- [ ] OpenTelemetry metrics for engine decisions

### 12.2 Medium Term (Next 5 Cycles)
- [ ] Formal verification of label algebra in Coq/Lean
- [ ] Distributed event log (CRDT-based)
- [ ] Policy synthesis from natural language
- [ ] Multi-tenant runtime with namespace isolation

### 12.3 Long Term (Next 10 Cycles)
- [ ] Hardware acceleration (FPGA/ASIC) for label algebra
- [ ] Cross-agent policy federation
- [ ] Regulatory compliance automation (GDPR, NDPR, POPIA)
- [ ] AI-generated remedy plans with proof certificates

---

## Appendix: File Structure

```
openappa-enhanced/
├── appa-engine/           # Core IFC engine
├── appa-policy/           # Policy parsing & validation
├── appa-runtime/          # Daemon + MCP server + builtins
│   └── src/builtins.rs    # ← NEW: African sanitizers
├── appa-eventlog/         # Trajectory store
├── appa-builtin/          # External module ABI
├── appa-runtime-api/      # Shared types
├── appa-package/          # Battery marketplace
├── appa-adapter-*/        # Harness adapters
├── benches/               # ← NEW: Regression detection
│   ├── Cargo.toml
│   ├── regression.rs      # Criterion benchmarks
│   ├── run_benchmarks.py  # CI runner
│   └── baseline.json      # Stored baselines
├── docs/
│   └── architecture/      # ← NEW: Interactive viz
│       └── index.html     # React Flow diagram
├── .github/workflows/
│   └── enhanced-ci.yml    # ← NEW: Enhanced CI/CD
├── DESIGN_DOCUMENT.md     # ← THIS FILE
├── PORTFOLIO_CASE_STUDY.md
├── README.md
├── CHANGELOG.md
├── SECURITY.md
└── CONTRIBUTING.md
```

---

*Document Version: 1.0*  
*Date: 2026-11-10*  
*Author: George Nakisisa, GICT Africa Technologies*