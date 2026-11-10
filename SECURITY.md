# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 0.41.x  | ✅ Yes             |
| < 0.41  | ❌ No              |

## Reporting a Vulnerability

We take security vulnerabilities seriously. If you discover a security vulnerability in OpenAPPA Enhanced, please report it responsibly.

### How to Report

**Email:** security@gictafrica.com (PGP key available on request)

**Please include:**
- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)
- Your contact information for follow-up

### Response Timeline

- **Acknowledgment:** Within 48 hours
- **Initial Assessment:** Within 1 week
- **Fix Timeline:** Depends on severity (see below)

### Severity Classification

| Severity | Description | Target Fix |
|----------|-------------|------------|
| Critical | Remote code execution, authentication bypass, data exfiltration | 72 hours |
| High     | Privilege escalation, significant data exposure | 1 week |
| Medium   | Information disclosure, DoS, logic bypass | 2 weeks |
| Low      | Minor issues, defense-in-depth improvements | Next release |

---

## Threat Model

### Assets Protected

1. **Agent Trajectory Data** — Event logs, tool calls, emissions, fork bindings
2. **Policy Configuration** — Trust chains, tool declarations, deployment profiles
3. **Sanitizer Output** — Redacted PII, secrets, financial identifiers
4. **MCP Communications** — Tool invocations, remedy plans, battery matching
5. **Deployment Integrity** — Binary fingerprints, policy keys, battery digests

### Trust Boundaries

```
┌─────────────────────────────────────────────────────────────┐
│                    HARNESS (Untrusted)                      │
│  Claude Code / OpenCode / Amp / kagent                      │
└──────────────────────────┬──────────────────────────────────┘
                           │ Hook Events / MCP Calls
                           ▼
┌─────────────────────────────────────────────────────────────┐
│                  APPA RUNTIME (Trusted)                     │
│  ┌─────────────┐ ┌─────────────┐ ┌─────────────────────┐   │
│  │ Hook        │ │ MCP Server  │ │ Management API      │   │
│  │ Dispatcher  │ │ (HTTP/SSE)  │ │ (Loopback Only)     │   │
│  └─────────────┘ └─────────────┘ └─────────────────────┘   │
│                           │                                 │
│                           ▼                                 │
│  ┌─────────────────────────────────────────────────────┐   │
│  │              APPA ENGINE (Core IFC)                  │   │
│  │  • Label Algebra (audience × trust monoids)         │   │
│  │  • Event Log (conditional append)                   │   │
│  │  • Policy Registry (validated declarations)         │   │
│  └─────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────┘
```

### Threat Scenarios & Mitigations

| Threat | Scenario | Mitigation |
|--------|----------|------------|
| **Sanitizer Bypass** | Adversarial input evades regex patterns | Deterministic regex; registration = trust decision; same input → same output |
| **Policy Tampering** | Modified TOML loaded at runtime | Binary fingerprint verification; `/reload` requires loopback |
| **MCP Hijacking** | Unauthorized client calls MCP tools | Allowed-hosts config; loopback-only management endpoints |
| **Supply Chain** | Malicious dependency injected | cargo-audit, cargo-deny, TruffleHog, SBOM in CI |
| **Secret Leakage** | Credentials in logs/history | TruffleHog scans history; tokens redacted in debug output |
| **Replay Attack** | Captured hook event replayed | Trajectory IDs bound to session; conditional append |
| **Fork Escape** | Child trajectory contaminates parent | Seal-bound spawn bindings; recovery semantics |

---

## Sanitizer Security Model

### Design Principles

1. **Detection, Not Verification** — Sanitizers are *trust decisions*, not proofs of absence. Registration implies trust in the detector.

2. **Deterministic** — Same input always produces same output. No ML, no probabilistic classifiers.

3. **In-Process Only** — No external calls, no network dependencies. Pure Rust regex.

3. **Word-Boundary Scanning** — Token-based to avoid partial matches.

### Sanitizer Coverage

| Sanitizer | Patterns | Replacement Token |
|-----------|----------|-------------------|
| `redact-email` | Email-like tokens | `[redacted-email]` |
| `redact-secrets` | Private keys, tokens, AWS keys, high-entropy runs | `[redacted-secret]` |
| `redact-african-pii` | Phone (+256, +254, +234, +27, +233, +255, +251, +263, +258, +267), national IDs (BVN, KRA PIN, SA ID, NIN, Ghana Card, NIDA, Ethiopian ID), passports, name prefixes (7 languages) | `[redacted-african-pii]` |
| `redact-mobile-money` | 12+ providers (M-Pesa, MTN MoMo, Airtel, Orange, Wave, EcoCash, Vodacom, Tigo, Halopesa, EazzyPay, M-Pawa, MoKash) | `[redacted-mobile-money]` |
| `redact-fintech` | BVN, KRA PIN, SA ID, NIN, Ghana Card, NIDA, IBAN, SWIFT/BIC, credit cards (Luhn), African bank accounts | `[redacted-fintech]` |

### Limitations

- **Not a substitute for proper data handling** — Sanitizers reduce risk but don't eliminate need for secure architecture
- **Pattern-based** — Novel formats not in regex won't be caught
- **Context-unaware** — Operates on word tokens, not semantic understanding
- **Trust decision required** — Deployer must evaluate if sanitizer coverage is sufficient for their threat model

---

## Supply Chain Security

### CI/CD Security Gates

| Check | Tool | Frequency |
|-------|------|-----------|
| Vulnerability Scanning | `cargo-audit` (RustSec) | Every build |
| License Compliance | `cargo-deny` (allowlist) | Every build |
| Dependency Policy | `cargo-deny` (duplicates, advisories) | Every build |
| Secret Detection | `TruffleHog` (code + history) | Every build |
| SBOM Generation | `cargo-cyclonedx` (CycloneDX) | Every release |
| Dependency Review | GitHub Action | Every PR |
| Go Vulnerabilities | `govulncheck` | Every build |

### Dependency Policy

- **Allowed Licenses:** MIT, Apache-2.0, BSD-2-Clause, BSD-3-Clause, ISC, Unicode-DFS-2016
- **Denied Licenses:** GPL, AGPL, LGPL, MPL, custom/non-OSI
- **Maximum Duplicates:** 0 (cargo-deny enforces)
- **Security Advisories:** Block on any unpatched RUSTSEC advisory

### SBOM

Software Bill of Materials generated in **CycloneDX** format for every release:

```bash
cargo cyclonedx --format json --output-target sbom.json
```

---

## Deployment Security

### Runtime Hardening

- **Loopback-only management endpoints** (`/reload`, `/status`, `/policy-key`, `/binary-fingerprint`, `/prerequisites`, `/battery-check`)
- **Allowed-hosts for MCP** — Configure via `APPA_MCP_ALLOWED_HOST` or `--mcp-allowed-host`
- **Binary fingerprint verification** — Installation verifies deployed binary matches expected digest
- **Session keep-alive** — Tied to review timeout + 60s grace
- **No credential logging** — Tokens redacted in all debug output

### Configuration Security

```toml
# Example secure deployment config
[deployment]
starting_label = { trust = "trusted", audience = "self" }
assumed_tools = ["read_file"]
provider_run_tools = ["search_web"]
confined_results = ["send_email"]
# Never expose management endpoints publicly
```

### Network Architecture

```
                    ┌─────────────────┐
                    │  Load Balancer  │
                    │  (TLS Termination)
                    └────────┬────────┘
                             │
                    ┌────────▼────────┐
                    │  APPA Runtime   │
                    │  (Container/VM) │
                    │                 │
                    │  :8787          │
                    │  /hook          │◄── Harness adapters
                    │  /mcp           │◄── MCP clients
                    │  /health        │◄── Health checks
                    │  /batteries     │◄── Battery catalog
                    │                 │
                    │  127.0.0.1:8787 │
                    │  /reload        │◄── Loopback only
                    │  /status        │◄── Loopback only
                    │  /policy-key    │◄── Loopback only
                    └─────────────────┘
```

---

## Compliance

### Data Protection

| Regulation | Coverage |
|------------|----------|
| **GDPR** (EU) | Sanitizers redact PII; trajectory data minimized; right to erasure via log truncation |
| **NDPR** (Nigeria) | African PII sanitizer covers Nigerian identifiers (BVN, NIN, phone) |
| **POPIA** (South Africa) | SA ID sanitizer; trajectory access controls |
| **Data Protection Act** (Kenya) | KRA PIN, Huduma Namba, phone number sanitization |

### Industry Standards

- **OWASP Top 10 for LLM Applications** — Benchmarked via AgentThreatBench (0% ASR)
- **NIST AI RMF** — Deterministic IFC provides governance, mapping, measurement
- **ISO 27001** — Supply chain controls, access management, incident response ready

---

## Incident Response

### Escalation Contacts

| Role | Contact | PGP |
|------|---------|-----|
| Security Lead | George Nakisisa | On request |
| Maintainer | nakisisageorge@gmail.com | On request |

### Response Procedure

1. **Contain** — Disable affected endpoints, rotate credentials
2. **Assess** — Determine scope, impact, root cause
3. **Remediate** — Develop and test fix
4. **Deploy** — Release patch with security advisory
5. **Notify** — Affected users, GitHub Security Advisories
6. **Review** — Post-incident review within 2 weeks

---

## Security Checklist for Deployers

- [ ] Run `cargo audit` before deployment
- [ ] Configure `APPA_MCP_ALLOWED_HOST` for your domain
- [ ] Ensure management endpoints (`/reload`, etc.) are loopback-only
- [ ] Enable TLS termination at load balancer
- [ ] Set up log monitoring for hook/MCP anomalies
- [ ] Regularly update dependencies (`cargo update`)
- [ ] Review sanitizer coverage for your threat model
- [ ] Test policy changes in staging with `appa describe --check`
- [ ] Verify binary fingerprint matches release artifact
- [ ] Subscribe to GitHub Security Advisories for this repo

---

## Contact

**Security Email:** security@gictafrica.com  
**Maintainer:** George Nakisisa (nakisisageorge@gmail.com)  
**Company:** GICT Africa Technologies  
**Location:** Kampala, Uganda 🇺🇬

*Last Updated: 2026-11-10*