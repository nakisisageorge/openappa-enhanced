use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use std::sync::Arc;
use std::time::Duration;
use tempfile::tempdir;

use appa_engine::{Engine, DeploymentPolicy, RegistryConfig, ProfileDeclaration, PlannerCap};
use appa_engine::label::Label;
use appa_engine::names::{ToolName, AnnotatorName};
use appa_engine::contract::ToolDeclaration;
use appa_engine::registry::{RecorderName, AnnotatorDeclaration, AudienceVocabulary, TrustChain};
use appa_engine::authority::ContextHint;
use appa_policy::Config;
use appa_runtime::{Runtime, RuntimeToolService, Harness};

/// Benchmark policy parsing and validation
fn bench_policy_parsing(c: &mut Criterion) {
    let mut group = c.benchmark_group("policy_parsing");
    
    // Simple policy
    let simple_policy = r#"
version = 2
trust_chain = ["suspicious", "trusted"]

[[tool]]
name = "read_file"
description = "Read a file"

[[tool]]
name = "write_file"
description = "Write a file"

[deployment]
starting_label = { trust = "trusted", audience = "self" }
"#;
    
    // Complex policy with many tools and annotators
    let complex_policy = r#"
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

[[tool]]
name = "search_web"
description = "Search the web"
delta = { trust = "suspicious", audience = ["public"] }

[[annotator]]
name = "content_classifier"
builtin = "llm"
hint = "Classify content sensitivity"

[[annotator]]
name = "pii_detector"
builtin = "llm"
hint = "Detect PII in content"

[deployment]
starting_label = { trust = "trusted", audience = "self" }
assumed_tools = ["read_file", "write_file"]
provider_run_tools = ["search_web"]
confined_results = ["send_email"]
"#;
    
    for (name, policy) in [("simple", simple_policy), ("complex", complex_policy)] {
        group.bench_function(BenchmarkId::new("parse", name), |b| {
            b.iter(|| {
                let _ = Config::from_toml_str(black_box(policy)).expect("Policy should parse");
            });
        });
    }
    
    group.finish();
}

/// Benchmark engine decision making
fn bench_engine_decisions(c: &mut Criterion) {
    let mut group = c.benchmark_group("engine_decisions");
    
    // Create a test policy
    let policy = Config::from_toml_str(r#"
version = 2
trust_chain = ["suspicious", "untrusted", "internal", "trusted"]

[[tool]]
name = "read_file"
delta = { trust = "internal", audience = ["self"] }

[[tool]]
name = "write_file"
delta = { trust = "trusted", audience = ["self", "internal"] }
requires = { trust = "internal" }

[[tool]]
name = "send_email"
delta = { trust = "trusted", audience = ["internal"] }
requires = { trust = "trusted", audience = { contains = ["internal"] } }

[[annotator]]
name = "classifier"
builtin = "llm"

[deployment]
starting_label = { trust = "trusted", audience = "self" }
assumed_tools = ["read_file"]
"#).expect("Policy should parse");
    
    let engine = policy.engine();
    
    // Benchmark single decision
    group.bench_function("single_decision", |b| {
        b.iter(|| {
            let decision = engine.decide(
                black_box(&ToolName::new("read_file")),
                black_box(&Label::new_trusted_self()),
                black_box(&Label::new_trusted_self()),
            );
            black_box(decision);
        });
    });
    
    // Benchmark batch decisions
    for size in [10, 50, 100] {
        group.bench_function(BenchmarkId::new("batch_decisions", size), |b| {
            b.iter(|| {
                for _ in 0..black_box(size) {
                    let _ = engine.decide(
                        &ToolName::new("read_file"),
                        &Label::new_trusted_self(),
                        &Label::new_trusted_self(),
                    );
                }
            });
        });
    }
    
    group.finish();
}

/// Benchmark sanitizer performance
fn bench_sanitizers(c: &mut Criterion) {
    let mut group = c.benchmark_group("sanitizers");
    
    // Test data of varying sizes
    let small_text = "Contact alice@corp.example for more info";
    let medium_text = " ".repeat(1000).replace(" ", "alice@corp.example ");
    let large_text = " ".repeat(10000).replace(" ", "alice@corp.example ");
    
    let test_cases = [
        ("small", small_text),
        ("medium", &medium_text),
        ("large", &large_text),
    ];
    
    // Test email redaction
    for (name, text) in &test_cases {
        group.throughput(Throughput::Bytes(text.len() as u64));
        group.bench_function(BenchmarkId::new("redact_email", name), |b| {
            b.iter(|| {
                let _ = appa_runtime::builtins::redact_email(black_box(text));
            });
        });
    }
    
    // Test secrets redaction
    let secrets_text = "API_KEY=sk-1234567890abcdef PRIVATE_KEY=-----BEGIN PRIVATE KEY-----\nMIIE...\n-----END PRIVATE KEY-----";
    group.bench_function("redact_secrets", |b| {
        b.iter(|| {
            let _ = appa_runtime::secrets::redact_secrets(black_box(secrets_text));
        });
    });
    
    // Test African PII redaction
    let african_pii_text = "Call +256700123456 or Mzee Juma at ID 12345678901";
    group.bench_function("redact_african_pii", |b| {
        b.iter(|| {
            let _ = appa_runtime::builtins::redact_african_pii(black_box(african_pii_text));
        });
    });
    
    // Test Mobile Money redaction
    let mobile_money_text = "Transaction MP1234567890 completed for MTN123456789012";
    group.bench_function("redact_mobile_money", |b| {
        b.iter(|| {
            let _ = appa_runtime::builtins::redact_mobile_money(black_box(mobile_money_text));
        });
    });
    
    // Test FinTech redaction
    let fintech_text = "BVN 12345678901 KRA PIN A123456789B Card 4111111111111111";
    group.bench_function("redact_fintech", |b| {
        b.iter(|| {
            let _ = appa_runtime::builtins::redact_fintech(black_box(fintech_text));
        });
    });
    
    group.finish();
}

/// Benchmark MCP tool routing
fn bench_mcp_routing(c: &mut Criterion) {
    let mut group = c.benchmark_group("mcp_routing");
    
    let rt = tokio::runtime::Runtime::new().unwrap();
    let db = tempdir().unwrap().path().join("appa.db");
    
    let policy = Config::from_toml_str(r#"
version = 2
trust_chain = ["suspicious", "trusted"]

[[tool]]
name = "execute_remedy_plan"

[deployment]
starting_label = { trust = "trusted", audience = "self" }
"#).expect("Policy should parse");
    
    let runtime = Arc::new(
        Runtime::open(policy, db, None, appa_runtime::describe::served(appa_runtime_api::AdapterName::ClaudeCode))
            .expect("Runtime should open")
    );
    
    let service = RuntimeToolService::new(Arc::clone(&runtime), Harness::ClaudeCode);
    let router = service.tool_router();
    
    // Benchmark tool listing
    group.bench_function("list_tools", |b| {
        b.iter(|| {
            let tools = router.list_all();
            black_box(tools);
        });
    });
    
    // Benchmark tool lookup
    group.bench_function("lookup_tool", |b| {
        b.iter(|| {
            let tool = router.get("execute_remedy_plan");
            black_box(tool);
        });
    });
    
    group.finish();
}

/// Benchmark event log operations
fn bench_event_log(c: &mut Criterion) {
    let mut group = c.benchmark_group("event_log");
    
    let db = tempdir().unwrap().path().join("appa.db");
    let policy = Config::from_toml_str(r#"
version = 2
trust_chain = ["suspicious", "trusted"]

[[tool]]
name = "read_file"
delta = { trust = "internal" }

[deployment]
starting_label = { trust = "trusted", audience = "self" }
"#).expect("Policy should parse");
    
    let runtime = Arc::new(
        Runtime::open(policy, db, None, appa_runtime::describe::served(appa_runtime_api::AdapterName::ClaudeCode))
            .expect("Runtime should open")
    );
    
    // Benchmark event append
    group.bench_function("append_event", |b| {
        b.iter(|| {
            let rt = tokio::runtime::Runtime::new().unwrap();
            rt.block_on(async {
                let _ = runtime.log().append(black_box("test event"), black_box(vec![])).await;
            });
        });
    });
    
    // Benchmark event read
    group.bench_function("read_events", |b| {
        b.iter(|| {
            let rt = tokio::runtime::Runtime::new().unwrap();
            rt.block_on(async {
                let events = runtime.log().recent(black_box(100)).await;
                black_box(events);
            });
        });
    });
    
    group.finish();
}

/// Benchmark configuration validation (describe --check)
fn bench_config_validation(c: &mut Criterion) {
    let mut group = c.benchmark_group("config_validation");
    
    let policies = [
        ("minimal", r#"
version = 2
trust_chain = ["suspicious", "trusted"]

[[tool]]
name = "test"

[deployment]
starting_label = { trust = "trusted", audience = "self" }
"#),
        ("with_annotators", r#"
version = 2
trust_chain = ["suspicious", "untrusted", "internal", "trusted"]

[[tool]]
name = "read_file"
delta = { trust = "internal" }

[[tool]]
name = "write_file"
delta = { trust = "trusted" }
requires = { trust = "internal" }

[[annotator]]
name = "classifier"
builtin = "llm"

[[annotator]]
name = "pii"
builtin = "llm"

[deployment]
starting_label = { trust = "trusted", audience = "self" }
assumed_tools = ["read_file"]
"#),
    ];
    
    for (name, policy) in &policies {
        group.bench_function(BenchmarkId::new("validate", name), |b| {
            b.iter(|| {
                let _ = Config::from_toml_str(black_box(policy)).expect("Should parse");
            });
        });
    }
    
    group.finish();
}

/// Benchmark policy compilation (from raw to engine)
fn bench_policy_compilation(c: &mut Criterion) {
    let mut group = c.benchmark_group("policy_compilation");
    
    let policy = r#"
version = 2
trust_chain = ["suspicious", "untrusted", "internal", "trusted"]

[[tool]]
name = "read_file"
delta = { trust = "internal", audience = ["self"] }

[[tool]]
name = "write_file"
delta = { trust = "trusted", audience = ["self", "internal"] }
requires = { trust = "internal" }

[[tool]]
name = "send_email"
delta = { trust = "trusted", audience = ["internal"] }
requires = { trust = "trusted", audience = { contains = ["internal"] } }

[[tool]]
name = "search_web"
delta = { trust = "suspicious", audience = ["public"] }

[[annotator]]
name = "content_classifier"
builtin = "llm"
hint = "Classify content sensitivity"

[[annotator]]
name = "pii_detector"
builtin = "llm"
hint = "Detect PII in content"

[[authority]]
name = "approver"
permits = { trust_below = "trusted" }

[[sanitizer]]
name = "redact-email"
on = ["tool_output"]

[[sanitizer]]
name = "redact-secrets"
on = ["tool_output"]

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
assumed_tools = ["read_file", "write_file"]
provider_run_tools = ["search_web"]
confined_results = ["send_email"]
"#;
    
    group.bench_function("full_compilation", |b| {
        b.iter(|| {
            let _ = Config::from_toml_str(black_box(policy)).expect("Should compile");
        });
    });
    
    group.finish();
}

criterion_group!(
    benches,
    bench_policy_parsing,
    bench_engine_decisions,
    bench_sanitizers,
    bench_mcp_routing,
    bench_event_log,
    bench_config_validation,
    bench_policy_compilation,
);
criterion_main!(benches);