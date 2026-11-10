#!/usr/bin/env python3
"""
Criterion benchmark configuration for OpenAPPA Enhanced.

This file defines the benchmark structure and creates the necessary
Cargo.toml entries for criterion-based benchmarking with regression detection.
"""

import os
import sys

# This is a configuration script - the actual benchmarks are in benches/regression.rs
# Run with: python3 benches/setup_benchmarks.py

def create_benchmark_cargo_toml():
    """Create or update the benches/Cargo.toml for criterion benchmarks."""
    cargo_toml_content = '''[package]
name = "openappa-benches"
version = "0.1.0"
edition = "2021"
publish = false

[[bench]]
name = "regression"
harness = false

[dependencies]
criterion = { version = "0.8", features = ["cargo_bench_support"] }
appa-engine = { path = "../appa-engine" }
appa-runtime = { path = "../appa-runtime" }
appa-policy = { path = "../appa-policy" }
appa-eventlog = { path = "../appa-eventlog" }
tokio = { version = "1", features = ["rt-multi-thread", "time", "macros", "sync"] }
serde = { version = "1", features = ["derive"] }
serde_json = "1"
uuid = { version = "1", features = ["v4", "serde"] }
tempfile = "3"
'''
    return cargo_toml_content


def main():
    benches_dir = os.path.join(os.path.dirname(__file__))
    
    # Create Cargo.toml for benches
    with open(os.path.join(benches_dir, "Cargo.toml"), "w") as f:
        f.write(create_benchmark_cargo_toml())
    
    print(f"Created {benches_dir}/Cargo.toml")
    print("Now create benches/regression.rs with your benchmarks")
    

if __name__ == "__main__":
    main()