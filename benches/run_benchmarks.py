#!/usr/bin/env python3
"""
Benchmark regression detection runner for OpenAPPA Enhanced.

This script runs criterion benchmarks and compares results against a baseline
to detect performance regressions. It can be used in CI/CD pipelines.

Usage:
    python3 run_benchmarks.py [--baseline BASELINE_FILE] [--output OUTPUT_FILE] [--threshold THRESHOLD]
"""

import json
import subprocess
import sys
import os
import argparse
from pathlib import Path
from typing import Dict, Any, Optional
import statistics


def run_criterion_benchmarks(bench_name: str = "") -> Dict[str, Any]:
    """Run criterion benchmarks and return parsed JSON output."""
    cmd = ["cargo", "bench", "--bench", "regression"]
    if bench_name:
        cmd.extend(["--", bench_name])
    cmd.extend(["--output-format", "json"])
    
    result = subprocess.run(cmd, capture_output=True, text=True, cwd=os.path.dirname(__file__))
    
    if result.returncode != 0:
        print(f"Benchmark failed: {result.stderr}", file=sys.stderr)
        return {}
    
    # Parse criterion JSON output
    benchmarks = {}
    for line in result.stdout.strip().split('\n'):
        if line.startswith('{'):
            try:
                data = json.loads(line)
                if 'reason' in data and data['reason'] == 'benchmark-complete':
                    benchmarks[data['id']] = {
                        'mean': data['typical']['estimate'],
                        'lower': data['typical']['lower_bound'],
                        'upper': data['typical']['upper_bound'],
                        'median': data['typical']['median'],
                        'deviation': data['typical']['deviation'],
                        'throughput': data.get('throughput'),
                    }
            except json.JSONDecodeError:
                continue
    
    return benchmarks


def load_baseline(baseline_path: str) -> Dict[str, Any]:
    """Load baseline benchmark results from file."""
    if not os.path.exists(baseline_path):
        return {}
    with open(baseline_path, 'r') as f:
        return json.load(f)


def save_baseline(baseline_path: str, data: Dict[str, Any]) -> None:
    """Save benchmark results as baseline."""
    with open(baseline_path, 'w') as f:
        json.dump(data, f, indent=2)


def compare_benchmarks(current: Dict[str, Any], baseline: Dict[str, Any], threshold: float = 0.05) -> Dict[str, Any]:
    """Compare current benchmarks against baseline and detect regressions."""
    results = {
        'regressions': [],
        'improvements': [],
        'unchanged': [],
        'new': [],
        'missing': [],
    }
    
    all_keys = set(current.keys()) | set(baseline.keys())
    
    for key in all_keys:
        if key not in baseline:
            results['new'].append(key)
            continue
        if key not in current:
            results['missing'].append(key)
            continue
        
        current_mean = current[key]['mean']
        baseline_mean = baseline[key]['mean']
        
        # Calculate relative change (positive = slower/regression)
        change = (current_mean - baseline_mean) / baseline_mean
        
        if change > threshold:
            results['regressions'].append({
                'benchmark': key,
                'baseline_mean': baseline_mean,
                'current_mean': current_mean,
                'change_percent': change * 100,
            })
        elif change < -threshold:
            results['improvements'].append({
                'benchmark': key,
                'baseline_mean': baseline_mean,
                'current_mean': current_mean,
                'change_percent': change * 100,
            })
        else:
            results['unchanged'].append(key)
    
    return results


def print_results(results: Dict[str, Any], threshold: float) -> int:
    """Print comparison results and return exit code (0 = pass, 1 = regressions found)."""
    print(f"\n{'='*60}")
    print(f"Benchmark Regression Detection (threshold: {threshold*100:.1f}%)")
    print(f"{'='*60}")
    
    if results['regressions']:
        print(f"\n❌ REGRESSIONS DETECTED ({len(results['regressions'])}):")
        for r in results['regressions']:
            print(f"  {r['benchmark']}: {r['baseline_mean']:.2f} -> {r['current_mean']:.2f} ({r['change_percent']:+.1f}%)")
    
    if results['improvements']:
        print(f"\n✅ IMPROVEMENTS ({len(results['improvements'])}):")
        for r in results['improvements']:
            print(f"  {r['benchmark']}: {r['baseline_mean']:.2f} -> {r['current_mean']:.2f} ({r['change_percent']:+.1f}%)")
    
    if results['new']:
        print(f"\n🆕 NEW BENCHMARKS ({len(results['new'])}):")
        for b in results['new']:
            print(f"  {b}")
    
    if results['missing']:
        print(f"\n⚠️  MISSING BENCHMARKS ({len(results['missing'])}):")
        for b in results['missing']:
            print(f"  {b}")
    
    if results['unchanged']:
        print(f"\n✓ UNCHANGED ({len(results['unchanged'])} benchmarks)")
    
    print(f"\n{'='*60}")
    
    return 1 if results['regressions'] else 0


def main():
    parser = argparse.ArgumentParser(description='Run benchmark regression detection')
    parser.add_argument('--baseline', default='baseline.json', help='Baseline file path')
    parser.add_argument('--output', default='baseline.json', help='Output baseline file path')
    parser.add_argument('--threshold', type=float, default=0.05, help='Regression threshold (default: 0.05 = 5%)')
    parser.add_argument('--bench', default='', help='Specific benchmark to run')
    parser.add_argument('--update-baseline', action='store_true', help='Update baseline with current results')
    parser.add_argument('--fail-on-regression', action='store_true', default=True, help='Exit with code 1 on regression')
    
    args = parser.parse_args()
    
    # Change to the openappa-enhanced directory
    project_root = Path(__file__).parent.parent
    os.chdir(project_root)
    
    print("Running criterion benchmarks...")
    current = run_criterion_benchmarks(args.bench)
    
    if not current:
        print("No benchmarks found or benchmark failed", file=sys.stderr)
        return 1
    
    print(f"Completed {len(current)} benchmarks")
    
    baseline = load_baseline(args.baseline)
    
    if args.update_baseline or not baseline:
        print("Updating baseline...")
        save_baseline(args.output, current)
        print(f"Baseline saved to {args.output}")
        return 0
    
    results = compare_benchmarks(current, baseline, args.threshold)
    exit_code = print_results(results, args.threshold)
    
    if args.fail_on_regression:
        return exit_code
    return 0


if __name__ == '__main__':
    sys.exit(main())