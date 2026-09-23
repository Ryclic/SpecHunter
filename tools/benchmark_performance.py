#!/usr/bin/env python3
"""Microarchitectural verification latency, throughput, and memory benchmarking tool."""

from __future__ import annotations

import argparse
import json
import resource
import time
from pathlib import Path

from spechunter.backends import BackendConfig
from spechunter.chia_nodes import SpecHunterSecurityAuditBlock
from spechunter.loop import experiment


def get_peak_rss_mb() -> float:
    """Return peak resident memory usage in megabytes."""
    return resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024.0


def benchmark_strategy(
    strategy: str,
    iterations: int = 16,
    trials: int = 5,
    benchmark_id: str = "transient-cache",
) -> dict:
    config = BackendConfig("model")
    durations = []
    discovered_list = []
    exec_counts = []

    for seed in range(trials):
        t0 = time.perf_counter()
        report = experiment(
            config=config,
            strategy=strategy,
            iterations=iterations,
            seed=seed,
            benchmark_id=benchmark_id,
        )
        t1 = time.perf_counter()
        durations.append(t1 - t0)
        metrics = report.get("metrics", {})
        discovered_list.append(metrics.get("discovered", 0))
        exec_counts.append(metrics.get("executions", 0))

    avg_duration = sum(durations) / len(durations)
    total_execs = sum(exec_counts)
    throughput = total_execs / sum(durations) if sum(durations) > 0 else 0.0
    discovery_rate = (sum(1 for d in discovered_list if d > 0) / len(discovered_list)) * 100.0

    return {
        "strategy": strategy,
        "trials": trials,
        "avg_duration_sec": round(avg_duration, 4),
        "total_executions": total_execs,
        "sim_throughput_hz": round(throughput, 1),
        "discovery_rate_pct": round(discovery_rate, 1),
        "peak_rss_mb": round(get_peak_rss_mb(), 2),
    }


def benchmark_chia_block(benchmark_id: str = "transient-cache", iterations: int = 4) -> dict:
    t0 = time.perf_counter()
    block = SpecHunterSecurityAuditBlock(
        config=BackendConfig("model"),
        strategy="guided",
        iterations=iterations,
        seed=42,
        benchmark_id=benchmark_id,
    )
    report = block.execute(local=True)
    duration = time.perf_counter() - t0
    metrics = report.get("metrics", {})

    return {
        "target_benchmark": benchmark_id,
        "duration_sec": round(duration, 4),
        "discovered": metrics.get("discovered", 0),
        "executions": metrics.get("executions", 0),
        "engine": report.get("orchestration", {}).get("engine", "unknown"),
        "peak_rss_mb": round(get_peak_rss_mb(), 2),
    }


def run_benchmarks(trials: int = 5, output_path: Path | None = None) -> dict:
    print("=== SpecHunter Microarchitectural Security Performance Benchmark ===")
    print(f"Running {trials} trials per search strategy on 'transient-cache' threat model...\n")

    guided_res = benchmark_strategy("guided", iterations=16, trials=trials)
    random_res = benchmark_strategy("random", iterations=16, trials=trials)
    chia_res = benchmark_chia_block("transient-cache", iterations=4)

    results = {
        "search_strategies": {
            "guided": guided_res,
            "random": random_res,
        },
        "chia_security_block": chia_res,
        "system_peak_rss_mb": round(get_peak_rss_mb(), 2),
    }

    print(
        f"{'Strategy':<12} | {'Avg Latency (s)':<16} | {'Sims / Sec':<12} | "
        f"{'Discovery Rate':<15} | {'Peak RSS (MB)'}"
    )
    print("-" * 80)
    for name, data in [("Guided", guided_res), ("Random", random_res)]:
        row = (
            f"{name:<12} | {data['avg_duration_sec']:<16.4f} | "
            f"{data['sim_throughput_hz']:<12.1f} | "
            f"{data['discovery_rate_pct']:>5.1f}%          | {data['peak_rss_mb']:<10.2f}"
        )
        print(row)
    print("-" * 80)
    chia_line = (
        f"CHIA Security Block Latency: {chia_res['duration_sec']:.4f}s "
        f"({chia_res['executions']} simulations)"
    )
    print(chia_line)
    print(f"Overall Peak Resident Memory: {results['system_peak_rss_mb']} MB")

    if output_path:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(json.dumps(results, indent=2), encoding="utf-8")
        print(f"\n✓ Performance benchmark written to {output_path}")

    return results


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--trials", type=int, default=5, help="Number of benchmark trials")
    parser.add_argument("--output", type=Path, default=Path("artifacts/performance_benchmark.json"))
    args = parser.parse_args()

    run_benchmarks(trials=args.trials, output_path=args.output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
