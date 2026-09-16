"""Reproducible quantitative comparison for the deterministic fixture benchmark."""

from __future__ import annotations

import math
import statistics
from datetime import UTC, datetime
from hashlib import sha256
from pathlib import Path

from spechunter.backends import BackendConfig
from spechunter.loop import experiment

BENCHMARKS = ("privilege-bypass", "transient-cache", "secure-control")


def _wilson(successes: int, total: int, z: float = 1.959963984540054) -> list[float]:
    if total <= 0 or not 0 <= successes <= total:
        raise ValueError("invalid binomial sample")
    rate = successes / total
    denominator = 1 + z * z / total
    center = (rate + z * z / (2 * total)) / denominator
    margin = z * math.sqrt(rate * (1 - rate) / total + z * z / (4 * total * total))
    margin /= denominator
    return [max(0.0, center - margin), min(1.0, center + margin)]


def _run(strategy: str, seed: int, iterations: int) -> dict:
    reports = [
        experiment(BackendConfig("model"), strategy, iterations, seed, benchmark)
        for benchmark in BENCHMARKS
    ]
    positives = reports[:2]
    negative = reports[2]
    attempts = [len(report["results"][0]["attempts"]) for report in positives]
    return {
        "seed": seed,
        "positive_discoveries": sum(report["metrics"]["discovered"] for report in positives),
        "positive_cases": 2,
        "false_positives": negative["metrics"]["false_positives"],
        "negative_cases": 1,
        "inconclusive_cases": sum(report["metrics"]["inconclusive_cases"] for report in reports),
        "executions": sum(report["metrics"]["executions"] for report in reports),
        "positive_attempts": attempts,
    }


def _summarize(runs: list[dict], stochastic: bool) -> dict:
    discoveries = sum(run["positive_discoveries"] for run in runs)
    positives = sum(run["positive_cases"] for run in runs)
    false_positives = sum(run["false_positives"] for run in runs)
    negatives = sum(run["negative_cases"] for run in runs)
    executions = [run["executions"] for run in runs]
    attempts = [attempt for run in runs for attempt in run["positive_attempts"]]
    summary = {
        "trials": len(runs),
        "positive_cases": positives,
        "discoveries": discoveries,
        "discovery_rate": discoveries / positives,
        "negative_cases": negatives,
        "false_positives": false_positives,
        "false_positive_rate": false_positives / negatives,
        "inconclusive_cases": sum(run["inconclusive_cases"] for run in runs),
        "executions_mean": statistics.fmean(executions),
        "executions_median": statistics.median(executions),
        "positive_attempts_mean": statistics.fmean(attempts),
        "positive_attempts_median": statistics.median(attempts),
    }
    if stochastic:
        summary["discovery_rate_wilson_95"] = _wilson(discoveries, positives)
        summary["false_positive_rate_wilson_95"] = _wilson(false_positives, negatives)
    return summary


def evaluate(trials: int = 100, iterations: int = 16) -> dict:
    if not 2 <= trials <= 10_000:
        raise ValueError("evaluation trials must be 2..10000")
    if not 1 <= iterations <= 1000:
        raise ValueError("iterations must be 1..1000")
    guided = [_run("guided", 0, iterations)]
    random_runs = [_run("random", seed, iterations) for seed in range(trials)]
    package = Path(__file__).resolve().parent
    return {
        "schema_version": 1,
        "experiment": "fixture-guided-vs-random-evaluation",
        "classification": "deterministic-fixture-evaluation-not-real-boom-evidence",
        "benchmark_ids": list(BENCHMARKS),
        "iteration_limit": iterations,
        "random_seeds": {"first": 0, "last": trials - 1, "count": trials},
        "provenance": {
            "backend": "deterministic-model-fixture",
            "evaluator_sha256": sha256(Path(__file__).read_bytes()).hexdigest(),
            "loop_sha256": sha256((package / "loop.py").read_bytes()).hexdigest(),
            "domain_sha256": sha256((package / "domain.py").read_bytes()).hexdigest(),
        },
        "guided": _summarize(guided, stochastic=False),
        "random": _summarize(random_runs, stochastic=True),
        "random_trials": random_runs,
        "completed_at": datetime.now(UTC).isoformat(),
    }
