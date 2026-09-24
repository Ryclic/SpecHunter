#!/usr/bin/env python3
"""Run bounded repeated Vertex discovery/repair loops on the model positive control."""

from __future__ import annotations

import argparse
import hashlib
import json
from datetime import UTC, datetime
from decimal import Decimal
from pathlib import Path

from spechunter.agent_loop import agent_experiment
from spechunter.agents import VertexAgentProvider
from spechunter.backends import BackendConfig

CLASSIFICATION = "model-fixture-repeatability-not-real-boom-evidence"


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def trial_success(report: dict) -> bool:
    metrics = report.get("metrics", {})
    results = report.get("results", [])
    return bool(
        metrics.get("discovered") == 1
        and metrics.get("positive_cases") == 1
        and metrics.get("false_positives") == 0
        and metrics.get("inconclusive_cases") == 0
        and metrics.get("repairs_attacker_exhausted") == 1
        and len(results) == 1
        and results[0].get("repair", {}).get("verified") is True
    )


def summarize(reports: list[dict]) -> dict:
    successes = sum(trial_success(report) for report in reports)
    return {
        "trials": len(reports),
        "successful_full_loops": successes,
        "full_loop_success_rate": successes / len(reports),
        "discoveries": sum(report["metrics"]["discovered"] for report in reports),
        "repairs_attacker_exhausted": sum(
            report["metrics"]["repairs_attacker_exhausted"] for report in reports
        ),
        "inconclusive_cases": sum(report["metrics"]["inconclusive_cases"] for report in reports),
        "llm_calls": sum(report["metrics"]["llm_calls"] for report in reports),
        "fixture_executions": sum(report["metrics"]["executions"] for report in reports),
    }


def write_atomic(path: Path, value: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(value, indent=2) + "\n")
    temporary.replace(path)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path)
    parser.add_argument("--ledger", type=Path, required=True)
    parser.add_argument("--project", default="spechunter")
    parser.add_argument("--location", default="global")
    parser.add_argument("--model", default="gemini-2.5-flash-lite")
    parser.add_argument("--trials", type=int, default=10)
    parser.add_argument("--budget-usd", type=Decimal, default=Decimal("0.05"))
    args = parser.parse_args()
    if not args.output.is_absolute() or not args.ledger.is_absolute():
        parser.error("output and ledger must be absolute paths")
    if not 2 <= args.trials <= 20:
        parser.error("trials must be 2..20")
    root = Path(__file__).resolve().parents[1]
    reports = []
    evidence = {
        "schema_version": 1,
        "experiment": "vertex-agent-loop-repeatability",
        "classification": CLASSIFICATION,
        "model": args.model,
        "benchmark": "boom-positive-control",
        "limits_per_trial": {"recon_cycles": 1, "attack_limit": 4, "repair_limit": 1},
        "provenance": {
            "tool_sha256": digest(Path(__file__)),
            "agent_loop_sha256": digest(root / "src/spechunter/agent_loop.py"),
            "agents_sha256": digest(root / "src/spechunter/agents.py"),
        },
        "trials": reports,
    }
    try:
        for index in range(1, args.trials + 1):
            provider = VertexAgentProvider(
                args.project,
                args.location,
                args.model,
                max_calls=8,
                budget_usd=args.budget_usd,
                ledger_path=args.ledger,
                max_output_tokens=2048,
                retries=2,
            )
            report = agent_experiment(
                provider,
                BackendConfig("model"),
                recon_cycles=1,
                attack_limit=4,
                repair_limit=1,
                benchmark_id="boom-positive-control",
            )
            reports.append({"trial": index, "success": trial_success(report), "report": report})
            evidence["summary"] = summarize([item["report"] for item in reports])
            evidence["cost"] = provider.cost_summary
            write_atomic(args.output, evidence)
        evidence["completed_at"] = datetime.now(UTC).isoformat()
        write_atomic(args.output, evidence)
        print(json.dumps({"summary": evidence["summary"], "cost": evidence["cost"]}, indent=2))
        return 0 if evidence["summary"]["successful_full_loops"] == args.trials else 2
    except (ImportError, OSError, RuntimeError, ValueError) as exc:
        evidence["error"] = str(exc)
        write_atomic(args.output, evidence)
        print(f"Vertex repeatability evaluation: {exc}")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
