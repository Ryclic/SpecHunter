#!/usr/bin/env python3
"""Validate and seal a Vertex agent loop executed through a local CHIA node."""

from __future__ import annotations

import hashlib
import json
import sys
from decimal import Decimal
from pathlib import Path

CLASSIFICATION = "model-fixture-chia-integration-not-real-boom-evidence"


class SealError(RuntimeError):
    pass


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def verify(report: dict, ledger: dict) -> None:
    orchestration = report.get("orchestration", {})
    if orchestration.get("engine") != "chia" or orchestration.get("execution") != "local-ray":
        raise SealError("report lacks local CHIA orchestration provenance")
    if orchestration.get("node") != "run_agent_experiment":
        raise SealError("unexpected CHIA node")
    if not orchestration.get("chialoops_version") or not orchestration.get("ray_version"):
        raise SealError("CHIA dependency provenance is incomplete")
    metrics = report.get("metrics", {})
    if (
        metrics.get("discovered") != 1
        or metrics.get("positive_cases") != 1
        or metrics.get("repairs_attacker_exhausted") != 1
        or metrics.get("inconclusive_cases") != 0
        or metrics.get("llm_calls") != 4
    ):
        raise SealError("CHIA agent loop did not complete successfully")
    results = report.get("results")
    if not isinstance(results, list) or len(results) != 1:
        raise SealError("CHIA report must contain one result")
    result = results[0]
    if not result.get("findings") or result.get("repair", {}).get("verified") is not True:
        raise SealError("CHIA report lacks a verified repair")
    stages = [event.get("stage") for event in result.get("transcript", [])]
    if stages != ["recon", "attacker", "validator", "repair", "attacker", "validator", "attacker"]:
        raise SealError("CHIA transcript does not contain the required nested loop")
    entries = ledger.get("entries")
    if not isinstance(entries, list) or len(entries) != 4:
        raise SealError("CHIA cost ledger must contain four calls")
    if any(
        entry.get("state") != "settled" or entry.get("outcome") != "success" for entry in entries
    ):
        raise SealError("CHIA cost ledger contains an unsettled call")
    accounted = sum(Decimal(entry["amount_usd"]) for entry in entries)
    if accounted != Decimal(report.get("cost", {}).get("accounted_usd", "-1")):
        raise SealError("CHIA report cost differs from ledger")


def main() -> int:
    try:
        if len(sys.argv) != 4 or any(not Path(arg).is_absolute() for arg in sys.argv[1:]):
            raise SealError(
                "usage: seal_chia_vertex_loop.py /ABSOLUTE/report.json "
                "/ABSOLUTE/ledger.json /ABSOLUTE/seal.json"
            )
        report_path, ledger_path, output = map(Path, sys.argv[1:])
        report = json.loads(report_path.read_text())
        ledger = json.loads(ledger_path.read_text())
        verify(report, ledger)
        root = Path(__file__).resolve().parents[1]
        seal = {
            "schema_version": 1,
            "experiment": "vertex-agent-loop-through-chia",
            "classification": CLASSIFICATION,
            "report": report_path.name,
            "report_sha256": digest(report_path),
            "cost_ledger": ledger_path.name,
            "cost_ledger_sha256": digest(ledger_path),
            "chia_nodes_sha256": digest(root / "src/spechunter/chia_nodes.py"),
            "orchestration": report["orchestration"],
            "accounted_usd": report["cost"]["accounted_usd"],
        }
        output.write_text(json.dumps(seal, indent=2) + "\n")
        print(json.dumps({"sealed": True, "orchestration": seal["orchestration"]}, indent=2))
        return 0
    except (OSError, KeyError, json.JSONDecodeError, SealError) as exc:
        print(f"CHIA Vertex loop seal: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
