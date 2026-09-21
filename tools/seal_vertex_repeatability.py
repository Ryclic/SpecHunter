#!/usr/bin/env python3
"""Validate and seal repeated Vertex fixture-loop evidence and its cost ledger."""

from __future__ import annotations

import hashlib
import json
import sys
from decimal import Decimal
from pathlib import Path

CLASSIFICATION = "model-fixture-repeatability-not-real-boom-evidence"


class SealError(RuntimeError):
    pass


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def verify(evidence: dict, ledger: dict) -> None:
    if evidence.get("experiment") != "vertex-agent-loop-repeatability":
        raise SealError("unsupported repeatability experiment")
    if evidence.get("classification") != CLASSIFICATION:
        raise SealError("repeatability classification differs")
    trials = evidence.get("trials")
    summary = evidence.get("summary", {})
    if not isinstance(trials, list) or len(trials) != 10:
        raise SealError("exactly ten trials are required")
    if summary.get("trials") != 10 or summary.get("successful_full_loops") != 10:
        raise SealError("not every full loop succeeded")
    if summary.get("inconclusive_cases") != 0 or summary.get("llm_calls") != 40:
        raise SealError("unexpected inconclusive case or call count")
    for index, trial in enumerate(trials, 1):
        report = trial.get("report", {})
        metrics = report.get("metrics", {})
        results = report.get("results", [])
        if trial.get("trial") != index or trial.get("success") is not True:
            raise SealError(f"trial {index} is not successful")
        if metrics.get("discovered") != 1 or metrics.get("repairs_attacker_exhausted") != 1:
            raise SealError(f"trial {index} did not complete discovery and red-team repair")
        if metrics.get("inconclusive_cases") != 0 or len(results) != 1:
            raise SealError(f"trial {index} is incomplete")
        if results[0].get("repair", {}).get("verified") is not True:
            raise SealError(f"trial {index} repair is unverified")
    entries = ledger.get("entries")
    if not isinstance(entries, list) or len(entries) != 40:
        raise SealError("cost ledger must contain 40 calls")
    if any(
        entry.get("state") != "settled" or entry.get("outcome") != "success" for entry in entries
    ):
        raise SealError("cost ledger contains an unsettled or unsuccessful call")
    accounted = sum(Decimal(entry["amount_usd"]) for entry in entries)
    if accounted != Decimal(evidence.get("cost", {}).get("accounted_usd", "-1")):
        raise SealError("accounted cost differs from ledger")


def main() -> int:
    try:
        if len(sys.argv) != 4 or any(not Path(arg).is_absolute() for arg in sys.argv[1:]):
            raise SealError(
                "usage: seal_vertex_repeatability.py /ABSOLUTE/evidence.json "
                "/ABSOLUTE/ledger.json /ABSOLUTE/seal.json"
            )
        evidence_path, ledger_path, output = map(Path, sys.argv[1:])
        evidence = json.loads(evidence_path.read_text())
        ledger = json.loads(ledger_path.read_text())
        verify(evidence, ledger)
        seal = {
            "schema_version": 1,
            "experiment": evidence["experiment"],
            "classification": CLASSIFICATION,
            "evidence": evidence_path.name,
            "evidence_sha256": digest(evidence_path),
            "cost_ledger": ledger_path.name,
            "cost_ledger_sha256": digest(ledger_path),
            "model": evidence["model"],
            "trials": 10,
            "llm_calls": 40,
            "accounted_usd": evidence["cost"]["accounted_usd"],
        }
        output.write_text(json.dumps(seal, indent=2) + "\n")
        print(json.dumps({"sealed": True, "trials": 10}, indent=2))
        return 0
    except (OSError, KeyError, json.JSONDecodeError, SealError) as exc:
        print(f"Vertex repeatability seal: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
