#!/usr/bin/env python3
"""Seal a successful Vertex-to-BOOM agent run into hash-bound demo evidence."""

from __future__ import annotations

import hashlib
import json
import sys
from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation
from pathlib import Path


class SealError(RuntimeError):
    pass


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def read_json(path: Path) -> dict:
    try:
        value = json.loads(path.read_text())
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise SealError(f"cannot read {path.name}: {exc}") from exc
    if not isinstance(value, dict):
        raise SealError(f"{path.name} must contain an object")
    return value


def validate(report: dict, ledger: dict, positive_control: dict) -> None:
    if (
        report.get("schema_version") != 2
        or report.get("strategy") != "llm"
        or report.get("provider") != "vertex"
        or report.get("provenance", {}).get("kind") != "boom"
        or report.get("provenance", {}).get("is_boom_evidence") is not True
    ):
        raise SealError("report is not a Vertex-to-BOOM run")
    results = report.get("results")
    if not isinstance(results, list) or len(results) != 1:
        raise SealError("demo must contain exactly one benchmark")
    result = results[0]
    if result.get("benchmark", {}).get("id") != "boom-positive-control":
        raise SealError("demo did not target boom-positive-control")
    findings = result.get("findings")
    repair = result.get("repair", {})
    if not isinstance(findings, list) or not findings:
        raise SealError("Vertex did not produce a validated finding")
    witness = findings[0].get("program")
    if (
        not isinstance(witness, list)
        or not all(operation in witness for operation in ("enter_user", "load_secret", "probe"))
        or not witness.index("enter_user") < witness.index("load_secret") < witness.index("probe")
    ):
        raise SealError("finding does not preserve the protected user load")
    if repair != {
        "attempted": True,
        "attacker_exhausted": True,
        "verified": True,
        "final_variant": "remove-seeded-cache-leak",
        "rtl_patch_applied": False,
    }:
        raise SealError("repair did not pass retest and attacker exhaustion")
    transcript = result.get("transcript")
    if not isinstance(transcript, list):
        raise SealError("missing agent transcript")
    stages = [event.get("stage") for event in transcript]
    required = ["recon", "attacker", "validator", "repair", "attacker", "validator", "attacker"]
    cursor = iter(stages)
    if not all(any(stage == expected for stage in cursor) for expected in required):
        raise SealError("transcript does not contain the nested repair-red-team loop")
    repair_events = [event for event in transcript if event.get("stage") == "repair"]
    if not repair_events or repair_events[-1].get("repair_id") != "remove-seeded-cache-leak":
        raise SealError("Vertex did not select the closed positive-control repair")
    repair_index = max(i for i, event in enumerate(transcript) if event.get("stage") == "repair")
    post_repair = transcript[repair_index + 1 :]
    if (
        len(post_repair) < 3
        or post_repair[0].get("stage") != "attacker"
        or post_repair[0].get("rationale") != "mandatory minimized-exploit repair retest"
        or post_repair[0].get("program") != witness
        or post_repair[1].get("stage") != "validator"
        or post_repair[1].get("status") != "clean"
        or post_repair[-1].get("stage") != "attacker"
        or post_repair[-1].get("outcome") != "exhausted"
    ):
        raise SealError("repair was not followed by mandatory clean retest and attacker exhaustion")
    if report.get("metrics", {}).get("repairs_attacker_exhausted") != 1:
        raise SealError("report metrics do not record attacker exhaustion")
    entries = ledger.get("entries")
    if (
        ledger.get("schema_version") != 1
        or not isinstance(entries, list)
        or not entries
        or any(
            entry.get("state") != "settled" or entry.get("outcome") != "success"
            for entry in entries
        )
    ):
        raise SealError("cost ledger is missing or unsettled")
    metrics = report.get("metrics", {})
    cost = report.get("cost", {})
    try:
        accounted = sum(Decimal(entry["amount_usd"]) for entry in entries)
        reported = Decimal(cost["accounted_usd"])
    except (InvalidOperation, KeyError, TypeError) as exc:
        raise SealError("cost accounting is invalid") from exc
    if (
        len(entries) != metrics.get("llm_calls")
        or len(entries) != cost.get("calls")
        or accounted != reported
    ):
        raise SealError("report and settled ledger cost totals differ")
    if positive_control.get("classification") != (
        "intentional-harness-mutation-not-upstream-boom-vulnerability"
    ):
        raise SealError("positive-control evidence is mislabeled")
    if positive_control.get("simulator_sha256") != report.get("provenance", {}).get(
        "simulator_sha256"
    ):
        raise SealError("simulator provenance differs")


def main() -> int:
    try:
        if len(sys.argv) != 5 or any(not Path(value).is_absolute() for value in sys.argv[1:]):
            raise SealError(
                "usage: seal_vertex_demo.py /ABSOLUTE/report.json /ABSOLUTE/ledger.json "
                "/ABSOLUTE/positive-control.json /ABSOLUTE/seal.json"
            )
        report_path, ledger_path, control_path, output = map(Path, sys.argv[1:])
        report = read_json(report_path)
        ledger = read_json(ledger_path)
        control = read_json(control_path)
        if Path(report.get("cost", {}).get("ledger", "")).name != ledger_path.name:
            raise SealError("report does not reference the sealed cost ledger")
        validate(report, ledger, control)
        seal = {
            "schema_version": 1,
            "experiment": "vertex-agent-boom-discovery-repair-red-team-loop",
            "classification": control["classification"],
            "report": report_path.name,
            "report_sha256": digest(report_path),
            "cost_ledger": ledger_path.name,
            "cost_ledger_sha256": digest(ledger_path),
            "positive_control": control_path.name,
            "positive_control_sha256": digest(control_path),
            "provider": report["provider"],
            "model": ledger["entries"][0]["model"],
            "llm_calls": report["metrics"]["llm_calls"],
            "accounted_usd": report["cost"]["accounted_usd"],
            "target_revision": report["provenance"]["target_revision"],
            "completed_at": datetime.now(timezone.utc).isoformat(),  # noqa: UP017 (Python 3.10)
        }
        temporary = output.with_suffix(output.suffix + ".tmp")
        temporary.write_text(json.dumps(seal, indent=2) + "\n")
        temporary.replace(output)
        print(json.dumps({"sealed": True, "llm_calls": seal["llm_calls"]}, indent=2))
        return 0
    except (KeyError, OSError, SealError) as exc:
        print(f"Vertex BOOM demo seal: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
