#!/usr/bin/env python3
"""Validate the seeded BOOM cache-leak positive control and its harness repair."""

from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

MUTATED = "seeded-cache-leak"
REPAIRED = "remove-seeded-cache-leak"


class PositiveControlError(RuntimeError):
    pass


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def load_evidence(path: Path) -> dict:
    try:
        data = json.loads(path.read_text())
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise PositiveControlError(f"cannot read matrix evidence: {exc}") from exc
    if not isinstance(data, dict) or not isinstance(data.get("scenarios"), list):
        raise PositiveControlError("invalid matrix evidence")
    return data


def run_matrix(script: Path, output: Path, variant: str) -> int:
    try:
        result = subprocess.run(
            [str(script), str(output), variant],
            capture_output=True,
            timeout=1800,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise PositiveControlError(f"matrix execution failed: {exc}") from exc
    if len(result.stdout) + len(result.stderr) > 1_048_576:
        raise PositiveControlError("matrix output limit exceeded")
    if result.returncode not in {0, 1}:
        raise PositiveControlError(
            f"matrix exited {result.returncode}: {result.stderr.decode(errors='replace')[-2000:]}"
        )
    return result.returncode


def scenario_map(evidence: dict) -> dict[str, dict]:
    try:
        scenarios = {item["name"]: item for item in evidence["scenarios"]}
    except (KeyError, TypeError) as exc:
        raise PositiveControlError("invalid scenario evidence") from exc
    if len(scenarios) != 2:
        raise PositiveControlError("positive control requires exactly two scenarios")
    return scenarios


def validate_pair(mutated: dict, repaired: dict) -> None:
    for key in ("chipyard_revision", "boom_revision", "config", "simulator_sha256", "repeats"):
        if mutated.get(key) != repaired.get(key):
            raise PositiveControlError(f"matrix provenance differs: {key}")
    if mutated.get("variant") != MUTATED or repaired.get("variant") != REPAIRED:
        raise PositiveControlError("matrix variant provenance mismatch")
    mutated_scenarios = scenario_map(mutated)
    repaired_scenarios = scenario_map(repaired)
    if set(mutated_scenarios) != set(repaired_scenarios):
        raise PositiveControlError("scenario sets differ")
    for name, before in mutated_scenarios.items():
        after = repaired_scenarios[name]
        if before.get("program_sha256") != after.get("program_sha256"):
            raise PositiveControlError(f"program differs across repair: {name}")
        if before.get("deterministic") is not True or before.get("status") != "violation":
            raise PositiveControlError(f"mutation did not produce a repeatable violation: {name}")
        if after.get("deterministic") is not True or after.get("status") != "clean":
            raise PositiveControlError(f"repair did not produce a repeatable clean result: {name}")


def main() -> int:
    try:
        if len(sys.argv) != 2 or not Path(sys.argv[1]).is_absolute():
            raise PositiveControlError("usage: run_positive_control.py /ABSOLUTE/evidence.json")
        manifest = Path(sys.argv[1])
        manifest.parent.mkdir(parents=True, exist_ok=True)
        stem = manifest.with_suffix("")
        mutated_path = stem.with_name(stem.name + "-mutated.json")
        repaired_path = stem.with_name(stem.name + "-repaired.json")
        matrix = Path(__file__).resolve().parent / "run_secure_matrix.py"
        if run_matrix(matrix, mutated_path, MUTATED) != 1:
            raise PositiveControlError("mutated matrix did not report a violation")
        if run_matrix(matrix, repaired_path, REPAIRED) != 0:
            raise PositiveControlError("repaired matrix did not report clean")
        mutated = load_evidence(mutated_path)
        repaired = load_evidence(repaired_path)
        validate_pair(mutated, repaired)
        evidence = {
            "schema_version": 1,
            "experiment": "boom-seeded-cache-leak-positive-control",
            "classification": "intentional-harness-mutation-not-upstream-boom-vulnerability",
            "mutated_variant": MUTATED,
            "repaired_variant": REPAIRED,
            "mutated_evidence": mutated_path.name,
            "mutated_evidence_sha256": digest(mutated_path),
            "repaired_evidence": repaired_path.name,
            "repaired_evidence_sha256": digest(repaired_path),
            "matrix_runner_sha256": digest(matrix),
            "trusted_runner_sha256": mutated["runner_sha256"],
            "simulator_sha256": mutated["simulator_sha256"],
            "completed_at": datetime.now(timezone.utc).isoformat(),  # noqa: UP017 (Python 3.10)
        }
        temporary = manifest.with_suffix(manifest.suffix + ".tmp")
        temporary.write_text(json.dumps(evidence, indent=2) + "\n")
        temporary.replace(manifest)
        print(json.dumps({"mutation": "violation", "repair": "clean"}, indent=2))
        return 0
    except (KeyError, OSError, PositiveControlError) as exc:
        print(f"BOOM positive control: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
