#!/usr/bin/env python3
"""Validate and seal the reproducible fixture comparison artifact."""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

CLASSIFICATION = "deterministic-fixture-evaluation-not-real-boom-evidence"


class SealError(RuntimeError):
    pass


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def verify(report: dict, root: Path) -> None:
    if report.get("experiment") != "fixture-guided-vs-random-evaluation":
        raise SealError("unsupported evaluation experiment")
    if report.get("classification") != CLASSIFICATION:
        raise SealError("evaluation classification differs")
    trials = report.get("random_trials")
    seeds = report.get("random_seeds", {})
    if not isinstance(trials, list) or len(trials) < 1000 or seeds.get("count") != len(trials):
        raise SealError("evaluation requires at least 1000 recorded random trials")
    if [trial.get("seed") for trial in trials] != list(range(len(trials))):
        raise SealError("random seed sequence differs")
    random = report.get("random", {})
    discoveries = sum(trial.get("positive_discoveries", -1) for trial in trials)
    false_positives = sum(trial.get("false_positives", -1) for trial in trials)
    if random.get("discoveries") != discoveries or random.get("positive_cases") != 2 * len(trials):
        raise SealError("random discovery summary differs from trials")
    if random.get("false_positives") != false_positives:
        raise SealError("random false-positive summary differs from trials")
    provenance = report.get("provenance", {})
    for field, relative in (
        ("evaluator_sha256", "src/spechunter/evaluation.py"),
        ("loop_sha256", "src/spechunter/loop.py"),
        ("domain_sha256", "src/spechunter/domain.py"),
    ):
        if provenance.get(field) != digest(root / relative):
            raise SealError(f"{field} differs")


def main() -> int:
    try:
        if len(sys.argv) != 3 or any(not Path(arg).is_absolute() for arg in sys.argv[1:]):
            raise SealError(
                "usage: seal_fixture_evaluation.py /ABSOLUTE/report.json /ABSOLUTE/seal.json"
            )
        report_path, output = map(Path, sys.argv[1:])
        report = json.loads(report_path.read_text())
        if not isinstance(report, dict):
            raise SealError("evaluation must contain a JSON object")
        root = Path(__file__).resolve().parents[1]
        verify(report, root)
        seal = {
            "schema_version": 1,
            "experiment": report["experiment"],
            "classification": CLASSIFICATION,
            "evaluation": report_path.name,
            "evaluation_sha256": digest(report_path),
            "random_trials": len(report["random_trials"]),
        }
        output.write_text(json.dumps(seal, indent=2) + "\n")
        print(json.dumps({"sealed": True, "random_trials": len(report["random_trials"])}, indent=2))
        return 0
    except (OSError, json.JSONDecodeError, SealError) as exc:
        print(f"fixture evaluation seal: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
