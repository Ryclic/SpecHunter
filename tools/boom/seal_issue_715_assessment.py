#!/usr/bin/env python3
"""Seal a negative current-pin assessment of upstream BOOM issue #715."""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

SOURCE_CLASSIFICATION = "adapted-upstream-boom-issue-715-reproduction"
CLASSIFICATION = "upstream-issue-715-not-reproduced-on-current-pin"
PROGRAM = ["enter_user", "load_secret", "probe"]


class SealError(RuntimeError):
    pass


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def read(path: Path) -> dict:
    value = json.loads(path.read_text())
    if not isinstance(value, dict):
        raise SealError(f"{path} must contain a JSON object")
    return value


def load_pins(path: Path) -> dict[str, str]:
    pins = {}
    for line in path.read_text().splitlines():
        if line and not line.startswith("#"):
            key, separator, value = line.partition("=")
            if not separator:
                raise SealError("invalid pins.env")
            pins[key] = value
    return pins


def create_seal(source_path: Path, smoke_path: Path, matrix_path: Path, pins_path: Path) -> dict:
    source = read(source_path)
    smoke = read(smoke_path)
    matrix = read(matrix_path)
    pins = load_pins(pins_path)
    if (
        source.get("classification") != SOURCE_CLASSIFICATION
        or source.get("upstream_issue") != "riscv-boom/riscv-boom#715"
        or source.get("adaptation_program") != PROGRAM
    ):
        raise SealError("upstream source provenance differs")
    common = {
        "chipyard_revision": pins["CHIPYARD_REVISION"],
        "boom_revision": pins["BOOM_REVISION"],
        "config": pins["BOOM_CONFIG"],
    }
    for label, value in (("smoke", smoke), ("matrix", matrix)):
        if any(value.get(key) != expected for key, expected in common.items()):
            raise SealError(f"{label} revision provenance differs")
    if smoke.get("target") != "boom" or smoke.get("simulator_sha256") != matrix.get(
        "simulator_sha256"
    ):
        raise SealError("matrix simulator differs from smoke evidence")
    runner_hash = digest(pins_path.parent / "trusted_runner.py")
    if matrix.get("runner_sha256") != runner_hash:
        raise SealError("assessment runner differs from reviewed source")
    scenarios = matrix.get("scenarios")
    if (
        matrix.get("experiment") != "boom-secure-control-matched-secret-matrix"
        or matrix.get("variant") != "issue-715-baseline"
        or matrix.get("repeats") != 2
        or not isinstance(scenarios, list)
        or len(scenarios) != 1
    ):
        raise SealError("assessment matrix shape differs")
    scenario = scenarios[0]
    if (
        scenario.get("name") != "issue-715-mispredict"
        or scenario.get("program") != PROGRAM
        or scenario.get("deterministic") is not True
        or scenario.get("status") != "clean"
        or not isinstance(scenario.get("observations"), list)
        or len(scenario["observations"]) != 4
    ):
        raise SealError("current-pin assessment is not deterministic and clean")
    return {
        "schema_version": 1,
        "experiment": "boom-issue-715-current-pin-assessment",
        "classification": CLASSIFICATION,
        "upstream_issue": source["upstream_issue"],
        "vulnerability_reproduced": False,
        "security_fix_validated": False,
        "reason": "the reviewed adaptation was deterministic and clean on the current pin",
        "source_provenance": source_path.name,
        "source_provenance_sha256": digest(source_path),
        "smoke_evidence": smoke_path.name,
        "smoke_evidence_sha256": digest(smoke_path),
        "assessment_matrix": matrix_path.name,
        "assessment_matrix_sha256": digest(matrix_path),
        "program_sha256": scenario["program_sha256"],
        "simulator_sha256": matrix["simulator_sha256"],
        "runner_sha256": runner_hash,
        "executions": len(scenario["observations"]),
    }


def main() -> int:
    try:
        if len(sys.argv) != 5 or any(not Path(arg).is_absolute() for arg in sys.argv[1:]):
            raise SealError(
                "usage: seal_issue_715_assessment.py /ABSOLUTE/source.json "
                "/ABSOLUTE/smoke.json /ABSOLUTE/matrix.json /ABSOLUTE/seal.json"
            )
        source, smoke, matrix, output = map(Path, sys.argv[1:])
        pins = Path(__file__).resolve().parent / "pins.env"
        seal = create_seal(source, smoke, matrix, pins)
        temporary = output.with_suffix(output.suffix + ".tmp")
        temporary.write_text(json.dumps(seal, indent=2) + "\n")
        temporary.replace(output)
        print(json.dumps({"sealed": True, "vulnerability_reproduced": False}, indent=2))
        return 0
    except (KeyError, OSError, json.JSONDecodeError, SealError) as exc:
        print(f"BOOM issue #715 assessment seal: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
