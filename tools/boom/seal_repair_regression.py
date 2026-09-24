#!/usr/bin/env python3
"""Seal a built BOOM candidate patch and its clean target regression matrix."""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

CLASSIFICATION = "source-reviewed-candidate-regression-not-validated-security-fix"


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


def validate_matrix(value: dict, variant: str, label: str) -> None:
    scenarios = value.get("scenarios")
    if (
        value.get("experiment") != "boom-secure-control-matched-secret-matrix"
        or value.get("variant") != variant
        or value.get("repeats") != 2
        or not isinstance(scenarios, list)
        or [item.get("name") for item in scenarios] != ["architectural-denial", "transient-window"]
    ):
        raise SealError(f"{label} matrix shape differs")
    for scenario in scenarios:
        observations = scenario.get("observations")
        if (
            scenario.get("deterministic") is not True
            or scenario.get("status") != "clean"
            or not isinstance(observations, list)
            or len(observations) != 4
        ):
            raise SealError(f"{label} matrix is not deterministic and clean")


def create_seal(
    smoke_path: Path,
    baseline_path: Path,
    build_path: Path,
    matrix_path: Path,
    pins_path: Path,
) -> dict:
    smoke = read(smoke_path)
    baseline = read(baseline_path)
    build = read(build_path)
    matrix = read(matrix_path)
    pins = load_pins(pins_path)
    common = {
        "chipyard_revision": pins["CHIPYARD_REVISION"],
        "boom_revision": pins["BOOM_REVISION"],
        "config": pins["BOOM_CONFIG"],
    }
    for name, value in (
        ("smoke", smoke),
        ("baseline", baseline),
        ("build", build),
        ("matrix", matrix),
    ):
        if any(value.get(key) != expected for key, expected in common.items()):
            raise SealError(f"{name} revision provenance differs")
    baseline_hash = smoke.get("simulator_sha256")
    if smoke.get("schema_version") != 1 or smoke.get("target") != "boom":
        raise SealError("baseline smoke shape differs")
    if baseline.get("simulator_sha256") != baseline_hash:
        raise SealError("baseline simulator differs from prior clean matrix")
    validate_matrix(baseline, "none", "baseline")
    if build.get("variant") != "gate-faulting-loads":
        raise SealError("unexpected repair build variant")
    if build.get("lsu_source_sha256") != pins["BOOM_REPAIRED_LSU_SHA256"]:
        raise SealError("repaired LSU source digest differs")
    if build.get("patch_sha256") != pins["BOOM_LOAD_GATE_PATCH_SHA256"]:
        raise SealError("repair patch digest differs")
    repaired_hash = build.get("simulator_sha256")
    if not isinstance(repaired_hash, str) or repaired_hash == baseline_hash:
        raise SealError("repaired simulator is missing or identical to baseline")
    if (
        matrix.get("variant") != "gate-faulting-loads"
        or matrix.get("simulator_sha256") != repaired_hash
    ):
        raise SealError("repaired matrix simulator provenance differs")
    validate_matrix(matrix, "gate-faulting-loads", "repaired")
    return {
        "schema_version": 1,
        "experiment": "boom-candidate-rtl-repair-build-and-regression",
        "classification": CLASSIFICATION,
        "security_fix_validated": False,
        "reason": "the pristine baseline had no repeatable violation for this candidate patch",
        "candidate_build_validated": True,
        "target_regression_validated": True,
        "baseline_smoke": smoke_path.name,
        "baseline_smoke_sha256": digest(smoke_path),
        "prior_baseline_matrix": baseline_path.name,
        "prior_baseline_matrix_sha256": digest(baseline_path),
        "repair_build": build_path.name,
        "repair_build_sha256": digest(build_path),
        "repair_matrix": matrix_path.name,
        "repair_matrix_sha256": digest(matrix_path),
        "baseline_simulator_sha256": baseline_hash,
        "repaired_simulator_sha256": repaired_hash,
        "patch_sha256": pins["BOOM_LOAD_GATE_PATCH_SHA256"],
    }


def main() -> int:
    try:
        if len(sys.argv) != 6 or any(not Path(arg).is_absolute() for arg in sys.argv[1:]):
            raise SealError(
                "usage: seal_repair_regression.py /ABSOLUTE/smoke.json "
                "/ABSOLUTE/baseline-matrix.json /ABSOLUTE/build.json "
                "/ABSOLUTE/repaired-matrix.json /ABSOLUTE/seal.json"
            )
        smoke, baseline, build, matrix, output = map(Path, sys.argv[1:])
        pins = Path(__file__).resolve().parent / "pins.env"
        seal = create_seal(smoke, baseline, build, matrix, pins)
        temporary = output.with_suffix(output.suffix + ".tmp")
        temporary.write_text(json.dumps(seal, indent=2) + "\n")
        temporary.replace(output)
        print(json.dumps({"sealed": True, "security_fix_validated": False}, indent=2))
        return 0
    except (KeyError, OSError, json.JSONDecodeError, SealError) as exc:
        print(f"BOOM repair regression seal: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
