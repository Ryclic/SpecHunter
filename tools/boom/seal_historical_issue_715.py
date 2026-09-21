#!/usr/bin/env python3
"""Verify and seal the exact historical issue #715 before/after experiment."""

from __future__ import annotations

import hashlib
import json
import sys
from datetime import UTC, datetime
from pathlib import Path


class SealError(RuntimeError):
    pass


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def read(path: Path) -> dict:
    try:
        return json.loads(path.read_text())
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise SealError(f"cannot read {path}: {exc}") from exc


def pins(path: Path) -> dict[str, str]:
    return dict(
        line.split("=", 1)
        for line in path.read_text().splitlines()
        if line and not line.startswith("#")
    )


def validate_pair(build: dict, matrix: dict, expected_variant: str, values: dict[str, str]) -> bool:
    source_hash = (
        values["BOOM_LSU_SHA256"]
        if expected_variant.endswith("baseline")
        else values["BOOM_REPAIRED_LSU_SHA256"]
    )
    expected = {
        "chipyard_revision": values["CHIPYARD_REVISION"],
        "boom_revision": values["BOOM_REVISION"],
        "config": values["BOOM_CONFIG"],
        "variant": expected_variant,
    }
    if any(build.get(key) != value for key, value in expected.items()):
        raise SealError(f"{expected_variant} build provenance mismatch")
    if any(matrix.get(key) != value for key, value in expected.items()):
        raise SealError(f"{expected_variant} matrix provenance mismatch")
    if build.get("lsu_source_sha256") != source_hash:
        raise SealError(f"{expected_variant} source hash mismatch")
    runs = matrix.get("runs")
    if not isinstance(runs, list) or len(runs) != 4:
        raise SealError(f"{expected_variant} must contain four runs")
    if {run.get("secret") for run in runs} != {0, 1}:
        raise SealError(f"{expected_variant} does not cover both secrets")
    if any(
        run.get("response", {}).get("simulator_sha256") != build.get("simulator_sha256")
        for run in runs
    ):
        raise SealError(f"{expected_variant} simulator mismatch")
    probes: dict[int, list[int]] = {0: [], 1: []}
    for run in runs:
        response = run.get("response", {})
        observation = response.get("observation", {})
        secret = run.get("secret")
        if (
            response.get("variant") != expected_variant
            or response.get("secret") != secret
            or observation.get("completed") is not True
            or observation.get("architectural") != []
            or observation.get("events") != []
            or observation.get("probes") not in ([0], [1])
        ):
            raise SealError(f"{expected_variant} contains an invalid observation")
        probes[secret].append(observation["probes"][0])
    if any(len(items) != 2 or len(set(items)) != 1 for items in probes.values()):
        raise SealError(f"{expected_variant} is not repeatable")
    violation = probes[0] != probes[1]
    classification = "repeatable-violation" if violation else "deterministic-clean"
    if (
        matrix.get("classification") != classification
        or matrix.get("vulnerability_reproduced") is not violation
        or matrix.get("probe_sequences") != {str(key): value for key, value in probes.items()}
    ):
        raise SealError(f"{expected_variant} classification does not match raw runs")
    return violation


def create_seal(
    source_path: Path,
    baseline_build_path: Path,
    baseline_matrix_path: Path,
    pin_path: Path,
    repair_build_path: Path | None = None,
    repair_matrix_path: Path | None = None,
) -> dict:
    source = read(source_path)
    baseline_build = read(baseline_build_path)
    baseline = read(baseline_matrix_path)
    values = pins(pin_path)
    if (
        source.get("upstream_issue_url") != "https://github.com/riscv-boom/riscv-boom/issues/715"
        or source.get("reported_chipyard_revision") != values["CHIPYARD_REVISION"]
        or source.get("reported_boom_revision") != values["BOOM_REVISION"]
    ):
        raise SealError("source provenance is not upstream issue #715")
    reproduced = validate_pair(baseline_build, baseline, "historical-issue-715-baseline", values)
    expected_runner = digest(pin_path.parent / "historical_issue_715_runner.py")
    expected_trusted = digest(pin_path.parent / "trusted_runner.py")
    if (
        baseline.get("runner_sha256") != expected_runner
        or baseline.get("trusted_runner_sha256") != expected_trusted
    ):
        raise SealError("baseline runner provenance mismatch")
    repaired = repair_build_path is not None or repair_matrix_path is not None
    if repaired != (repair_build_path is not None and repair_matrix_path is not None):
        raise SealError("repair build and matrix must be supplied together")
    fix_validated = False
    repair_entries: dict[str, str] = {}
    if repaired:
        if not reproduced:
            raise SealError("repair evidence is invalid without a repeatable baseline violation")
        repair_build = read(repair_build_path)
        repair = read(repair_matrix_path)
        repair_violation = validate_pair(
            repair_build, repair, "historical-issue-715-repaired", values
        )
        if (
            repair.get("runner_sha256") != expected_runner
            or repair.get("trusted_runner_sha256") != expected_trusted
        ):
            raise SealError("repair runner provenance mismatch")
        fix_validated = not repair_violation
        if not fix_validated:
            raise SealError("repaired matrix is not deterministically clean")
        repair_entries = {
            "repair_build": repair_build_path.name,
            "repair_build_sha256": digest(repair_build_path),
            "repair_matrix": repair_matrix_path.name,
            "repair_matrix_sha256": digest(repair_matrix_path),
        }
    classification = (
        "historical-vulnerability-and-repair-validated"
        if fix_validated
        else (
            "historical-vulnerability-reproduced-repair-not-run"
            if reproduced
            else "historical-vulnerability-not-reproduced"
        )
    )
    return {
        "schema_version": 1,
        "experiment": "boom-historical-issue-715",
        "classification": classification,
        "vulnerability_reproduced": reproduced,
        "security_fix_validated": fix_validated,
        "source_provenance": source_path.name,
        "source_provenance_sha256": digest(source_path),
        "baseline_build": baseline_build_path.name,
        "baseline_build_sha256": digest(baseline_build_path),
        "baseline_matrix": baseline_matrix_path.name,
        "baseline_matrix_sha256": digest(baseline_matrix_path),
        **repair_entries,
        "pins_sha256": digest(pin_path),
        "sealed_at": datetime.now(UTC).isoformat(),
    }


def main() -> int:
    if len(sys.argv) not in {5, 7} or any(not Path(arg).is_absolute() for arg in sys.argv[1:]):
        print(
            "usage: seal_historical_issue_715.py /SOURCE.json /BASELINE_BUILD.json "
            "/BASELINE_MATRIX.json /OUTPUT.json [/REPAIR_BUILD.json /REPAIR_MATRIX.json]",
            file=sys.stderr,
        )
        return 2
    source, baseline_build, baseline_matrix, output = map(Path, sys.argv[1:5])
    repair = tuple(map(Path, sys.argv[5:7]))
    try:
        seal = create_seal(
            source,
            baseline_build,
            baseline_matrix,
            Path(__file__).resolve().parent / "historical_pins.env",
            *repair,
        )
    except SealError as exc:
        print(f"historical issue #715 seal: {exc}", file=sys.stderr)
        return 2
    output.write_text(json.dumps(seal, indent=2) + "\n")
    print(json.dumps(seal, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
