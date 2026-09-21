import hashlib
import importlib.util
import json
from copy import deepcopy
from pathlib import Path

import pytest

ROOT = Path(__file__).parents[1]
SCRIPT = ROOT / "tools/boom/run_positive_control.py"
SPEC = importlib.util.spec_from_file_location("run_positive_control", SCRIPT)
assert SPEC and SPEC.loader
CONTROL = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CONTROL)


def evidence(variant, status):
    return {
        "variant": variant,
        "chipyard_revision": "chipyard",
        "boom_revision": "boom",
        "config": "SmallBoomV3Config",
        "simulator_sha256": "simulator",
        "repeats": 2,
        "scenarios": [
            {
                "name": name,
                "program_sha256": name + "-program",
                "deterministic": True,
                "status": status,
            }
            for name in ("architectural-denial", "transient-window")
        ],
    }


def test_positive_control_requires_repeatable_violation_then_clean_repair():
    CONTROL.validate_pair(
        evidence(CONTROL.MUTATED, "violation"), evidence(CONTROL.REPAIRED, "clean")
    )
    invalid = evidence(CONTROL.MUTATED, "violation")
    invalid["scenarios"][0]["deterministic"] = False
    with pytest.raises(CONTROL.PositiveControlError, match="repeatable violation"):
        CONTROL.validate_pair(invalid, evidence(CONTROL.REPAIRED, "clean"))


def test_positive_control_rejects_provenance_or_program_drift():
    mutated = evidence(CONTROL.MUTATED, "violation")
    repaired = evidence(CONTROL.REPAIRED, "clean")
    drifted = deepcopy(repaired)
    drifted["simulator_sha256"] = "other"
    with pytest.raises(CONTROL.PositiveControlError, match="provenance differs"):
        CONTROL.validate_pair(mutated, drifted)
    drifted = deepcopy(repaired)
    drifted["scenarios"][0]["program_sha256"] = "other"
    with pytest.raises(CONTROL.PositiveControlError, match="program differs"):
        CONTROL.validate_pair(mutated, drifted)


def test_live_positive_control_evidence_is_hash_bound_and_labeled():
    evidence_dir = ROOT / "docs/evidence"
    manifest = json.loads((evidence_dir / "boom-positive-control.json").read_text())
    assert manifest["classification"] == (
        "intentional-harness-mutation-not-upstream-boom-vulnerability"
    )
    assert (
        manifest["trusted_runner_sha256"]
        == hashlib.sha256((ROOT / "tools/boom/trusted_runner.py").read_bytes()).hexdigest()
    )
    assert (
        manifest["matrix_runner_sha256"]
        == hashlib.sha256((ROOT / "tools/boom/run_secure_matrix.py").read_bytes()).hexdigest()
    )
    for prefix, expected in (("mutated", "violation"), ("repaired", "clean")):
        child = evidence_dir / manifest[f"{prefix}_evidence"]
        assert (
            manifest[f"{prefix}_evidence_sha256"] == hashlib.sha256(child.read_bytes()).hexdigest()
        )
        child_evidence = json.loads(child.read_text())
        assert all(scenario["status"] == expected for scenario in child_evidence["scenarios"])
        assert child_evidence["simulator_sha256"] == manifest["simulator_sha256"]
