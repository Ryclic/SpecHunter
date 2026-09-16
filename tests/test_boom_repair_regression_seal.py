import importlib.util
import json
from pathlib import Path

import pytest

ROOT = Path(__file__).parents[1]
SCRIPT = ROOT / "tools/boom/seal_repair_regression.py"
SPEC = importlib.util.spec_from_file_location("seal_repair_regression", SCRIPT)
assert SPEC and SPEC.loader
SEAL = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(SEAL)


def write(path, value):
    path.write_text(json.dumps(value))
    return path


def fixture(tmp_path):
    pins = SEAL.load_pins(ROOT / "tools/boom/pins.env")
    common = {
        "chipyard_revision": pins["CHIPYARD_REVISION"],
        "boom_revision": pins["BOOM_REVISION"],
        "config": pins["BOOM_CONFIG"],
    }
    smoke = write(
        tmp_path / "smoke.json",
        {**common, "schema_version": 1, "target": "boom", "simulator_sha256": "a" * 64},
    )

    def matrix(variant):
        return {
            **common,
            "experiment": "boom-secure-control-matched-secret-matrix",
            "variant": variant,
            "repeats": 2,
            "simulator_sha256": "a" * 64 if variant == "none" else "b" * 64,
            "scenarios": [
                {
                    "name": name,
                    "deterministic": True,
                    "status": "clean",
                    "observations": [{}, {}, {}, {}],
                }
                for name in ("architectural-denial", "transient-window")
            ],
        }

    baseline = write(tmp_path / "baseline.json", matrix("none"))
    build = write(
        tmp_path / "build.json",
        {
            **common,
            "variant": "gate-faulting-loads",
            "lsu_source_sha256": pins["BOOM_REPAIRED_LSU_SHA256"],
            "patch_sha256": pins["BOOM_LOAD_GATE_PATCH_SHA256"],
            "simulator_sha256": "b" * 64,
        },
    )
    matrix = write(
        tmp_path / "matrix.json",
        matrix("gate-faulting-loads"),
    )
    return smoke, baseline, build, matrix, pins


def test_seal_distinguishes_clean_regression_from_validated_security_fix(tmp_path):
    smoke, baseline, build, matrix, pins = fixture(tmp_path)
    seal = SEAL.create_seal(smoke, baseline, build, matrix, ROOT / "tools/boom/pins.env")
    assert seal["candidate_build_validated"] is True
    assert seal["target_regression_validated"] is True
    assert seal["security_fix_validated"] is False
    assert seal["patch_sha256"] == pins["BOOM_LOAD_GATE_PATCH_SHA256"]


def test_seal_rejects_dirty_repaired_matrix(tmp_path):
    smoke, baseline, build, matrix, _ = fixture(tmp_path)
    value = json.loads(matrix.read_text())
    value["scenarios"][0]["status"] = "violation"
    write(matrix, value)
    with pytest.raises(SEAL.SealError, match="not deterministic and clean"):
        SEAL.create_seal(smoke, baseline, build, matrix, ROOT / "tools/boom/pins.env")


def test_checked_repair_regression_seal_recomputes_from_raw_evidence():
    evidence = ROOT / "docs/evidence"
    seal_path = evidence / "boom-load-gate-regression-seal-2026-09-16.json"
    checked = json.loads(seal_path.read_text())
    recomputed = SEAL.create_seal(
        evidence / checked["baseline_smoke"],
        evidence / checked["prior_baseline_matrix"],
        evidence / checked["repair_build"],
        evidence / checked["repair_matrix"],
        ROOT / "tools/boom/pins.env",
    )
    assert recomputed == checked
    assert checked["candidate_build_validated"] is True
    assert checked["target_regression_validated"] is True
    assert checked["security_fix_validated"] is False
