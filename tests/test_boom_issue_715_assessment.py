import importlib.util
import json
from pathlib import Path

import pytest

ROOT = Path(__file__).parents[1]
SCRIPT = ROOT / "tools/boom/seal_issue_715_assessment.py"
SPEC = importlib.util.spec_from_file_location("seal_issue_715_assessment", SCRIPT)
assert SPEC and SPEC.loader
SEAL = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(SEAL)


def write(path, value):
    path.write_text(json.dumps(value))
    return path


def fixtures(tmp_path):
    pins = SEAL.load_pins(ROOT / "tools/boom/pins.env")
    common = {
        "chipyard_revision": pins["CHIPYARD_REVISION"],
        "boom_revision": pins["BOOM_REVISION"],
        "config": pins["BOOM_CONFIG"],
    }
    source = write(
        tmp_path / "source.json",
        {
            "classification": SEAL.SOURCE_CLASSIFICATION,
            "upstream_issue": "riscv-boom/riscv-boom#715",
            "adaptation_program": SEAL.PROGRAM,
        },
    )
    smoke = write(
        tmp_path / "smoke.json",
        {**common, "target": "boom", "simulator_sha256": "a" * 64},
    )
    matrix = write(
        tmp_path / "matrix.json",
        {
            **common,
            "experiment": "boom-secure-control-matched-secret-matrix",
            "variant": "issue-715-baseline",
            "repeats": 2,
            "simulator_sha256": "a" * 64,
            "runner_sha256": SEAL.digest(ROOT / "tools/boom/trusted_runner.py"),
            "scenarios": [
                {
                    "name": "issue-715-mispredict",
                    "program": SEAL.PROGRAM,
                    "program_sha256": "b" * 64,
                    "deterministic": True,
                    "status": "clean",
                    "observations": [{}, {}, {}, {}],
                }
            ],
        },
    )
    return source, smoke, matrix


def test_seal_records_negative_current_pin_assessment(tmp_path):
    source, smoke, matrix = fixtures(tmp_path)
    seal = SEAL.create_seal(source, smoke, matrix, ROOT / "tools/boom/pins.env")
    assert seal["classification"] == SEAL.CLASSIFICATION
    assert seal["vulnerability_reproduced"] is False
    assert seal["security_fix_validated"] is False
    assert seal["executions"] == 4


@pytest.mark.parametrize("status", ["violation", "inconclusive"])
def test_seal_rejects_non_clean_current_pin_result(tmp_path, status):
    source, smoke, matrix = fixtures(tmp_path)
    changed = json.loads(matrix.read_text())
    changed["scenarios"][0]["status"] = status
    write(matrix, changed)
    with pytest.raises(SEAL.SealError, match="not deterministic and clean"):
        SEAL.create_seal(source, smoke, matrix, ROOT / "tools/boom/pins.env")


def test_seal_rejects_simulator_drift(tmp_path):
    source, smoke, matrix = fixtures(tmp_path)
    changed = json.loads(matrix.read_text())
    changed["simulator_sha256"] = "c" * 64
    write(matrix, changed)
    with pytest.raises(SEAL.SealError, match="differs from smoke"):
        SEAL.create_seal(source, smoke, matrix, ROOT / "tools/boom/pins.env")


def test_checked_assessment_seal_recomputes_from_raw_evidence():
    evidence = ROOT / "docs/evidence"
    seal_path = evidence / "boom-issue-715-assessment-seal-2026-09-16.json"
    checked = json.loads(seal_path.read_text())
    recomputed = SEAL.create_seal(
        evidence / checked["source_provenance"],
        evidence / checked["smoke_evidence"],
        evidence / checked["assessment_matrix"],
        ROOT / "tools/boom/pins.env",
    )
    assert recomputed == checked
    assert checked["vulnerability_reproduced"] is False
    assert checked["security_fix_validated"] is False
