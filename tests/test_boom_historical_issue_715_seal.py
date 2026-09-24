import importlib.util
import json
from pathlib import Path

import pytest

ROOT = Path(__file__).parents[1]
SCRIPT = ROOT / "tools/boom/seal_historical_issue_715.py"
SPEC = importlib.util.spec_from_file_location("seal_historical_issue_715", SCRIPT)
SEAL = importlib.util.module_from_spec(SPEC)
assert SPEC.loader
SPEC.loader.exec_module(SEAL)
PINS = SEAL.pins(ROOT / "tools/boom/historical_pins.env")


def artifacts(tmp_path: Path, violation: bool):
    source = tmp_path / "source.json"
    build = tmp_path / "build.json"
    matrix = tmp_path / "matrix.json"
    source.write_text(
        json.dumps(
            {
                "upstream_issue_url": "https://github.com/riscv-boom/riscv-boom/issues/715",
                "reported_chipyard_revision": PINS["CHIPYARD_REVISION"],
                "reported_boom_revision": PINS["BOOM_REVISION"],
            }
        )
    )
    simulator = "a" * 64
    common = {
        "chipyard_revision": PINS["CHIPYARD_REVISION"],
        "boom_revision": PINS["BOOM_REVISION"],
        "config": PINS["BOOM_CONFIG"],
        "variant": "historical-issue-715-baseline",
    }
    build.write_text(
        json.dumps(
            {**common, "lsu_source_sha256": PINS["BOOM_LSU_SHA256"], "simulator_sha256": simulator}
        )
    )
    runs = [
        {
            "secret": secret,
            "response": {
                "variant": "historical-issue-715-baseline",
                "secret": secret,
                "simulator_sha256": simulator,
                "observation": {
                    "architectural": [],
                    "events": [],
                    "probes": [secret if violation else 0],
                    "completed": True,
                },
            },
        }
        for _ in range(2)
        for secret in (0, 1)
    ]
    matrix.write_text(
        json.dumps(
            {
                **common,
                "classification": "repeatable-violation" if violation else "deterministic-clean",
                "vulnerability_reproduced": violation,
                "runner_sha256": SEAL.digest(ROOT / "tools/boom/historical_issue_715_runner.py"),
                "trusted_runner_sha256": SEAL.digest(ROOT / "tools/boom/trusted_runner.py"),
                "probe_sequences": {"0": [0, 0], "1": [1, 1] if violation else [0, 0]},
                "runs": runs,
            }
        )
    )
    return source, build, matrix


def test_seal_accepts_honest_clean_baseline(tmp_path):
    source, build, matrix = artifacts(tmp_path, False)
    result = SEAL.create_seal(source, build, matrix, ROOT / "tools/boom/historical_pins.env")
    assert result["classification"] == "historical-vulnerability-not-reproduced"
    assert result["security_fix_validated"] is False


def test_seal_rejects_repair_without_baseline_violation(tmp_path):
    source, build, matrix = artifacts(tmp_path, False)
    with pytest.raises(SEAL.SealError, match="without a repeatable"):
        SEAL.create_seal(
            source, build, matrix, ROOT / "tools/boom/historical_pins.env", build, matrix
        )


def test_seal_rejects_simulator_drift(tmp_path):
    source, build, matrix = artifacts(tmp_path, True)
    value = json.loads(matrix.read_text())
    value["runs"][0]["response"]["simulator_sha256"] = "b" * 64
    matrix.write_text(json.dumps(value))
    with pytest.raises(SEAL.SealError, match="simulator mismatch"):
        SEAL.create_seal(source, build, matrix, ROOT / "tools/boom/historical_pins.env")


def test_checked_historical_evidence_verifies():
    evidence = ROOT / "docs/evidence"
    result = SEAL.create_seal(
        evidence / "boom-issue-715-source-2026-09-16.json",
        evidence / "boom-issue-715-historical-build-2026-09-17.json",
        evidence / "boom-issue-715-historical-matrix-2026-09-17.json",
        ROOT / "tools/boom/historical_pins.env",
    )
    checked = json.loads((evidence / "boom-issue-715-historical-seal-2026-09-17.json").read_text())
    result.pop("sealed_at")
    checked.pop("sealed_at")
    assert result == checked
