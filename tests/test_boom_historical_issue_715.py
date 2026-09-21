import hashlib
import importlib.util
import json
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).parents[1]
RUNNER_PATH = ROOT / "tools/boom/historical_issue_715_runner.py"
SPEC = importlib.util.spec_from_file_location("historical_issue_715_runner", RUNNER_PATH)
RUNNER = importlib.util.module_from_spec(SPEC)
assert SPEC.loader
SPEC.loader.exec_module(RUNNER)


def request(tmp_path: Path, **changes) -> Path:
    program = ["enter_user", "load_secret", "probe"]
    value = {
        "schema_version": 1,
        "program": program,
        "program_sha256": hashlib.sha256(json.dumps(program).encode()).hexdigest(),
        "secret": 0,
        "variant": RUNNER.BASELINE,
        "target_revision": "004297b6a8c01be1b2110c4cf4f9393ae1ff8805",
    }
    value.update(changes)
    path = tmp_path / "request.json"
    path.write_text(json.dumps(value))
    return path


def test_historical_pins_and_patch_are_hash_bound():
    pins = RUNNER.load_pins(ROOT / "tools/boom/historical_pins.env")
    patch = ROOT / "tools/boom/patches/issue_715_historical_gate_faulting_loads.patch"
    assert pins["CHIPYARD_REVISION"] == "004297b6a8c01be1b2110c4cf4f9393ae1ff8805"
    assert pins["BOOM_REVISION"] == "fac2c370c9deae97ca52aca6b34857e9ac0f6e9d"
    assert hashlib.sha256(patch.read_bytes()).hexdigest() == pins["BOOM_LOAD_GATE_PATCH_SHA256"]


def test_historical_request_accepts_only_closed_program(tmp_path):
    pins = RUNNER.load_pins(ROOT / "tools/boom/historical_pins.env")
    assert RUNNER.validate_request(request(tmp_path), pins)["variant"] == RUNNER.BASELINE
    with pytest.raises(RUNNER.TRUSTED.RunnerError, match="fixed program"):
        RUNNER.validate_request(request(tmp_path, program=["enter_user", "probe"]), pins)


def test_historical_request_rejects_unbound_digest(tmp_path):
    pins = RUNNER.load_pins(ROOT / "tools/boom/historical_pins.env")
    with pytest.raises(RUNNER.TRUSTED.RunnerError, match="digest"):
        RUNNER.validate_request(request(tmp_path, program_sha256="0" * 64), pins)


def test_historical_candidate_contains_faulting_transient_gadget():
    assembly = RUNNER.TRUSTED.render_issue_715_candidate(1)
    assert "ld s1, 0(s2)" in assembly
    assert "lbu zero, 0(t0)" in assembly
    assert "beqz s6, .Lissue715_correct_path" in assembly


def test_repaired_install_preserves_porcelain_status_column(tmp_path, monkeypatch):
    chipyard = tmp_path / "chipyard"
    boom = chipyard / "generators/boom"
    source = boom / "src/main/scala/lsu/lsu.scala"
    source.parent.mkdir(parents=True)
    subprocess.run(["git", "init", "-q", chipyard], check=True)
    subprocess.run(["git", "init", "-q", boom], check=True)
    source.write_text("baseline\n")
    subprocess.run(["git", "-C", boom, "add", "."], check=True)
    subprocess.run(
        [
            "git",
            "-C",
            boom,
            "-c",
            "user.name=test",
            "-c",
            "user.email=test@example.com",
            "commit",
            "-qm",
            "baseline",
        ],
        check=True,
    )
    (chipyard / "marker").write_text("chipyard\n")
    subprocess.run(["git", "-C", chipyard, "add", "marker"], check=True)
    subprocess.run(
        [
            "git",
            "-C",
            chipyard,
            "-c",
            "user.name=test",
            "-c",
            "user.email=test@example.com",
            "commit",
            "-qm",
            "pin",
        ],
        check=True,
    )
    source.write_text("repaired\n")
    diff = subprocess.run(
        ["git", "-C", boom, "diff", "--", "src/main/scala/lsu/lsu.scala"],
        capture_output=True,
        check=True,
    ).stdout
    pins = {
        "CHIPYARD_REVISION": subprocess.check_output(
            ["git", "-C", chipyard, "rev-parse", "HEAD"], text=True
        ).strip(),
        "BOOM_REVISION": subprocess.check_output(
            ["git", "-C", boom, "rev-parse", "HEAD"], text=True
        ).strip(),
        "BOOM_LSU_SHA256": "unused",
        "BOOM_REPAIRED_LSU_SHA256": hashlib.sha256(source.read_bytes()).hexdigest(),
        "BOOM_LOAD_GATE_PATCH_SHA256": hashlib.sha256(diff).hexdigest(),
    }
    monkeypatch.setattr(RUNNER, "git_output", RUNNER.git_output)
    RUNNER.validate_install(chipyard, pins, RUNNER.REPAIRED)
