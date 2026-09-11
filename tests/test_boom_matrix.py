import importlib.util
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).parents[1]
MATRIX_PATH = ROOT / "tools/boom/run_secure_matrix.py"
SPEC = importlib.util.spec_from_file_location("run_secure_matrix", MATRIX_PATH)
assert SPEC and SPEC.loader
MATRIX = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MATRIX)


def observation(probe):
    return {
        "architectural": [],
        "probes": [probe],
        "events": ["load-access-fault"],
        "completed": True,
    }


def test_matrix_classification_requires_repeatability_before_finding():
    assert MATRIX.classify([observation(0), observation(0)] * 2) == {
        "deterministic": True,
        "status": "clean",
    }
    assert MATRIX.classify([observation(0), observation(1)] * 2) == {
        "deterministic": True,
        "status": "violation",
    }
    assert MATRIX.classify([observation(0), observation(0), observation(1), observation(0)]) == {
        "deterministic": False,
        "status": "inconclusive",
    }
    with pytest.raises(MATRIX.MatrixError):
        MATRIX.classify([observation(0)])


def test_matrix_uses_two_fixed_scenarios_and_secret_independent_programs():
    assert set(MATRIX.SCENARIOS) == {"architectural-denial", "transient-window"}
    for program in MATRIX.SCENARIOS.values():
        assert program.count("enter_user") == 1
        assert "load_secret" in program
        assert program[-1] == "probe"


def test_matrix_rejects_runner_provenance_mismatch(tmp_path):
    request = {
        "schema_version": 1,
        "program": ["enter_user"],
        "program_sha256": MATRIX.program_digest(["enter_user"]),
        "secret": 0,
        "variant": "none",
        "target_revision": "revision",
    }
    request_path = tmp_path / "request.json"
    request_path.write_text(json.dumps(request))
    runner = tmp_path / "runner"
    runner.write_text(
        f"#!{sys.executable}\n"
        "import json,sys\n"
        "r=json.load(open(sys.argv[1])); r.update(target='wrong', observation={})\n"
        "print(json.dumps(r))\n"
    )
    runner.chmod(0o755)
    with pytest.raises(MATRIX.MatrixError, match="provenance mismatch"):
        MATRIX.run_request(runner, request_path)
