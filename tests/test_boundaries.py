import json
import sys

import pytest

from spechunter.backends import Backend, BackendConfig
from spechunter.cli import main
from spechunter.domain import BENCHMARKS, Observation, Op, Program
from spechunter.loop import validate
from spechunter.process import ExecutionError, run


def test_process_timeout_and_output_limit(tmp_path):
    with pytest.raises(ExecutionError, match="deadline"):
        run([sys.executable, "-c", "import time; time.sleep(10)"], tmp_path, timeout=0.05)
    with pytest.raises(ExecutionError, match="output limit"):
        run([sys.executable, "-c", "print('x' * 10000)"], tmp_path, max_output=100)


def test_process_does_not_inherit_credentials(tmp_path, monkeypatch):
    monkeypatch.setenv("GOOGLE_APPLICATION_CREDENTIALS", "private")
    assert (
        run(
            [
                sys.executable,
                "-c",
                "import os; print(os.environ.get('GOOGLE_APPLICATION_CREDENTIALS'))",
            ],
            tmp_path,
        ).strip()
        == "None"
    )


@pytest.mark.parametrize(
    "change",
    [{"completed": False}, {"probes": [True]}, {"events": "bad"}, {"architectural": [1.5]}],
)
def test_observation_schema(change):
    data = {"architectural": [], "probes": [], "events": [], "completed": True} | change
    with pytest.raises(ValueError):
        Observation.from_dict(data)


def test_boom_provenance_and_failure(tmp_path):
    runner = tmp_path / "runner.py"
    runner.write_text("""import json, sys
r = json.load(open(sys.argv[1]))
r.update(target="boom", observation={"architectural": [], "probes": [],
                                    "events": [], "completed": True},
         simulator_sha256="0" * 64)
print(json.dumps(r))
""")
    config = BackendConfig("boom", (sys.executable, str(runner)), target_revision="test-revision")
    with Backend(config) as backend:
        assert validate(backend, Program((Op.NOP,)), BENCHMARKS[0]).status == "clean"
    runner.write_text("print('{}')")
    with Backend(config) as backend:
        assert validate(backend, Program((Op.NOP,)), BENCHMARKS[0]).status == "inconclusive"


def test_cli_report(tmp_path, monkeypatch):
    output = tmp_path / "report.json"
    monkeypatch.setattr(
        sys, "argv", ["spechunter", "compare", "--iterations", "2", "--output", str(output)]
    )
    assert main() == 0
    reports = json.loads(output.read_text())
    assert [r["strategy"] for r in reports] == ["guided", "random"]


def test_cli_llm_requires_explicit_model(monkeypatch, capsys):
    monkeypatch.setattr(sys, "argv", ["spechunter", "run", "--strategy", "llm"])
    assert main() == 2
    assert "--llm-model is required" in capsys.readouterr().err


def test_cli_boom_defaults_to_secure_control_and_long_timeout(tmp_path, monkeypatch):
    captured = {}

    def fake_experiment(config, strategy, iterations, seed, benchmark_id):
        captured.update(
            timeout=config.timeout_seconds, benchmark=benchmark_id, command=config.command
        )
        return {"strategy": strategy, "metrics": {"inconclusive_cases": 0}}

    runner = tmp_path / "runner"
    runner.write_text("")
    monkeypatch.setattr("spechunter.cli.experiment", fake_experiment)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "spechunter",
            "run",
            "--backend",
            "boom",
            "--runner",
            str(runner),
            "--runner-arg=--project=spechunter",
            "--target-revision",
            "revision",
            "--output",
            str(tmp_path / "report.json"),
        ],
    )
    assert main() == 0
    assert captured == {
        "timeout": 900,
        "benchmark": "secure-control",
        "command": (str(runner), "--project=spechunter"),
    }


def test_parallel_boom_execution_preserves_secret_order(monkeypatch):
    def fake_boom(self, program, secret, bug):
        return Observation((), (secret,), ())

    monkeypatch.setattr(Backend, "_boom", fake_boom)
    config = BackendConfig("boom", ("/trusted/runner",), target_revision="revision")
    with Backend(config) as backend:
        observations = backend.execute_many(Program((Op.NOP,)), [0, 1, 0, 1], "none")
        assert [observation.probes for observation in observations] == [(0,), (1,), (0,), (1,)]
        assert backend.executions == 4
