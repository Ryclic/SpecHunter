import hashlib
import importlib.util
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).parents[1]
RUNNER_PATH = ROOT / "tools/boom/trusted_runner.py"
SPEC = importlib.util.spec_from_file_location("trusted_runner", RUNNER_PATH)
assert SPEC and SPEC.loader
RUNNER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(RUNNER)


def request(program=None, **changes):
    program = program or ["enter_user", "load_secret", "encode", "squash", "probe"]
    value = {
        "schema_version": 1,
        "program": program,
        "program_sha256": hashlib.sha256(json.dumps(program).encode()).hexdigest(),
        "secret": 1,
        "variant": "none",
        "target_revision": "revision",
    }
    return value | changes


def validate(tmp_path, value):
    path = tmp_path / "request.json"
    path.write_text(json.dumps(value))
    return RUNNER.validate_request(path, "revision")


def test_request_validation_accepts_only_pinned_secure_control(tmp_path):
    assert validate(tmp_path, request())["secret"] == 1
    assert validate(tmp_path, request(variant="gate-faulting-loads"))["variant"] == (
        "gate-faulting-loads"
    )
    assert validate(tmp_path, request(variant="seeded-cache-leak"))["variant"] == (
        "seeded-cache-leak"
    )
    assert validate(tmp_path, request(variant="remove-seeded-cache-leak"))["variant"] == (
        "remove-seeded-cache-leak"
    )
    for change in (
        {"variant": "transient"},
        {"target_revision": "other"},
        {"secret": True},
        {"program_sha256": "0" * 64},
    ):
        with pytest.raises(RUNNER.RunnerError):
            validate(tmp_path, request(**change))


@pytest.mark.parametrize(
    "program",
    [
        ["load_secret", "enter_user"],
        ["probe", "enter_user"],
        ["enter_user", "load_secret", "load_secret"],
        ["enter_user", "probe", "probe"],
        ["enter_user", "unknown"],
        ["nop"],
    ],
)
def test_request_validation_rejects_unsafe_program_shapes(tmp_path, program):
    with pytest.raises(RUNNER.RunnerError):
        validate(tmp_path, request(program))


def test_candidate_is_fixed_instruction_translation():
    assembly = RUNNER.render_candidate(
        ["train", "enter_user", "load_secret", "encode", "squash", "probe", "fence"], 1
    )
    assert "csrw pmpaddr0" in assembly
    assert "csrw pmpcfg0" in assembly
    assert "csrc mstatus" in assembly
    assert "csrw mcounteren" in assembly
    assert "csrw scounteren" in assembly
    assert "spechunter_after_fault" in assembly
    assert "rdcycle" in assembly
    assert "probe_lines" in assembly
    assert "protected_secret" in assembly
    assert "SECRET" not in assembly
    assert assembly.index("ld s1, 0(s2)") < assembly.index("lbu zero, 0(t0)")
    assert assembly.index("fence.i") < assembly.index("spechunter_after_fault:")
    assert assembly.index("spechunter_after_fault:") < assembly.index("rdcycle")
    assert "lbu zero, 64(t0)" in assembly
    assert "sltu t2, t2, t4" in assembly


def test_positive_control_seeds_cache_only_in_explicit_mutated_variant():
    program = ["enter_user", "load_secret", "probe"]
    mutated = RUNNER.render_candidate(program, 1, "seeded-cache-leak")
    repaired = RUNNER.render_candidate(program, 1, "remove-seeded-cache-leak")
    marker = "Explicit positive-control mutation"
    assert marker in mutated
    assert marker not in repaired
    assert mutated.count("lbu zero, 0(t0)") == repaired.count("lbu zero, 0(t0)") + 1


def test_runner_requires_complete_pin_set(tmp_path):
    pins = tmp_path / "pins.env"
    pins.write_text("CHIPYARD_REVISION=abc\nBOOM_CONFIG=SmallBoomV3Config\n")
    with pytest.raises(RUNNER.RunnerError):
        RUNNER.load_pins(pins)


def test_htif_exit_code_is_a_bounded_probe_observation(tmp_path, monkeypatch):
    monkeypatch.setattr(
        RUNNER.subprocess,
        "run",
        lambda *args, **kwargs: SimpleNamespace(returncode=2, stdout=b"", stderr=b""),
    )
    assert RUNNER.run_htif_observation(
        ["executor"], tmp_path, {}, 1, has_load=True, has_probe=True
    ) == {
        "architectural": [],
        "probes": [1],
        "events": ["load-access-fault"],
        "completed": True,
    }
    with pytest.raises(RUNNER.RunnerError, match="exited 2"):
        RUNNER.run_htif_observation(["executor"], tmp_path, {}, 1, has_load=True, has_probe=False)


def test_repaired_build_manifest_binds_simulator(tmp_path):
    chipyard = tmp_path / "chipyard-repaired"
    simulator = chipyard / "sims/verilator/simulator-test-SmallBoomV3Config"
    simulator.parent.mkdir(parents=True)
    simulator.write_bytes(b"simulator")
    pins = {
        "CHIPYARD_REVISION": "chipyard",
        "BOOM_REVISION": "boom",
        "BOOM_CONFIG": "SmallBoomV3Config",
        "BOOM_REPAIRED_LSU_SHA256": "source",
        "BOOM_LOAD_GATE_PATCH_SHA256": "patch",
    }
    manifest = {
        "schema_version": 1,
        "variant": "gate-faulting-loads",
        "chipyard_revision": "chipyard",
        "boom_revision": "boom",
        "config": "SmallBoomV3Config",
        "lsu_source_sha256": "source",
        "patch_sha256": "patch",
        "simulator_sha256": hashlib.sha256(b"simulator").hexdigest(),
    }
    (simulator.parent / "spechunter-build-gate-faulting-loads.json").write_text(
        json.dumps(manifest)
    )
    RUNNER.validate_repair_build(request(variant="gate-faulting-loads"), simulator, chipyard, pins)
    simulator.write_bytes(b"stale")
    with pytest.raises(RUNNER.RunnerError, match="does not match"):
        RUNNER.validate_repair_build(
            request(variant="gate-faulting-loads"), simulator, chipyard, pins
        )


def test_execute_requires_spike_boom_architecture_and_trap_agreement(tmp_path, monkeypatch):
    chipyard = tmp_path / "chipyard"
    simulator = chipyard / "sims/verilator/simulator-test-SmallBoomV3Config"
    simulator.parent.mkdir(parents=True)
    simulator.write_text("")
    simulator.chmod(0o755)
    outputs = iter(
        [
            {"architectural": [], "probes": [0], "events": ["load-access-fault"]},
            {"architectural": [1], "probes": [0], "events": ["load-access-fault"]},
        ]
    )
    monkeypatch.setattr(RUNNER, "run_bounded", lambda *args, **kwargs: "")
    monkeypatch.setattr(RUNNER, "run_htif_observation", lambda *args, **kwargs: next(outputs))
    with pytest.raises(RUNNER.RunnerError, match="observations or traps disagree"):
        RUNNER.execute(request(), "SmallBoomV3Config", chipyard)
