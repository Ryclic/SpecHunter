import hashlib
import importlib.util
import json
from pathlib import Path

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


def test_observation_parser_ignores_executor_noise_and_requires_done():
    output = "noise\nSPECHUNTER EVENT load-access-fault\nSPECHUNTER PROBE 1\nSPECHUNTER DONE\n"
    assert RUNNER.parse_observation(output) == {
        "architectural": [],
        "probes": [1],
        "events": ["load-access-fault"],
        "completed": True,
    }
    with pytest.raises(RUNNER.RunnerError):
        RUNNER.parse_observation("SPECHUNTER PROBE 1\n")
    for invalid in ("SPECHUNTER PROBE 17", "SPECHUNTER ARCH nope", "SPECHUNTER EVENT other"):
        with pytest.raises(RUNNER.RunnerError):
            RUNNER.parse_observation(f"{invalid}\nSPECHUNTER DONE\n")


def test_runner_requires_complete_pin_set(tmp_path):
    pins = tmp_path / "pins.env"
    pins.write_text("CHIPYARD_REVISION=abc\nBOOM_CONFIG=SmallBoomV3Config\n")
    with pytest.raises(RUNNER.RunnerError):
        RUNNER.load_pins(pins)


def test_execute_requires_spike_boom_architecture_and_trap_agreement(tmp_path, monkeypatch):
    chipyard = tmp_path / "chipyard"
    simulator = chipyard / "sims/verilator/simulator-test-SmallBoomV3Config"
    simulator.parent.mkdir(parents=True)
    simulator.write_text("")
    simulator.chmod(0o755)
    outputs = iter(
        [
            "",
            "SPECHUNTER EVENT load-access-fault\nSPECHUNTER DONE\n",
            "SPECHUNTER ARCH 1\nSPECHUNTER DONE\n",
        ]
    )
    monkeypatch.setattr(RUNNER, "run_bounded", lambda *args, **kwargs: next(outputs))
    with pytest.raises(RUNNER.RunnerError, match="observations or traps disagree"):
        RUNNER.execute(request(), "SmallBoomV3Config", chipyard)
