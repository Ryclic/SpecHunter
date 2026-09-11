#!/usr/bin/env python3
"""Compile whitelisted experiments and compare Spike with pinned BOOM RTL."""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

OPS = {"nop", "train", "enter_user", "load_secret", "encode", "squash", "probe", "fence"}
MAX_OPS = 128
MAX_OUTPUT = 1_048_576
CHIPYARD = Path("/opt/spechunter/chipyard")
REPAIRED_CHIPYARD = Path("/opt/spechunter/chipyard-gate-faulting-loads")
REPAIR_VARIANT = "gate-faulting-loads"
POSITIVE_CONTROL_VARIANT = "seeded-cache-leak"
POSITIVE_CONTROL_REPAIR = "remove-seeded-cache-leak"


class RunnerError(RuntimeError):
    pass


def load_pins(path: Path) -> dict[str, str]:
    pins = {}
    for line in path.read_text().splitlines():
        if line and not line.startswith("#"):
            key, separator, value = line.partition("=")
            if not separator or not key or not value:
                raise RunnerError("invalid pins.env")
            pins[key] = value
    for key in (
        "CHIPYARD_REVISION",
        "BOOM_REVISION",
        "BOOM_CONFIG",
        "BOOM_LSU_SHA256",
        "BOOM_REPAIRED_LSU_SHA256",
        "BOOM_LOAD_GATE_PATCH_SHA256",
    ):
        if key not in pins:
            raise RunnerError(f"missing pin: {key}")
    return pins


def validate_install(chipyard: Path, pins: dict[str, str], variant: str) -> str:
    boom = chipyard / "generators/boom"

    def git_output(directory: Path, *arguments: str) -> str:
        return subprocess.run(
            ["git", "-c", f"safe.directory={directory}", "-C", str(directory), *arguments],
            capture_output=True,
            text=True,
            timeout=10,
            check=True,
        ).stdout.strip()

    chipyard_revision = git_output(chipyard, "rev-parse", "HEAD")
    boom_revision = git_output(boom, "rev-parse", "HEAD")
    if chipyard_revision != pins["CHIPYARD_REVISION"] or boom_revision != pins["BOOM_REVISION"]:
        raise RunnerError("installed Chipyard/BOOM revisions do not match pins.env")
    lsu = boom / "src/main/scala/v3/lsu/lsu.scala"
    source_digest = hashlib.sha256(lsu.read_bytes()).hexdigest()
    status = git_output(boom, "status", "--porcelain", "--untracked-files=all")
    if variant in {"none", POSITIVE_CONTROL_VARIANT, POSITIVE_CONTROL_REPAIR}:
        if status or source_digest != pins["BOOM_LSU_SHA256"]:
            raise RunnerError("baseline BOOM tree is not pristine reviewed source")
    elif variant == REPAIR_VARIANT:
        repair_diff = subprocess.run(
            [
                "git",
                "-c",
                f"safe.directory={boom}",
                "-C",
                str(boom),
                "diff",
                "--",
                "src/main/scala/v3/lsu/lsu.scala",
            ],
            capture_output=True,
            timeout=10,
            check=True,
        ).stdout
        if (
            status != " M src/main/scala/v3/lsu/lsu.scala"
            or source_digest != pins["BOOM_REPAIRED_LSU_SHA256"]
            or hashlib.sha256(repair_diff).hexdigest() != pins["BOOM_LOAD_GATE_PATCH_SHA256"]
        ):
            raise RunnerError("repaired BOOM tree does not match the reviewed load-gate patch")
    else:
        raise RunnerError("unsupported BOOM source variant")
    return chipyard_revision


def validate_request(path: Path, target_revision: str) -> dict:
    try:
        request = json.loads(path.read_text())
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise RunnerError(f"cannot read request: {exc}") from exc
    required = {
        "schema_version",
        "program",
        "program_sha256",
        "secret",
        "variant",
        "target_revision",
    }
    if set(request) != required or request["schema_version"] != 1:
        raise RunnerError("invalid request schema")
    program = request["program"]
    if (
        not isinstance(program, list)
        or not 1 <= len(program) <= MAX_OPS
        or any(type(op) is not str or op not in OPS for op in program)
    ):
        raise RunnerError("program is not a bounded operation list")
    digest = hashlib.sha256(json.dumps(program).encode()).hexdigest()
    if request["program_sha256"] != digest:
        raise RunnerError("program digest mismatch")
    if type(request["secret"]) is not int or request["secret"] not in (0, 1):
        raise RunnerError("secret must be 0 or 1")
    if request["variant"] not in {
        "none",
        REPAIR_VARIANT,
        POSITIVE_CONTROL_VARIANT,
        POSITIVE_CONTROL_REPAIR,
    }:
        raise RunnerError("unsupported BOOM source variant")
    if request["target_revision"] != target_revision:
        raise RunnerError("target revision mismatch")
    if program.count("enter_user") != 1:
        raise RunnerError("program must enter user mode exactly once")
    enter = program.index("enter_user")
    if "load_secret" in program[:enter] or "probe" in program[:enter]:
        raise RunnerError("secret loads and probes must execute in user mode")
    if program.count("load_secret") > 1:
        raise RunnerError("at most one protected load is supported")
    if program.count("probe") > 1:
        raise RunnerError("at most one fixed probe is supported")
    return request


def render_candidate(program: list[str], secret: int, variant: str = "none") -> str:
    snippets = {
        "nop": ["  nop"],
        "train": [
            "  li t0, 32",
            ".Ltrain_%d:",
            "  addi t0, t0, -1",
            "  bnez t0, .Ltrain_%d",
        ],
        "load_secret": [
            "  ld s1, 0(s2)",
        ],
        "encode": [
            "  la t0, probe_lines",
            "  slli t1, s1, 6",
            "  add t0, t0, t1",
            "  lbu zero, 0(t0)",
        ],
        "squash": ["  fence.i"],
        "probe": [
            "  la t0, probe_lines",
            "  fence rw, rw",
            "  rdcycle t1",
            "  lbu zero, 0(t0)",
            "  fence rw, rw",
            "  rdcycle t2",
            "  sub t2, t2, t1",
            "  fence rw, rw",
            "  rdcycle t3",
            "  lbu zero, 64(t0)",
            "  fence rw, rw",
            "  rdcycle t4",
            "  sub t4, t4, t3",
            "  sltu t2, t2, t4",
            "  mv s4, t2",
        ],
        "fence": ["  fence rw, rw", "  fence.i"],
    }
    lines = [
        '#include "riscv_test.h"',
        "RVTEST_RV64M",
        "RVTEST_CODE_BEGIN",
        "  la s2, protected_secret",
        f"  li t0, {secret}",
        "  sd t0, 0(s2)",
        "  li s1, 0",
        "  li s3, 0",
        "  li s4, 0",
        "  srli t0, s2, 2",
        "  ori t0, t0, 0x1ff",
        "  csrw pmpaddr0, t0",
        "  li t0, -1",
        "  csrw pmpaddr1, t0",
        "  li t0, 0x1f18",
        "  csrw pmpcfg0, t0",
        "  li t0, 1",
        "  csrw mcounteren, t0",
        "  csrw scounteren, t0",
    ]
    if variant == POSITIVE_CONTROL_VARIANT:
        lines += [
            "  # Explicit positive-control mutation: seed secret-selected public cache state.",
            "  la t0, probe_lines",
            f"  li t1, {secret}",
            "  slli t1, t1, 6",
            "  add t0, t0, t1",
            "  lbu zero, 0(t0)",
        ]
    load_index = program.index("load_secret") if "load_secret" in program else None
    fault_resume_after = load_index
    if load_index is not None:
        for candidate in ("squash", "encode"):
            later = [i for i, op in enumerate(program) if i > load_index and op == candidate]
            if later:
                fault_resume_after = later[0]
                break
    for index, op in enumerate(program):
        if op == "enter_user":
            lines += [
                f"  la t0, .Luser_{index}",
                "  csrw mepc, t0",
                "  li t0, (3 << 11)",
                "  csrc mstatus, t0",
                "  mret",
                f".Luser_{index}:",
            ]
        elif op == "train":
            lines += [line % index if "%d" in line else line for line in snippets[op]]
        elif op == "probe":
            lines += [line % index if "%d" in line else line for line in snippets[op]]
        else:
            lines += snippets[op]
        if index == fault_resume_after:
            lines += ["  .globl spechunter_after_fault", "spechunter_after_fault:"]
    if load_index is None:
        lines += ["  .globl spechunter_after_fault", "spechunter_after_fault:"]
    if load_index is not None:
        lines += ["  li t0, 1", "  bne s3, t0, spechunter_failed"]
    if "probe" in program:
        lines += ["  beqz s4, spechunter_passed", "  li TESTNUM, 2", "  RVTEST_FAIL"]
    lines += [
        "spechunter_passed:",
        "  RVTEST_PASS",
        "spechunter_failed:",
        "  li TESTNUM, 10",
        "  RVTEST_FAIL",
        "  .globl mtvec_handler",
        "mtvec_handler:",
        "spechunter_trap_handler:",
        "  csrr t0, mcause",
        "  li t1, 5",
        "  bne t0, t1, spechunter_failed",
        "  li s3, 1",
        "  la t0, spechunter_after_fault",
        "  csrw mepc, t0",
        "  mret",
        "RVTEST_CODE_END",
        "RVTEST_DATA_BEGIN",
        "  .balign 4096",
        "protected_secret:",
        "  .zero 4096",
        "  .balign 64",
        "probe_lines:",
        "  .zero 128",
        "RVTEST_DATA_END",
        "",
    ]
    return "\n".join(lines)


def run_bounded(argv: list[str], cwd: Path, env: dict[str, str], timeout: int) -> str:
    try:
        result = subprocess.run(
            argv,
            cwd=cwd,
            env=env,
            capture_output=True,
            timeout=timeout,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise RunnerError(f"executor failed: {exc}") from exc
    output = result.stdout + result.stderr
    if len(output) > MAX_OUTPUT:
        raise RunnerError("executor output limit exceeded")
    text = output.decode(errors="replace")
    if result.returncode:
        raise RunnerError(f"executor exited {result.returncode}: {text[-2000:]}")
    return text


def run_htif_observation(
    argv: list[str],
    cwd: Path,
    env: dict[str, str],
    timeout: int,
    *,
    has_load: bool,
    has_probe: bool,
) -> dict:
    try:
        result = subprocess.run(argv, cwd=cwd, env=env, capture_output=True, timeout=timeout)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise RunnerError(f"executor failed: {exc}") from exc
    output = result.stdout + result.stderr
    if len(output) > MAX_OUTPUT:
        raise RunnerError("executor output limit exceeded")
    if result.returncode not in ({0, 2} if has_probe else {0}):
        text = output.decode(errors="replace")
        raise RunnerError(f"executor exited {result.returncode}: {text[-2000:]}")
    return {
        "architectural": [],
        "probes": [int(result.returncode == 2)] if has_probe else [],
        "events": ["load-access-fault"] if has_load else [],
        "completed": True,
    }


def validate_repair_build(
    request: dict, simulator: Path, chipyard: Path, pins: dict[str, str]
) -> None:
    if request["variant"] != REPAIR_VARIANT:
        return
    manifest_path = chipyard / "sims/verilator/spechunter-build-gate-faulting-loads.json"
    try:
        manifest = json.loads(manifest_path.read_text())
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise RunnerError(f"cannot read repaired build manifest: {exc}") from exc
    expected = {
        "schema_version": 1,
        "variant": REPAIR_VARIANT,
        "chipyard_revision": pins["CHIPYARD_REVISION"],
        "boom_revision": pins["BOOM_REVISION"],
        "config": pins["BOOM_CONFIG"],
        "lsu_source_sha256": pins["BOOM_REPAIRED_LSU_SHA256"],
        "patch_sha256": pins["BOOM_LOAD_GATE_PATCH_SHA256"],
    }
    if any(manifest.get(key) != value for key, value in expected.items()):
        raise RunnerError("repaired build manifest provenance mismatch")
    if hashlib.sha256(simulator.read_bytes()).hexdigest() != manifest.get("simulator_sha256"):
        raise RunnerError("repaired simulator does not match its build manifest")


def execute(
    request: dict, config: str, chipyard: Path = CHIPYARD, pins: dict[str, str] | None = None
) -> dict:
    riscv = chipyard / ".conda-env/riscv-tools"
    env = {
        "PATH": f"{riscv / 'bin'}:/usr/bin:/bin",
        "HOME": "",
        "LANG": "C.UTF-8",
        "LD_LIBRARY_PATH": ":".join(
            str(path)
            for path in (riscv / "lib", chipyard / "sims/verilator", chipyard / "tools/DRAMSim2")
        ),
    }
    simulators = list((chipyard / "sims/verilator").glob(f"simulator-*-{config}"))
    if len(simulators) != 1 or not os.access(simulators[0], os.X_OK):
        raise RunnerError(f"expected exactly one executable {config} simulator")
    if pins is not None:
        validate_repair_build(request, simulators[0], chipyard, pins)
    with tempfile.TemporaryDirectory(prefix="spechunter-boom-") as temp:
        work = Path(temp)
        env["HOME"] = str(work)
        candidate = work / "candidate.S"
        payload = work / "candidate.riscv"
        candidate.write_text(
            render_candidate(request["program"], request["secret"], request["variant"])
        )
        compiler = riscv / "bin/riscv64-unknown-elf-gcc"
        test_environment = chipyard / "toolchains/riscv-tools/riscv-tests/env"
        run_bounded(
            [
                str(compiler),
                "-march=rv64imafd_zicsr_zifencei",
                "-mabi=lp64d",
                "-mcmodel=medany",
                "-nostdlib",
                "-nostartfiles",
                "-static",
                "-I",
                str(test_environment / "p"),
                "-I",
                str(test_environment),
                "-T",
                str(test_environment / "p/link.ld"),
                str(candidate),
                "-o",
                str(payload),
            ],
            work,
            env,
            60,
        )
        has_load = "load_secret" in request["program"]
        has_probe = "probe" in request["program"]
        spike = run_htif_observation(
            [str(riscv / "bin/spike"), str(payload)],
            work,
            env,
            60,
            has_load=has_load,
            has_probe=has_probe,
        )
        dramsim = chipyard / "generators/testchipip/src/main/resources/dramsim2_ini"
        boom = run_htif_observation(
            [
                str(simulators[0]),
                "+permissive",
                "+dramsim",
                f"+dramsim_ini_dir={dramsim}",
                "+max-cycles=10000000",
                "+permissive-off",
                str(payload),
            ],
            work,
            env,
            900,
            has_load=has_load,
            has_probe=has_probe,
        )
        if (spike["architectural"], spike["events"]) != (
            boom["architectural"],
            boom["events"],
        ):
            raise RunnerError("Spike/BOOM architectural observations or traps disagree")
        return boom


def main() -> int:
    try:
        if len(sys.argv) != 2 or not Path(sys.argv[1]).is_absolute():
            raise RunnerError("usage: trusted_runner.py /ABSOLUTE/request.json")
        script_dir = Path(__file__).resolve().parent
        pins = load_pins(script_dir / "pins.env")
        request = validate_request(Path(sys.argv[1]), pins["CHIPYARD_REVISION"])
        chipyard = REPAIRED_CHIPYARD if request["variant"] == REPAIR_VARIANT else CHIPYARD
        validate_install(chipyard, pins, request["variant"])
        observation = execute(request, pins["BOOM_CONFIG"], chipyard, pins)
        response = {
            key: request[key]
            for key in (
                "schema_version",
                "target_revision",
                "program_sha256",
                "secret",
                "variant",
            )
        }
        response.update(target="boom", observation=observation)
        print(json.dumps(response, separators=(",", ":")))
        return 0
    except (RunnerError, subprocess.SubprocessError) as exc:
        print(f"trusted BOOM runner: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
