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
    for key in ("CHIPYARD_REVISION", "BOOM_REVISION", "BOOM_CONFIG"):
        if key not in pins:
            raise RunnerError(f"missing pin: {key}")
    return pins


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
    if request["variant"] != "none":
        raise RunnerError("real BOOM runner supports only the unmodified secure-control variant")
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


def render_candidate(program: list[str], secret: int) -> str:
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
            "  la t0, architectural_value",
            "  sd s1, 0(t0)",
            "  la t0, architectural_visible",
            "  li t1, 1",
            "  sd t1, 0(t0)",
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
            "  la t0, probe_count",
            "  ld t1, 0(t0)",
            "  la t3, probe_results",
            "  slli t4, t1, 3",
            "  add t3, t3, t4",
            "  sd t2, 0(t3)",
            "  addi t1, t1, 1",
            "  sd t1, 0(t0)",
        ],
        "fence": ["  fence rw, rw", "  fence.i"],
    }
    lines = [
        "  .section .text",
        "  .align 2",
        "  .globl spechunter_candidate",
        "spechunter_candidate:",
        "  addi sp, sp, -48",
        "  sd ra, 40(sp)",
        "  sd s1, 32(sp)",
        "  sd s2, 24(sp)",
        "  la s2, protected_secret",
        f"  li t0, {secret}",
        "  sd t0, 0(s2)",
        "  li s1, 0",
        "  srli t0, s2, 2",
        "  ori t0, t0, 0x1ff",
        "  csrw pmpaddr0, t0",
        "  li t0, -1",
        "  csrw pmpaddr1, t0",
        "  li t0, 0x1f18",
        "  csrw pmpcfg0, t0",
        "  la t0, spechunter_trap_handler",
        "  csrw mtvec, t0",
        "  li t0, 1",
        "  csrw mcounteren, t0",
        "  csrw scounteren, t0",
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
    lines += [
        "  ecall",
        "  .globl spechunter_machine_resume",
        "spechunter_machine_resume:",
        "  ld s2, 24(sp)",
        "  ld s1, 32(sp)",
        "  ld ra, 40(sp)",
        "  addi sp, sp, 48",
        "  ret",
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


def parse_observation(output: str) -> dict:
    architectural: list[int] = []
    probes: list[int] = []
    events: list[str] = []
    done = False
    try:
        for line in output.splitlines():
            if line.startswith("SPECHUNTER ARCH "):
                architectural.append(int(line.removeprefix("SPECHUNTER ARCH ")))
            elif line.startswith("SPECHUNTER PROBE "):
                probes.append(int(line.removeprefix("SPECHUNTER PROBE ")))
            elif line.startswith("SPECHUNTER EVENT "):
                events.append(line.removeprefix("SPECHUNTER EVENT "))
            elif line == "SPECHUNTER DONE":
                done = True
    except ValueError as exc:
        raise RunnerError("executor emitted a non-integer observation") from exc
    if (
        not done
        or len(architectural) > 1
        or len(probes) > 1
        or len(events) > 1
        or any(value not in (0, 1) for value in architectural)
        or any(value not in (0, 1) for value in probes)
        or any(event != "load-access-fault" for event in events)
    ):
        raise RunnerError("executor did not emit a bounded complete observation")
    return {"architectural": architectural, "probes": probes, "events": events, "completed": True}


def execute(request: dict, config: str, chipyard: Path = CHIPYARD) -> dict:
    script_dir = Path(__file__).resolve().parent
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
    with tempfile.TemporaryDirectory(prefix="spechunter-boom-") as temp:
        work = Path(temp)
        env["HOME"] = str(work)
        candidate = work / "candidate.S"
        payload = work / "candidate.riscv"
        candidate.write_text(render_candidate(request["program"], request["secret"]))
        compiler = riscv / "bin/riscv64-unknown-elf-gcc"
        run_bounded(
            [
                str(compiler),
                "-march=rv64imafd_zicsr_zifencei",
                "-mabi=lp64d",
                "-mcmodel=medany",
                "-O2",
                "-static",
                "-specs=htif_nano.specs",
                "-T",
                "htif.ld",
                str(script_dir / "runtime.c"),
                str(script_dir / "runtime.S"),
                str(candidate),
                "-o",
                str(payload),
            ],
            work,
            env,
            60,
        )
        spike_output = run_bounded([str(riscv / "bin/spike"), str(payload)], work, env, 60)
        spike = parse_observation(spike_output)
        dramsim = chipyard / "generators/testchipip/src/main/resources/dramsim2_ini"
        boom_output = run_bounded(
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
        )
        boom = parse_observation(boom_output)
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
        target_revision = subprocess.run(
            ["git", "-c", f"safe.directory={CHIPYARD}", "-C", str(CHIPYARD), "rev-parse", "HEAD"],
            capture_output=True,
            text=True,
            timeout=10,
            check=True,
        ).stdout.strip()
        boom_revision = subprocess.run(
            [
                "git",
                "-c",
                f"safe.directory={CHIPYARD / 'generators/boom'}",
                "-C",
                str(CHIPYARD / "generators/boom"),
                "rev-parse",
                "HEAD",
            ],
            capture_output=True,
            text=True,
            timeout=10,
            check=True,
        ).stdout.strip()
        if target_revision != pins["CHIPYARD_REVISION"] or boom_revision != pins["BOOM_REVISION"]:
            raise RunnerError("installed Chipyard/BOOM revisions do not match pins.env")
        request = validate_request(Path(sys.argv[1]), target_revision)
        observation = execute(request, pins["BOOM_CONFIG"])
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
