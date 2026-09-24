#!/usr/bin/env python3
"""Fail-closed runner for the exact Chipyard/BOOM revision from issue #715."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location(
    "spechunter_trusted_runner", HERE / "trusted_runner.py"
)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("cannot load trusted runner")
TRUSTED = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(TRUSTED)

BASELINE = "historical-issue-715-baseline"
REPAIRED = "historical-issue-715-repaired"
INSTALLS = {
    BASELINE: Path("/opt/spechunter/chipyard-issue-715"),
    REPAIRED: Path("/opt/spechunter/chipyard-issue-715-repaired"),
}


def load_pins(path: Path) -> dict[str, str]:
    pins: dict[str, str] = {}
    for line in path.read_text().splitlines():
        if line and not line.startswith("#"):
            key, separator, value = line.partition("=")
            if not separator or not key or not value:
                raise TRUSTED.RunnerError("invalid historical_pins.env")
            pins[key] = value
    required = {
        "CHIPYARD_REVISION",
        "BOOM_REVISION",
        "BOOM_CONFIG",
        "BOOM_LSU_SHA256",
        "BOOM_REPAIRED_LSU_SHA256",
        "BOOM_LOAD_GATE_PATCH_SHA256",
    }
    if not required <= pins.keys():
        raise TRUSTED.RunnerError("historical pins are incomplete")
    return pins


def git_output(directory: Path, *args: str, binary: bool = False, preserve_columns: bool = False):
    result = subprocess.run(
        ["git", "-c", f"safe.directory={directory}", "-C", str(directory), *args],
        capture_output=True,
        text=not binary,
        timeout=15,
        check=True,
    )
    if binary:
        return result.stdout
    return result.stdout.rstrip("\r\n") if preserve_columns else result.stdout.strip()


def validate_install(chipyard: Path, pins: dict[str, str], variant: str) -> None:
    boom = chipyard / "generators/boom"
    if git_output(chipyard, "rev-parse", "HEAD") != pins["CHIPYARD_REVISION"]:
        raise TRUSTED.RunnerError("historical Chipyard revision mismatch")
    if git_output(boom, "rev-parse", "HEAD") != pins["BOOM_REVISION"]:
        raise TRUSTED.RunnerError("historical BOOM revision mismatch")
    source = boom / "src/main/scala/lsu/lsu.scala"
    digest = hashlib.sha256(source.read_bytes()).hexdigest()
    status = git_output(
        boom, "status", "--porcelain", "--untracked-files=all", preserve_columns=True
    )
    if variant == BASELINE:
        if status or digest != pins["BOOM_LSU_SHA256"]:
            raise TRUSTED.RunnerError("historical baseline tree is not pristine")
    elif variant == REPAIRED:
        diff = git_output(boom, "diff", "--", "src/main/scala/lsu/lsu.scala", binary=True)
        if (
            status != " M src/main/scala/lsu/lsu.scala"
            or digest != pins["BOOM_REPAIRED_LSU_SHA256"]
            or hashlib.sha256(diff).hexdigest() != pins["BOOM_LOAD_GATE_PATCH_SHA256"]
        ):
            raise TRUSTED.RunnerError("historical repair does not match reviewed patch")
    else:
        raise TRUSTED.RunnerError("unsupported historical variant")


def validate_build(chipyard: Path, pins: dict[str, str], variant: str, simulator: Path) -> None:
    manifest_path = chipyard / "sims/verilator/spechunter-historical-build.json"
    try:
        manifest = json.loads(manifest_path.read_text())
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise TRUSTED.RunnerError(f"cannot read historical build manifest: {exc}") from exc
    expected_source = (
        pins["BOOM_LSU_SHA256"] if variant == BASELINE else pins["BOOM_REPAIRED_LSU_SHA256"]
    )
    expected = {
        "schema_version": 1,
        "experiment": "boom-historical-issue-715-build",
        "variant": variant,
        "chipyard_revision": pins["CHIPYARD_REVISION"],
        "boom_revision": pins["BOOM_REVISION"],
        "config": pins["BOOM_CONFIG"],
        "lsu_source_sha256": expected_source,
    }
    if any(manifest.get(key) != value for key, value in expected.items()):
        raise TRUSTED.RunnerError("historical build manifest provenance mismatch")
    if hashlib.sha256(simulator.read_bytes()).hexdigest() != manifest.get("simulator_sha256"):
        raise TRUSTED.RunnerError("historical simulator does not match its build manifest")


def validate_request(path: Path, pins: dict[str, str]) -> dict:
    request = json.loads(path.read_text())
    required = {
        "schema_version",
        "program",
        "program_sha256",
        "secret",
        "variant",
        "target_revision",
    }
    if set(request) != required or request["schema_version"] != 1:
        raise TRUSTED.RunnerError("invalid request schema")
    if request["program"] != ["enter_user", "load_secret", "probe"]:
        raise TRUSTED.RunnerError("historical issue #715 requires the fixed program")
    if (
        request["variant"] not in INSTALLS
        or request["target_revision"] != pins["CHIPYARD_REVISION"]
    ):
        raise TRUSTED.RunnerError("request target or variant mismatch")
    if type(request["secret"]) is not int or request["secret"] not in (0, 1):
        raise TRUSTED.RunnerError("secret must be 0 or 1")
    expected = hashlib.sha256(json.dumps(request["program"]).encode()).hexdigest()
    if request["program_sha256"] != expected:
        raise TRUSTED.RunnerError("program digest mismatch")
    return request


def execute(request: dict, config: str, chipyard: Path) -> dict:
    """Execute with the pre-Zicsr naming convention understood by the 2022 compiler."""
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
        raise TRUSTED.RunnerError(f"expected exactly one executable {config} simulator")
    with tempfile.TemporaryDirectory(prefix="spechunter-boom-historical-") as temporary:
        work = Path(temporary)
        env["HOME"] = str(work)
        candidate = work / "candidate.S"
        payload = work / "candidate.riscv"
        candidate.write_text(TRUSTED.render_issue_715_candidate(request["secret"]))
        test_environment = chipyard / "toolchains/riscv-tools/riscv-tests/env"
        TRUSTED.run_bounded(
            [
                str(riscv / "bin/riscv64-unknown-elf-gcc"),
                "-march=rv64imafd",
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
        spike = TRUSTED.run_htif_observation(
            [str(riscv / "bin/spike"), str(payload)],
            work,
            env,
            60,
            has_load=False,
            has_probe=True,
        )
        dramsim = chipyard / "generators/testchipip/src/main/resources/dramsim2_ini"
        boom = TRUSTED.run_htif_observation(
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
            has_load=False,
            has_probe=True,
        )
        if (spike["architectural"], spike["events"]) != (
            boom["architectural"],
            boom["events"],
        ):
            raise TRUSTED.RunnerError("Spike/BOOM architectural observations disagree")
        return boom


def main() -> int:
    try:
        if len(sys.argv) != 2 or not Path(sys.argv[1]).is_absolute():
            raise TRUSTED.RunnerError(
                "usage: historical_issue_715_runner.py /ABSOLUTE/request.json"
            )
        pins = load_pins(HERE / "historical_pins.env")
        request = validate_request(Path(sys.argv[1]), pins)
        chipyard = INSTALLS[request["variant"]]
        validate_install(chipyard, pins, request["variant"])
        simulators = list((chipyard / "sims/verilator").glob(f"simulator-*-{pins['BOOM_CONFIG']}"))
        if len(simulators) != 1:
            raise TRUSTED.RunnerError("cannot bind historical simulator provenance")
        validate_build(chipyard, pins, request["variant"], simulators[0])
        observation = execute(request, pins["BOOM_CONFIG"], chipyard)
        response = {
            key: request[key]
            for key in ("schema_version", "target_revision", "program_sha256", "secret", "variant")
        }
        response.update(
            target="boom",
            boom_revision=pins["BOOM_REVISION"],
            simulator_sha256=hashlib.sha256(simulators[0].read_bytes()).hexdigest(),
            observation=observation,
        )
        print(json.dumps(response, separators=(",", ":")))
        return 0
    except (
        OSError,
        UnicodeError,
        json.JSONDecodeError,
        TRUSTED.RunnerError,
        subprocess.SubprocessError,
    ) as exc:
        print(f"historical BOOM runner: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
