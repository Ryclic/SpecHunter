#!/usr/bin/env python3
"""Execute the exact issue #715 attachment and record provenance without overclaiming it."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def load_pins(path: Path) -> dict[str, str]:
    return dict(
        line.split("=", 1)
        for line in path.read_text().splitlines()
        if line and not line.startswith("#")
    )


def git_head(path: Path) -> str:
    return subprocess.run(
        ["git", "-C", str(path), "rev-parse", "HEAD"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()


def git_status(path: Path) -> str:
    return subprocess.run(
        ["git", "-C", str(path), "status", "--porcelain", "--untracked-files=all"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.rstrip("\r\n")


def validate_isolated_candidate(source: Path, candidate: Path, manifest_path: Path) -> str:
    script = Path(__file__).with_name("prepare_issue_715_isolated_gadget.py")
    spec = importlib.util.spec_from_file_location("issue_715_isolated_gadget", script)
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load isolated gadget builder")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    module.verify_candidate(
        source.read_bytes(), candidate.read_bytes(), json.loads(manifest_path.read_text())
    )
    return digest(manifest_path)


def require_waveform_support(simulator: Path) -> None:
    """Reject a diagnostic run that cannot produce the signal-level evidence it needs."""
    help_text = subprocess.run(
        [str(simulator), "--help"], capture_output=True, text=True, timeout=30, check=True
    ).stdout
    if "--vcd" not in help_text:
        raise RuntimeError("diagnostic requires a trace-enabled simulator supporting --vcd")


def write_diagnostic_witness(waveform: Path, destination: Path) -> str:
    script = Path(__file__).with_name("scan_issue_715_vcd.py")
    spec = importlib.util.spec_from_file_location("issue_715_vcd", script)
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load issue #715 waveform scanner")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    witness = module.scan(waveform)
    if witness["trace_sha256"] != digest(waveform):
        raise RuntimeError("diagnostic witness waveform digest mismatch")
    destination.write_text(json.dumps(witness, indent=2) + "\n")
    return digest(destination)


def main() -> int:
    if len(sys.argv) not in (4, 6) or any(not Path(arg).is_absolute() for arg in sys.argv[1:]):
        print(
            "usage: run_historical_issue_715_attachment.py "
            "/ABSOLUTE/CHIPYARD /ABSOLUTE/program.elf /ABSOLUTE/evidence.json "
            "[/ABSOLUTE/original.elf /ABSOLUTE/candidate-manifest.json]",
            file=sys.stderr,
        )
        return 2
    chipyard, attachment, output = map(Path, sys.argv[1:4])
    here = Path(__file__).resolve().parent
    values = load_pins(here / "historical_pins.env")
    values.update(load_pins(here / "issue_715_attachment.env"))
    if git_head(chipyard) != values["CHIPYARD_REVISION"]:
        raise RuntimeError("historical Chipyard revision mismatch")
    if git_head(chipyard / "generators/boom") != values["BOOM_REVISION"]:
        raise RuntimeError("historical BOOM revision mismatch")
    boom = chipyard / "generators/boom"
    lsu = boom / "src/main/scala/lsu/lsu.scala"
    if git_status(boom) or digest(lsu) != values["BOOM_LSU_SHA256"]:
        raise RuntimeError("historical BOOM source tree is not pristine")
    candidate_manifest_sha256 = None
    if len(sys.argv) == 6:
        candidate_manifest_sha256 = validate_isolated_candidate(
            Path(sys.argv[4]), attachment, Path(sys.argv[5])
        )
    elif digest(attachment) != values["ISSUE_715_ATTACHMENT_ELF_SHA256"]:
        raise RuntimeError("issue #715 attachment ELF digest mismatch")
    manifest_path = chipyard / "sims/verilator/spechunter-historical-build.json"
    manifest = json.loads(manifest_path.read_text())
    expected = {
        "experiment": "boom-historical-issue-715-build",
        "variant": "historical-issue-715-baseline",
        "chipyard_revision": values["CHIPYARD_REVISION"],
        "boom_revision": values["BOOM_REVISION"],
        "config": values["BOOM_CONFIG"],
        "lsu_source_sha256": values["BOOM_LSU_SHA256"],
    }
    if any(manifest.get(key) != value for key, value in expected.items()):
        raise RuntimeError("historical build manifest provenance mismatch")
    simulators = list((chipyard / "sims/verilator").glob(f"simulator-*-{values['BOOM_CONFIG']}"))
    if len(simulators) != 1 or digest(simulators[0]) != manifest.get("simulator_sha256"):
        raise RuntimeError("historical simulator does not match its build manifest")
    if candidate_manifest_sha256:
        require_waveform_support(simulators[0])
        if output.with_suffix(".vcd").exists() or output.with_suffix(".witness.json").exists():
            raise RuntimeError("diagnostic artifact path already exists; choose a fresh output")
    dramsim = chipyard / "generators/testchipip/src/main/resources/dramsim2_ini"
    output.parent.mkdir(parents=True, exist_ok=True)
    loadmem = output.with_suffix(".loadmem.hex")
    elf2hex = chipyard / ".conda-env/riscv-tools/bin/elf2hex"
    converted = subprocess.run(
        [str(elf2hex), "64", "16384", str(attachment), "2147483648"],
        check=True,
        capture_output=True,
    )
    loadmem.write_bytes(converted.stdout)
    if len(loadmem.read_text().splitlines()) != 16384:
        raise RuntimeError("issue #715 attachment produced an unexpected loadmem image")
    argv = [
        str(simulators[0]),
        *(
            ["--seed=1789717734", "--vcd", str(output.with_suffix(".vcd"))]
            if candidate_manifest_sha256
            else []
        ),
        "+permissive",
        "+dramsim",
        f"+dramsim_ini_dir={dramsim}",
        "+max-cycles=150000",
        f"+loadmem={loadmem}",
        "+loadmem_addr=80000000",
        "+permissive-off",
        str(attachment),
    ]
    env = {
        "HOME": str(output.parent),
        "LANG": "C.UTF-8",
        "PATH": "/usr/bin:/bin",
        "LD_LIBRARY_PATH": ":".join(
            str(path)
            for path in (
                chipyard / ".conda-env/riscv-tools/lib",
                chipyard / "sims/verilator",
                chipyard / "tools/DRAMSim2",
            )
        ),
    }
    started = datetime.now(timezone.utc)  # noqa: UP017 - worker uses Python 3.9
    try:
        result = subprocess.run(argv, capture_output=True, timeout=300, env=env)
        timed_out = False
        stdout, stderr, returncode = result.stdout, result.stderr, result.returncode
    except subprocess.TimeoutExpired as exc:
        timed_out = True
        stdout, stderr, returncode = exc.stdout or b"", exc.stderr or b"", None
    log = output.with_suffix(".log")
    log.parent.mkdir(parents=True, exist_ok=True)
    log.write_bytes(stdout + b"\n--- STDERR ---\n" + stderr)
    evidence = {
        "schema_version": 1,
        "experiment": (
            "boom-historical-issue-715-isolated-gadget"
            if candidate_manifest_sha256
            else "boom-historical-issue-715-original-attachment"
        ),
        "classification": (
            "diagnostic-executed-signal-verdict-pending"
            if candidate_manifest_sha256 and not timed_out
            else "executed-signal-verdict-pending"
            if not timed_out
            else "execution-timeout"
        ),
        "vulnerability_reproduced": False,
        "security_fix_validated": False,
        "chipyard_revision": values["CHIPYARD_REVISION"],
        "boom_revision": values["BOOM_REVISION"],
        "config": values["BOOM_CONFIG"],
        "attachment_url": values["ISSUE_715_ATTACHMENT_URL"],
        "attachment_zip_sha256": values["ISSUE_715_ATTACHMENT_ZIP_SHA256"],
        "attachment_elf_sha256": values["ISSUE_715_ATTACHMENT_ELF_SHA256"],
        "loadmem_sha256": digest(loadmem),
        "simulator_sha256": digest(simulators[0]),
        "returncode": returncode,
        "timed_out": timed_out,
        "elapsed_seconds": round(
            (datetime.now(timezone.utc) - started).total_seconds(),  # noqa: UP017
            3,
        ),
        "log_sha256": digest(log),
        "completed_at": datetime.now(timezone.utc).isoformat(),  # noqa: UP017
    }
    if candidate_manifest_sha256:
        waveform = output.with_suffix(".vcd")
        if not waveform.is_file() or waveform.stat().st_size == 0:
            raise RuntimeError("diagnostic simulator did not produce a waveform")
        evidence["waveform_sha256"] = digest(waveform)
        evidence["waveform_path"] = str(waveform)
        witness_path = output.with_suffix(".witness.json")
        evidence["witness_sha256"] = write_diagnostic_witness(waveform, witness_path)
        evidence["witness_path"] = str(witness_path)
        evidence["seed"] = 1789717734
        evidence["executed_elf_sha256"] = digest(attachment)
        evidence["candidate_manifest_sha256"] = candidate_manifest_sha256
    output.write_text(json.dumps(evidence, indent=2) + "\n")
    print(json.dumps(evidence, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
