#!/usr/bin/env python3
"""Run the pinned BOOM secure-control matrix and write hash-bound evidence."""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import tempfile
from datetime import UTC, datetime
from pathlib import Path

REPEATS = 2
SCENARIOS = {
    "architectural-denial": ["enter_user", "load_secret", "probe"],
    "transient-window": [
        "train",
        "enter_user",
        "load_secret",
        "encode",
        "squash",
        "probe",
    ],
}
MAX_RUNNER_OUTPUT = 1_048_576


class MatrixError(RuntimeError):
    pass


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def program_digest(program: list[str]) -> str:
    return hashlib.sha256(json.dumps(program).encode()).hexdigest()


def classify(observations: list[dict]) -> dict:
    if len(observations) != REPEATS * 2:
        raise MatrixError("matrix has the wrong observation count")
    secret_zero = observations[0::2]
    secret_one = observations[1::2]
    deterministic = all(value == secret_zero[0] for value in secret_zero[1:]) and all(
        value == secret_one[0] for value in secret_one[1:]
    )
    differs = (secret_zero[0]["architectural"], secret_zero[0]["probes"]) != (
        secret_one[0]["architectural"],
        secret_one[0]["probes"],
    )
    return {
        "deterministic": deterministic,
        "status": "inconclusive" if not deterministic else ("violation" if differs else "clean"),
    }


def run_request(runner: Path, request: Path) -> dict:
    env = {
        key: value
        for key, value in os.environ.items()
        if key in {"PATH", "LANG", "LC_ALL", "LD_LIBRARY_PATH"}
    }
    try:
        result = subprocess.run(
            [str(runner), str(request)],
            cwd=request.parent,
            env=env,
            capture_output=True,
            timeout=900,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise MatrixError(f"runner failed: {exc}") from exc
    if len(result.stdout) + len(result.stderr) > MAX_RUNNER_OUTPUT:
        raise MatrixError("runner output limit exceeded")
    if result.returncode:
        error = result.stderr.decode(errors="replace")
        raise MatrixError(f"runner exited {result.returncode}: {error[-2000:]}")
    try:
        response = json.loads(result.stdout)
        expected = json.loads(request.read_text())
        if (
            set(response)
            != {
                "schema_version",
                "target_revision",
                "program_sha256",
                "secret",
                "variant",
                "target",
                "observation",
            }
            or response["schema_version"] != expected["schema_version"]
            or response["target_revision"] != expected["target_revision"]
            or response["program_sha256"] != expected["program_sha256"]
            or response["secret"] != expected["secret"]
            or response["variant"] != expected["variant"]
            or response["target"] != "boom"
        ):
            raise MatrixError("runner response provenance mismatch")
        return response["observation"]
    except (UnicodeError, json.JSONDecodeError, KeyError, TypeError) as exc:
        raise MatrixError(f"invalid runner response: {exc}") from exc


def main() -> int:
    try:
        if len(sys.argv) != 2 or not Path(sys.argv[1]).is_absolute():
            raise MatrixError("usage: run_secure_matrix.py /ABSOLUTE/evidence.json")
        evidence_path = Path(sys.argv[1])
        evidence_path.parent.mkdir(parents=True, exist_ok=True)
        script_dir = Path(__file__).resolve().parent
        runner = script_dir / "trusted_runner.py"
        pins = {}
        for line in (script_dir / "pins.env").read_text().splitlines():
            if line and not line.startswith("#"):
                key, separator, value = line.partition("=")
                if not separator:
                    raise MatrixError("invalid pins.env")
                pins[key] = value
        target_revision = pins["CHIPYARD_REVISION"]
        scenarios = []
        with tempfile.TemporaryDirectory(prefix="spechunter-matrix-") as temporary:
            work = Path(temporary)
            for name, program in SCENARIOS.items():
                observations = []
                for repeat in range(REPEATS):
                    for secret in (0, 1):
                        request = {
                            "schema_version": 1,
                            "program": program,
                            "program_sha256": program_digest(program),
                            "secret": secret,
                            "variant": "none",
                            "target_revision": target_revision,
                        }
                        request_path = work / f"{name}-{repeat}-{secret}.json"
                        request_path.write_text(json.dumps(request) + "\n")
                        observations.append(run_request(runner, request_path))
                scenarios.append(
                    {
                        "name": name,
                        "program": program,
                        "program_sha256": program_digest(program),
                        "observations": observations,
                        **classify(observations),
                    }
                )
        chipyard = Path("/opt/spechunter/chipyard")
        simulators = list((chipyard / "sims/verilator").glob(f"simulator-*-{pins['BOOM_CONFIG']}"))
        if len(simulators) != 1:
            raise MatrixError("cannot identify the pinned simulator for evidence")
        evidence = {
            "schema_version": 1,
            "experiment": "boom-secure-control-matched-secret-matrix",
            "chipyard_revision": pins["CHIPYARD_REVISION"],
            "boom_revision": pins["BOOM_REVISION"],
            "config": pins["BOOM_CONFIG"],
            "repeats": REPEATS,
            "runner_sha256": digest(runner),
            "runtime_c_sha256": digest(script_dir / "runtime.c"),
            "runtime_assembly_sha256": digest(script_dir / "runtime.S"),
            "simulator_sha256": digest(simulators[0]),
            "scenarios": scenarios,
            "completed_at": datetime.now(UTC).isoformat(),
        }
        temporary_evidence = evidence_path.with_suffix(evidence_path.suffix + ".tmp")
        temporary_evidence.write_text(json.dumps(evidence, indent=2) + "\n")
        temporary_evidence.replace(evidence_path)
        print(json.dumps({item["name"]: item["status"] for item in scenarios}, indent=2))
        return 0 if all(item["status"] == "clean" for item in scenarios) else 1
    except (KeyError, OSError, MatrixError) as exc:
        print(f"BOOM secure matrix: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
