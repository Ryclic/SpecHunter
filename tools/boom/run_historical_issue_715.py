#!/usr/bin/env python3
"""Run a repeatability matrix against exact historical issue #715 BOOM RTL."""

from __future__ import annotations

import hashlib
import json
import subprocess
import sys
import tempfile
from datetime import UTC, datetime
from pathlib import Path


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> int:
    if (
        len(sys.argv) != 3
        or sys.argv[1] not in {"historical-issue-715-baseline", "historical-issue-715-repaired"}
        or not Path(sys.argv[2]).is_absolute()
    ):
        print(
            "usage: run_historical_issue_715.py "
            "historical-issue-715-{baseline|repaired} /ABSOLUTE/evidence.json",
            file=sys.stderr,
        )
        return 2
    variant, output = sys.argv[1], Path(sys.argv[2])
    here = Path(__file__).resolve().parent
    pins = dict(
        line.split("=", 1)
        for line in (here / "historical_pins.env").read_text().splitlines()
        if line and not line.startswith("#")
    )
    runner = here / "historical_issue_715_runner.py"
    program = ["enter_user", "load_secret", "probe"]
    program_hash = hashlib.sha256(json.dumps(program).encode()).hexdigest()
    runs = []
    for repetition in range(2):
        for secret in (0, 1):
            request = {
                "schema_version": 1,
                "program": program,
                "program_sha256": program_hash,
                "secret": secret,
                "variant": variant,
                "target_revision": pins["CHIPYARD_REVISION"],
            }
            with tempfile.NamedTemporaryFile("w", suffix=".json") as handle:
                json.dump(request, handle)
                handle.flush()
                result = subprocess.run(
                    [str(runner), str(Path(handle.name).resolve())],
                    capture_output=True,
                    text=True,
                    timeout=1200,
                )
            if result.returncode:
                raise RuntimeError(result.stderr[-4000:])
            response = json.loads(result.stdout)
            if any(
                response.get(key) != request[key]
                for key in (
                    "schema_version",
                    "program_sha256",
                    "secret",
                    "variant",
                    "target_revision",
                )
            ):
                raise RuntimeError("runner response provenance mismatch")
            runs.append({"repetition": repetition, "secret": secret, "response": response})
    probes = {
        secret: [r["response"]["observation"]["probes"][0] for r in runs if r["secret"] == secret]
        for secret in (0, 1)
    }
    repeatable = all(len(set(values)) == 1 for values in probes.values())
    violation = repeatable and probes[0] != probes[1]
    evidence = {
        "schema_version": 1,
        "experiment": "boom-historical-issue-715",
        "variant": variant,
        "classification": "repeatable-violation"
        if violation
        else ("deterministic-clean" if repeatable else "inconclusive"),
        "vulnerability_reproduced": violation,
        "chipyard_revision": pins["CHIPYARD_REVISION"],
        "boom_revision": pins["BOOM_REVISION"],
        "config": pins["BOOM_CONFIG"],
        "runner_sha256": digest(runner),
        "trusted_runner_sha256": digest(here / "trusted_runner.py"),
        "program_sha256": program_hash,
        "probe_sequences": {str(k): v for k, v in probes.items()},
        "runs": runs,
        "completed_at": datetime.now(UTC).isoformat(),
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(evidence, indent=2) + "\n")
    print(json.dumps(evidence, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
