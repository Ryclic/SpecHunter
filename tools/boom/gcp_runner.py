#!/usr/bin/env python3
"""Transport one validated BOOM request to an isolated GCP worker."""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path
from uuid import uuid4

MAX_REQUEST = 1_048_576
MAX_OUTPUT = 1_048_576
IDENTIFIER = re.compile(r"[a-z](?:[-a-z0-9]{0,61}[a-z0-9])?")
ZONE = re.compile(r"[a-z0-9-]{1,40}")
REQUEST_FIELDS = {
    "schema_version",
    "program",
    "program_sha256",
    "secret",
    "variant",
    "target_revision",
}


class TransportError(RuntimeError):
    pass


def bounded(command: list[str], env: dict[str, str], timeout: int) -> subprocess.CompletedProcess:
    try:
        result = subprocess.run(command, env=env, capture_output=True, timeout=timeout, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise TransportError(f"gcloud command failed: {exc}") from exc
    if len(result.stdout) + len(result.stderr) > MAX_OUTPUT:
        raise TransportError("gcloud output limit exceeded")
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--project", required=True)
    parser.add_argument("--zone", required=True)
    parser.add_argument("--instance", required=True)
    parser.add_argument("--gcloud-config", type=Path, required=True)
    parser.add_argument("--ssh-key-file", type=Path, required=True)
    parser.add_argument("request", type=Path)
    try:
        args = parser.parse_args()
        if (
            not IDENTIFIER.fullmatch(args.project)
            or not IDENTIFIER.fullmatch(args.instance)
            or not ZONE.fullmatch(args.zone)
        ):
            raise TransportError("invalid GCP resource identifier")
        if not args.gcloud_config.is_absolute() or not args.gcloud_config.is_dir():
            raise TransportError("gcloud config must be an existing absolute directory")
        if not args.ssh_key_file.is_absolute() or not args.ssh_key_file.is_file():
            raise TransportError("SSH key must be an existing absolute file")
        if not args.request.is_absolute() or args.request.stat().st_size > MAX_REQUEST:
            raise TransportError("request must be an absolute bounded file")
        request = json.loads(args.request.read_text())
        if not isinstance(request, dict) or set(request) != REQUEST_FIELDS:
            raise TransportError("invalid BOOM request envelope")
        gcloud = shutil.which("gcloud")
        if not gcloud:
            raise TransportError("gcloud is not installed")
        env = {
            key: value
            for key, value in os.environ.items()
            if key in {"PATH", "LANG", "LC_ALL", "HOME"}
        }
        env["CLOUDSDK_CONFIG"] = str(args.gcloud_config)
        remote = f"/tmp/spechunter-request-{uuid4().hex}.json"
        destination = f"{args.instance}:{remote}"
        common = [
            "--project",
            args.project,
            "--zone",
            args.zone,
            "--ssh-key-file",
            str(args.ssh_key_file),
            "--quiet",
        ]
        copy = bounded([gcloud, "compute", "scp", str(args.request), destination, *common], env, 90)
        if copy.returncode:
            raise TransportError(
                f"request upload failed: {copy.stderr.decode(errors='replace')[-2000:]}"
            )
        try:
            execute = bounded(
                [
                    gcloud,
                    "compute",
                    "ssh",
                    args.instance,
                    *common,
                    "--command",
                    f"$HOME/boom-tools/trusted_runner.py {remote}",
                ],
                env,
                1000,
            )
            if execute.returncode:
                raise TransportError(
                    f"remote runner failed: {execute.stderr.decode(errors='replace')[-2000:]}"
                )
            sys.stdout.buffer.write(execute.stdout)
        finally:
            bounded(
                [
                    gcloud,
                    "compute",
                    "ssh",
                    args.instance,
                    *common,
                    "--command",
                    f"rm -f -- {remote}",
                ],
                env,
                60,
            )
        return 0
    except (OSError, UnicodeError, json.JSONDecodeError, TransportError) as exc:
        print(f"GCP BOOM transport: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
