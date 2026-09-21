#!/usr/bin/env python3
"""Fetch and verify the exact stripped ELF attached to upstream BOOM issue #715."""

from __future__ import annotations

import hashlib
import io
import sys
import urllib.request
import zipfile
from pathlib import Path


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def pins(path: Path) -> dict[str, str]:
    return dict(
        line.split("=", 1)
        for line in path.read_text().splitlines()
        if line and not line.startswith("#")
    )


def main() -> int:
    if len(sys.argv) != 2 or not Path(sys.argv[1]).is_absolute():
        print("usage: fetch_issue_715_attachment.py /ABSOLUTE/program.elf", file=sys.stderr)
        return 2
    values = pins(Path(__file__).with_name("issue_715_attachment.env"))
    with urllib.request.urlopen(values["ISSUE_715_ATTACHMENT_URL"], timeout=60) as response:
        archive = response.read()
    if digest(archive) != values["ISSUE_715_ATTACHMENT_ZIP_SHA256"]:
        raise RuntimeError("issue #715 attachment archive digest mismatch")
    with zipfile.ZipFile(io.BytesIO(archive)) as bundle:
        if bundle.namelist() != ["program.elf"]:
            raise RuntimeError("issue #715 attachment has unexpected contents")
        elf = bundle.read("program.elf")
    if digest(elf) != values["ISSUE_715_ATTACHMENT_ELF_SHA256"]:
        raise RuntimeError("issue #715 attachment ELF digest mismatch")
    output = Path(sys.argv[1])
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_bytes(elf)
    output.chmod(0o644)
    print(f"{values['ISSUE_715_ATTACHMENT_ELF_SHA256']}  {output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
