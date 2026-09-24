"""Recompute every SHA-256 binding in the checked-in evidence seals.

Each seal names its inputs as ``<key>: <file>`` next to ``<key>_sha256``.
Verification recomputes each named file's digest, rebuilds the issue #715
attachment case seal from its raw witnesses, and reports each seal's
classification so results cannot be read out of context.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterator
from pathlib import Path

from spechunter.attachment_case import verify_seal as verify_attachment_seal

ATTACHMENT_SEAL = "boom-issue-715-attachment-demo-seal-2026-09-20.json"


def _digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _bindings(value: object, prefix: str = "") -> Iterator[tuple[str, str, str]]:
    if isinstance(value, dict):
        for key, item in value.items():
            expected = value.get(f"{key}_sha256")
            if isinstance(item, str) and isinstance(expected, str):
                yield f"{prefix}{key}", item, expected
            yield from _bindings(item, f"{prefix}{key}.")
    elif isinstance(value, list):
        for index, item in enumerate(value):
            yield from _bindings(item, f"{prefix}[{index}].")


def verify_evidence(evidence: Path) -> tuple[list[str], int]:
    """Return report lines and the number of failures for ``evidence``."""
    seals = sorted(evidence.glob("*seal*.json"))
    if not seals:
        return [f"no seals found in {evidence}"], 1
    lines: list[str] = []
    failures = checked = 0
    for seal in seals:
        problems = []
        data = json.loads(seal.read_text())
        for label, name, expected in _bindings(data):
            checked += 1
            path = evidence / name
            if not path.is_file():
                problems.append(f"{label}: missing {name}")
            elif _digest(path) != expected:
                problems.append(f"{label}: digest mismatch for {name}")
        status = "FAIL" if problems else "ok"
        lines.append(f"[{status}] {seal.name}  ({data.get('classification', '-')})")
        lines.extend(f"       {problem}" for problem in problems)
        failures += len(problems)
    try:
        verify_attachment_seal(evidence / ATTACHMENT_SEAL)
        lines.append(f"[ok] {ATTACHMENT_SEAL} rebuilt from raw witnesses")
    except Exception as error:  # noqa: BLE001 - report any verifier failure
        lines.append(f"[FAIL] {ATTACHMENT_SEAL}: {error}")
        failures += 1
    lines.append(f"{len(seals)} seals, {checked} file bindings, {failures} failures")
    return lines, failures
