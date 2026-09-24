#!/usr/bin/env python3
"""Recompute every SHA-256 binding in docs/evidence (see spechunter.evidence_check)."""

from pathlib import Path

from spechunter.evidence_check import verify_evidence


def main() -> int:
    lines, failures = verify_evidence(Path(__file__).resolve().parents[1] / "docs" / "evidence")
    print("\n".join(lines))
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
