#!/usr/bin/env python3
"""Berkeley BOOM Upstream Security Test Harness CLI.

Executes SpecHunter-discovered microarchitectural exploit PoCs against simulated
and RTL microarchitectural targets, evaluating speculative side-channel leakage
and exporting standard JUnit XML for native Chipyard CI integration.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from spechunter.harness import (
    export_junit_xml,
    render_harness_json,
    render_harness_terminal,
    run_harness,
)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--pocs",
        type=str,
        default="all",
        help="Comma-separated PoC identifiers (e.g. transient-cache,issue-715) or 'all'",
    )
    parser.add_argument(
        "--verify-mitigations",
        action="store_true",
        help="Evaluate mitigated RTL variants (expects zero leakage / MITIGATED verdicts)",
    )
    parser.add_argument(
        "--junit-xml",
        type=Path,
        default=None,
        help="Path to export JUnit XML report for CI ingestion",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Format output as machine-readable JSON",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=None,
        help="Path to save report output",
    )

    args = parser.parse_args(argv)

    poc_list = None
    if args.pocs != "all":
        poc_list = [p.strip() for p in args.pocs.split(",")]

    report = run_harness(poc_names=poc_list, verify_mitigations=args.verify_mitigations)

    if args.junit_xml:
        export_junit_xml(report, args.junit_xml)
        print(f"JUnit XML exported to: {args.junit_xml}")

    output_str = render_harness_json(report) if args.json else render_harness_terminal(report)

    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(output_str, encoding="utf-8")
        print(f"Harness report saved to: {args.output}")
    else:
        print(output_str)

    return 0


if __name__ == "__main__":
    sys.exit(main())
