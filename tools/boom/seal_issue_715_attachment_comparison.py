#!/usr/bin/env python3
"""Seal matched baseline/repaired issue #715 traces without overstating results."""

from __future__ import annotations

import json
import sys
from pathlib import Path


def main() -> int:
    if len(sys.argv) != 5 or any(not Path(arg).is_absolute() for arg in sys.argv[1:]):
        print(
            "usage: seal_issue_715_attachment_comparison.py "
            "/ABSOLUTE/baseline.json /ABSOLUTE/repaired.json "
            "/ABSOLUTE/build.json /ABSOLUTE/output.json",
            file=sys.stderr,
        )
        return 2
    baseline_path, repaired_path, build_path, output = map(Path, sys.argv[1:])
    baseline = json.loads(baseline_path.read_text())
    repaired = json.loads(repaired_path.read_text())
    build = json.loads(build_path.read_text())
    if build.get("variant") != "historical-issue-715-repaired":
        raise RuntimeError("repair build manifest has the wrong variant")
    shared = ("branch_pc", "branch_fetch_cycle", "gadget_fetch_cycles", "target_mispredicts")
    same_control_flow = all(baseline[key] == repaired[key] for key in shared)
    baseline_requests = baseline["speculative_dcache_requests_before_resolution"]
    repaired_requests = repaired["speculative_dcache_requests_before_resolution"]
    repair_effective = bool(baseline_requests and not repaired_requests and same_control_flow)
    result = {
        "schema_version": 1,
        "experiment": "boom-upstream-issue-715-attachment-before-after",
        "baseline_trace_sha256": baseline["trace_sha256"],
        "repaired_trace_sha256": repaired["trace_sha256"],
        "repaired_simulator_sha256": build["simulator_sha256"],
        "matched_control_flow_and_seed": same_control_flow,
        "baseline_mechanism_witnessed": baseline["mechanism_witnessed"],
        "repaired_mechanism_witnessed": repaired["mechanism_witnessed"],
        "repair_effective": repair_effective,
        "security_fix_validated": repair_effective,
        "verdict": "repair-blocked-witness" if repair_effective else "repair-ineffective",
    }
    output.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
