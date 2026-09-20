#!/usr/bin/env python3
"""Seal matched baseline/repaired issue #715 traces without overstating results."""

from __future__ import annotations

import hashlib
import json
import re
import sys
from pathlib import Path


def _trigger_preserved(witness: dict) -> bool:
    branch = witness["branch_frontend_pc_cycle"]
    gadget_cycles = witness["gadget_frontend_pc_cycles"]
    if not {"0xd010028e00", "0xd010028e04"} <= gadget_cycles.keys():
        return False
    gadgets = gadget_cycles.values()
    if branch is None:
        return False
    resolutions = [event for event in witness["target_mispredicts"] if event["cycle"] > branch]
    if not resolutions:
        return False
    resolution = min(resolutions, key=lambda event: event["cycle"])
    for source in witness["protected_load_requests"]:
        if source["vaddr"] != "0xd010098000":
            continue
        if not branch < source["cycle"] < resolution["cycle"]:
            continue
        if not all(cycle is not None and branch < cycle < source["cycle"] for cycle in gadgets):
            continue
        source_mask = int(source["branch_mask"], 16)
        if any(
            source["cycle"] < fault["cycle"] < resolution["cycle"]
            and fault["cause"] == "0xd"
            and fault["badvaddr"] == source["vaddr"]
            and source_mask & int(fault["branch_mask"], 16)
            for fault in witness["load_page_faults"]
        ):
            return True
    return False


def _run_provenance(path: Path) -> tuple[int, str]:
    matches = re.findall(
        r"^\*\*\* FAILED \*\*\* via trace_count \(timeout, seed (\d+)\) after 10000 cycles$",
        path.read_text(errors="replace"),
        flags=re.MULTILINE,
    )
    if len(matches) != 1:
        raise RuntimeError(f"run log lacks one pinned-seed 10,000-cycle completion: {path}")
    return int(matches[0]), hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> int:
    if len(sys.argv) != 7 or any(not Path(arg).is_absolute() for arg in sys.argv[1:]):
        print(
            "usage: seal_issue_715_attachment_comparison.py "
            "/ABSOLUTE/baseline.json /ABSOLUTE/repaired.json "
            "/ABSOLUTE/build.json /ABSOLUTE/baseline.log "
            "/ABSOLUTE/repaired.log /ABSOLUTE/output.json",
            file=sys.stderr,
        )
        return 2
    baseline_path, repaired_path, build_path, baseline_run, repaired_run, output = map(
        Path, sys.argv[1:]
    )
    baseline = json.loads(baseline_path.read_text())
    repaired = json.loads(repaired_path.read_text())
    build = json.loads(build_path.read_text())
    allowed_variants = {
        "historical-issue-715-repaired",
        "historical-issue-715-speculative-load-block",
        "historical-issue-715-fault-dependent-kill",
        "historical-issue-715-dcache-fired-wakeup",
    }
    if build.get("variant") not in allowed_variants:
        raise RuntimeError("repair build manifest has the wrong variant")
    baseline_seed, baseline_run_hash = _run_provenance(baseline_run)
    repaired_seed, repaired_run_hash = _run_provenance(repaired_run)
    if baseline_seed != repaired_seed:
        raise RuntimeError("baseline and repaired runs used different seeds")
    same_control_flow = bool(
        baseline["branch_pc"] == repaired["branch_pc"]
        and baseline["gadget_frontend_pc_cycles"].keys()
        == repaired["gadget_frontend_pc_cycles"].keys()
        and baseline["target_mispredicts"]
        and repaired["target_mispredicts"]
        and baseline["target_mispredicts"][0]["pc"] == repaired["target_mispredicts"][0]["pc"]
    )
    baseline_requests = baseline["dependent_load_requests"]
    repaired_requests = repaired["dependent_load_requests"]
    repaired_trigger_preserved = _trigger_preserved(repaired)
    repair_effective = bool(
        baseline["mechanism_witnessed"]
        and baseline_requests
        and not repaired_requests
        and same_control_flow
        and repaired_trigger_preserved
        and not repaired["mechanism_witnessed"]
    )
    repair_ineffective = bool(
        baseline["mechanism_witnessed"]
        and repaired["mechanism_witnessed"]
        and same_control_flow
        and repaired_trigger_preserved
    )
    result = {
        "schema_version": 5,
        "experiment": "boom-upstream-issue-715-attachment-before-after",
        "repair_variant": build["variant"],
        "baseline_trace_sha256": baseline["trace_sha256"],
        "repaired_trace_sha256": repaired["trace_sha256"],
        "repaired_simulator_sha256": build["simulator_sha256"],
        "matched_control_flow": same_control_flow,
        "seed_provenance": "bound-by-run-logs",
        "seed": baseline_seed,
        "baseline_run_log_sha256": baseline_run_hash,
        "repaired_run_log_sha256": repaired_run_hash,
        "baseline_mechanism_witnessed": baseline["mechanism_witnessed"],
        "repaired_mechanism_witnessed": repaired["mechanism_witnessed"],
        "repaired_trigger_preserved": repaired_trigger_preserved,
        "baseline_dependent_requests": baseline_requests,
        "repaired_dependent_requests": repaired_requests,
        "baseline_observed_address_requests": baseline["observed_address_requests"],
        "repaired_observed_address_requests": repaired["observed_address_requests"],
        "repair_effective": repair_effective,
        "security_fix_validated": False,
        "attacker_retest_required": repair_effective,
        "verdict": (
            "inconclusive-baseline-not-reproduced"
            if not baseline["mechanism_witnessed"]
            else "repair-blocked-witness"
            if repair_effective
            else "repair-ineffective"
            if repair_ineffective
            else "inconclusive-unmatched-trigger"
        ),
    }
    output.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
