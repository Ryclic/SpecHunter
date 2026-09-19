#!/usr/bin/env python3
"""Extract a stable, machine-checkable issue #715 witness from a BOOM VCD."""

from __future__ import annotations

import gzip
import hashlib
import json
import sys
from pathlib import Path
from typing import TextIO

BRANCH_PC = 0xD0100287D0
GADGET_PCS = {0xD010028E00, 0xD010028E04}
PROTECTED_VADDR = 0xD010098000
DEPENDENT_VADDR = 0x59F


def _open(path: Path) -> TextIO:
    return (
        gzip.open(path, "rt", errors="replace")
        if path.suffix == ".gz"
        else path.open(errors="replace")
    )


def _sha256(path: Path) -> str:
    value = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            value.update(block)
    return value.hexdigest()


def _one(values: dict[str, int], ids: dict[str, set[str]], name: str, default: int = 0) -> int:
    found = {values[identifier] for identifier in ids.get(name, set()) if identifier in values}
    if not found:
        return default
    if len(found) != 1:
        raise RuntimeError(f"conflicting values for aliased signal {name}: {sorted(found)}")
    return found.pop()


def _witness_flags(
    branch_fetch_cycle: int | None,
    gadget_fetches: dict[int, int],
    protected: list[dict],
    dependent: list[dict],
    faults: list[dict],
    target_mispredicts: list[dict],
) -> tuple[bool, bool]:
    if branch_fetch_cycle is None:
        return False, False
    dataflow = False
    for resolution in target_mispredicts:
        for source in protected:
            if not branch_fetch_cycle < source["cycle"] < resolution["cycle"]:
                continue
            source_mask = int(source["branch_mask"], 16)
            for sink in dependent:
                if not source["cycle"] < sink["cycle"] < resolution["cycle"]:
                    continue
                shared_mask = source_mask & int(sink["branch_mask"], 16)
                if not shared_mask:
                    continue
                dataflow = True
                gadgets_in_window = all(
                    branch_fetch_cycle < gadget_fetches.get(pc, -1) < source["cycle"]
                    for pc in GADGET_PCS
                )
                if gadgets_in_window and any(
                    sink["cycle"] < fault["cycle"] < resolution["cycle"]
                    and shared_mask & int(fault["branch_mask"], 16)
                    for fault in faults
                ):
                    return True, True
    return dataflow, False


def scan(path: Path) -> dict:  # noqa: C901 - one-pass VCD state machine
    ids: dict[str, set[str]] = {}
    pc_ids: set[str] = set()
    values: dict[str, int] = {}
    timestamp = 0
    header = True
    changed: set[str] = set()
    branch_fetch_cycle = None
    gadget_fetches: dict[int, int] = {}
    tlb_requests: list[dict] = []
    load_faults: list[dict] = []
    mispredicts: list[dict] = []

    def finish_timestamp() -> None:
        nonlocal branch_fetch_cycle
        if not changed:
            return
        cycle = timestamp // 2
        for identifier in changed & pc_ids:
            pc = values[identifier]
            if pc == BRANCH_PC and branch_fetch_cycle is None:
                branch_fetch_cycle = cycle
            if pc in GADGET_PCS:
                gadget_fetches.setdefault(pc, cycle)
        tlb_related = set().union(
            ids.get("dtlb_io_req_0_valid", set()),
            ids.get("dtlb_io_req_0_bits_vaddr", set()),
            ids.get("exe_tlb_uop_0_br_mask", set()),
        )
        if changed & tlb_related and _one(values, ids, "dtlb_io_req_0_valid"):
            mask = _one(values, ids, "exe_tlb_uop_0_br_mask")
            if mask:
                event = {
                    "cycle": cycle,
                    "vaddr": hex(_one(values, ids, "dtlb_io_req_0_bits_vaddr")),
                    "branch_mask": hex(mask),
                }
                if not tlb_requests or tlb_requests[-1] != event:
                    tlb_requests.append(event)
        fault_related = set().union(
            ids.get("lsu_io_core_lxcpt_valid", set()),
            ids.get("lsu_io_core_lxcpt_bits_cause", set()),
            ids.get("lsu_io_core_lxcpt_bits_badvaddr", set()),
        )
        if changed & fault_related and _one(values, ids, "lsu_io_core_lxcpt_valid"):
            event = {
                "cycle": cycle,
                "cause": hex(_one(values, ids, "lsu_io_core_lxcpt_bits_cause")),
                "badvaddr": hex(_one(values, ids, "lsu_io_core_lxcpt_bits_badvaddr")),
                "branch_mask": hex(_one(values, ids, "lsu_io_core_lxcpt_bits_uop_br_mask")),
            }
            if not load_faults or load_faults[-1] != event:
                load_faults.append(event)
        mispredict_related = set().union(
            ids.get("core_io_ifu_brupdate_b2_mispredict", set()),
            ids.get("ftq_io_bpdupdate_bits_pc", set()),
            ids.get("core_io_ifu_brupdate_b2_uop_pc_lob", set()),
        )
        if changed & mispredict_related and _one(values, ids, "core_io_ifu_brupdate_b2_mispredict"):
            base = _one(values, ids, "ftq_io_bpdupdate_bits_pc")
            low = _one(values, ids, "core_io_ifu_brupdate_b2_uop_pc_lob")
            event = {"cycle": cycle, "pc": hex((base & ~0x3F) | low)}
            if not mispredicts or mispredicts[-1] != event:
                mispredicts.append(event)

    with _open(path) as trace:
        for raw in trace:
            line = raw.strip()
            if header:
                if line.startswith("$var "):
                    fields = line.split()
                    width, identifier, name = int(fields[2]), fields[3], fields[4]
                    ids.setdefault(name, set()).add(identifier)
                    if width >= 40 and "pc" in name.lower():
                        pc_ids.add(identifier)
                elif "$enddefinitions" in line:
                    header = False
                continue
            if line.startswith("#"):
                finish_timestamp()
                timestamp = int(line[1:])
                changed.clear()
                continue
            identifier = None
            value = None
            if line.startswith("b"):
                bits, separator, identifier = line[1:].partition(" ")
                if separator and "x" not in bits and "z" not in bits:
                    value = int(bits, 2)
            elif len(line) > 1 and line[0] in "01":
                identifier, value = line[1:], int(line[0])
            if identifier is not None and value is not None:
                values[identifier] = value
                changed.add(identifier)
    finish_timestamp()

    target_mispredicts = [event for event in mispredicts if event["pc"] == hex(BRANCH_PC)]
    protected = [event for event in tlb_requests if event["vaddr"] == hex(PROTECTED_VADDR)]
    dependent = [event for event in tlb_requests if event["vaddr"] == hex(DEPENDENT_VADDR)]
    faults = [
        event
        for event in load_faults
        if event["cause"] == "0xd" and event["badvaddr"] == hex(PROTECTED_VADDR)
    ]
    dataflow, witness = _witness_flags(
        branch_fetch_cycle,
        gadget_fetches,
        protected,
        dependent,
        faults,
        target_mispredicts,
    )
    return {
        "schema_version": 2,
        "experiment": "boom-upstream-issue-715-vcd-witness",
        "trace_sha256": _sha256(path),
        "branch_pc": hex(BRANCH_PC),
        "branch_fetch_cycle": branch_fetch_cycle,
        "gadget_fetch_cycles": {hex(pc): gadget_fetches.get(pc) for pc in sorted(GADGET_PCS)},
        "protected_load_requests": protected,
        "dependent_load_requests": dependent,
        "load_page_faults": faults,
        "target_mispredicts": target_mispredicts,
        "transient_dataflow_witnessed": dataflow,
        "mechanism_witnessed": witness,
        "architectural_secret_disclosure_proven": False,
    }


def main() -> int:
    if len(sys.argv) != 2 or not Path(sys.argv[1]).is_absolute():
        print("usage: scan_issue_715_vcd.py /ABSOLUTE/trace.vcd[.gz]", file=sys.stderr)
        return 2
    print(json.dumps(scan(Path(sys.argv[1])), indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
