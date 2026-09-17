#!/usr/bin/env python3
"""Extract a bounded, machine-checkable issue #715 witness from a BOOM VCD."""

from __future__ import annotations

import gzip
import hashlib
import json
import sys
from pathlib import Path
from typing import TextIO

BRANCH_PC = 0xD0100287D0
GADGET_PCS = {0xD010028E00, 0xD010028E04}


def _open(path: Path) -> TextIO:
    if path.suffix == ".gz":
        return gzip.open(path, "rt", errors="replace")
    return path.open(errors="replace")


def _sha256(path: Path) -> str:
    value = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            value.update(block)
    return value.hexdigest()


def _single_value(values: dict[str, int], ids: dict[str, set[str]], name: str) -> int:
    found = {values[identifier] for identifier in ids.get(name, set()) if identifier in values}
    if len(found) != 1:
        raise RuntimeError(f"expected one current value for {name}, found {sorted(found)}")
    return found.pop()


def scan(path: Path) -> dict:
    ids: dict[str, set[str]] = {}
    pc_ids: set[str] = set()
    values: dict[str, int] = {}
    timestamp = 0
    in_header = True
    branch_fetch_cycle = None
    gadget_fetches: dict[int, int] = {}
    speculative_requests = []
    mispredicts = []

    with _open(path) as trace:
        for raw in trace:
            line = raw.strip()
            if in_header:
                if line.startswith("$var "):
                    fields = line.split()
                    width, identifier, name = int(fields[2]), fields[3], fields[4]
                    ids.setdefault(name, set()).add(identifier)
                    if width >= 40 and "pc" in name.lower():
                        pc_ids.add(identifier)
                elif "$enddefinitions" in line:
                    in_header = False
                continue
            changed = None
            if line.startswith("#"):
                timestamp = int(line[1:])
                continue
            if line.startswith("b"):
                bits, separator, identifier = line[1:].partition(" ")
                if separator and "x" not in bits and "z" not in bits:
                    values[identifier] = int(bits, 2)
                    changed = identifier
            elif len(line) > 1 and line[0] in "01":
                changed = line[1:]
                values[changed] = int(line[0])
            if changed is None:
                continue

            cycle = timestamp // 2
            if changed in pc_ids:
                pc = values[changed]
                if pc == BRANCH_PC and branch_fetch_cycle is None:
                    branch_fetch_cycle = cycle
                if pc in GADGET_PCS:
                    gadget_fetches.setdefault(pc, cycle)

            valid_ids = ids.get("lsu_io_dmem_req_bits_0_valid", set())
            if changed in valid_ids and values[changed] == 1:
                mask = _single_value(values, ids, "lsu_io_dmem_req_bits_0_bits_uop_br_mask")
                if mask:
                    address = _single_value(values, ids, "lsu_io_dmem_req_bits_0_bits_addr")
                    speculative_requests.append(
                        {"cycle": cycle, "address": hex(address), "branch_mask": hex(mask)}
                    )

            mispredict_ids = ids.get("core_io_ifu_brupdate_b2_mispredict", set())
            if changed in mispredict_ids and values[changed] == 1:
                base = _single_value(values, ids, "ftq_io_bpdupdate_bits_pc")
                low = _single_value(values, ids, "core_io_ifu_brupdate_b2_uop_pc_lob")
                pc = (base & ~0x3F) | low
                mispredicts.append({"cycle": cycle, "pc": hex(pc)})

    target_mispredicts = [event for event in mispredicts if event["pc"] == hex(BRANCH_PC)]
    ordered_requests = [
        event
        for event in speculative_requests
        if gadget_fetches
        and event["cycle"] >= min(gadget_fetches.values())
        and target_mispredicts
        and event["cycle"] < target_mispredicts[0]["cycle"]
    ]
    witness = bool(
        branch_fetch_cycle is not None
        and GADGET_PCS.issubset(gadget_fetches)
        and ordered_requests
        and target_mispredicts
    )
    return {
        "schema_version": 1,
        "experiment": "boom-upstream-issue-715-vcd-witness",
        "trace_sha256": _sha256(path),
        "branch_pc": hex(BRANCH_PC),
        "branch_fetch_cycle": branch_fetch_cycle,
        "gadget_fetch_cycles": {hex(pc): gadget_fetches.get(pc) for pc in sorted(GADGET_PCS)},
        "speculative_dcache_requests_before_resolution": ordered_requests,
        "target_mispredicts": target_mispredicts,
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
