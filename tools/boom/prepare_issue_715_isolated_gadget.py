#!/usr/bin/env python3
"""Remove the independent load from the original #715 gadget for a diagnostic replay."""

from __future__ import annotations

import hashlib
import json
import struct
import sys
from pathlib import Path

SOURCE_SHA256 = "c7066c9e10d1d19233d5626670e404663c069afe1e168656dcab08efbaa2389b"
GADGET_VADDR = 0x80028E08
ORIGINAL_INSTRUCTION = 0x59F50483  # lb s1,1439(a0): independent third load
REPLACEMENT_INSTRUCTION = 0x00000013  # addi x0,x0,0: RISC-V NOP


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def patch_elf(source: bytes) -> tuple[bytes, int]:
    if len(source) < 64 or source[:6] != b"\x7fELF\x02\x01":
        raise ValueError("expected a little-endian ELF64 executable")
    if struct.unpack_from("<HH", source, 16) != (2, 243):
        raise ValueError("expected an executable for RISC-V")
    phoff = struct.unpack_from("<Q", source, 32)[0]
    phentsize, phnum = struct.unpack_from("<HH", source, 54)
    if phentsize != 56 or phnum < 1 or phoff + phentsize * phnum > len(source):
        raise ValueError("invalid ELF program-header table")
    matches = []
    for index in range(phnum):
        p_type, _, p_offset, p_vaddr, _, p_filesz, _, _ = struct.unpack_from(
            "<IIQQQQQQ", source, phoff + index * phentsize
        )
        if p_type == 1 and p_vaddr <= GADGET_VADDR and GADGET_VADDR + 4 <= p_vaddr + p_filesz:
            offset = p_offset + GADGET_VADDR - p_vaddr
            if offset + 4 <= len(source):
                matches.append(offset)
    if len(matches) != 1:
        raise ValueError("gadget instruction is not in exactly one file-backed LOAD segment")
    offset = matches[0]
    if struct.unpack_from("<I", source, offset)[0] != ORIGINAL_INSTRUCTION:
        raise ValueError("original independent load instruction differs")
    candidate = bytearray(source)
    struct.pack_into("<I", candidate, offset, REPLACEMENT_INSTRUCTION)
    return bytes(candidate), offset


def manifest_for(candidate: bytes, offset: int, source_sha256: str = SOURCE_SHA256) -> dict:
    return {
        "schema_version": 1,
        "experiment": "issue-715-isolate-dependent-gadget-diagnostic",
        "classification": "prepared-not-executed-no-security-claim",
        "source_elf_sha256": source_sha256,
        "candidate_elf_sha256": digest(candidate),
        "gadget_vaddr": hex(GADGET_VADDR),
        "file_offset": offset,
        "original_instruction": hex(ORIGINAL_INSTRUCTION),
        "replacement_instruction": hex(REPLACEMENT_INSTRUCTION),
        "mutation": "replace-independent-third-load-with-nop",
    }


def verify_candidate(
    source: bytes, candidate: bytes, manifest: dict, source_sha256: str = SOURCE_SHA256
) -> None:
    if digest(source) != source_sha256:
        raise ValueError("candidate source does not match original attachment")
    expected, offset = patch_elf(source)
    if candidate != expected:
        raise ValueError("candidate differs from the isolated gadget mutation")
    if manifest != manifest_for(expected, offset, source_sha256):
        raise ValueError("candidate manifest does not match the mutation")


def main() -> int:
    if len(sys.argv) != 4 or any(not Path(arg).is_absolute() for arg in sys.argv[1:]):
        print(
            "usage: prepare_issue_715_isolated_gadget.py "
            "/ABS/original.elf /ABS/isolated.elf /ABS/manifest.json",
            file=sys.stderr,
        )
        return 2
    original, output, manifest_path = (Path(arg).resolve() for arg in sys.argv[1:])
    if len({original, output, manifest_path}) != 3:
        raise ValueError("input, candidate and manifest must be distinct files")
    source = original.read_bytes()
    if digest(source) != SOURCE_SHA256:
        raise ValueError("original upstream attachment hash differs")
    candidate, offset = patch_elf(source)
    manifest = manifest_for(candidate, offset)
    output.parent.mkdir(parents=True, exist_ok=True)
    manifest_path.parent.mkdir(parents=True, exist_ok=True)
    output.write_bytes(candidate)
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n")
    print(json.dumps(manifest, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
