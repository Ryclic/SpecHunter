import importlib.util
import json
import struct
from pathlib import Path
from types import SimpleNamespace

import pytest

SCRIPT = Path(__file__).parents[1] / "tools/boom/prepare_issue_715_isolated_gadget.py"
RUNNER_SCRIPT = SCRIPT.with_name("run_historical_issue_715_attachment.py")
SPEC = importlib.util.spec_from_file_location("isolated_gadget", SCRIPT)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader
SPEC.loader.exec_module(MODULE)
RUNNER_SPEC = importlib.util.spec_from_file_location("historical_attachment_runner", RUNNER_SCRIPT)
RUNNER = importlib.util.module_from_spec(RUNNER_SPEC)
assert RUNNER_SPEC.loader
RUNNER_SPEC.loader.exec_module(RUNNER)
GADGET_VADDR = MODULE.GADGET_VADDR
ORIGINAL_INSTRUCTION = MODULE.ORIGINAL_INSTRUCTION
REPLACEMENT_INSTRUCTION = MODULE.REPLACEMENT_INSTRUCTION
patch_elf = MODULE.patch_elf


def elf_with_gadget() -> bytes:
    data = bytearray(0x88)
    data[:6] = b"\x7fELF\x02\x01"
    struct.pack_into("<HH", data, 16, 2, 243)
    struct.pack_into("<Q", data, 32, 64)
    struct.pack_into("<HH", data, 54, 56, 1)
    struct.pack_into("<IIQQQQQQ", data, 64, 1, 7, 0x78, GADGET_VADDR - 4, 0, 12, 12, 4)
    struct.pack_into("<I", data, 0x7C, ORIGINAL_INSTRUCTION)
    return bytes(data)


def test_mutation_changes_only_independent_instruction():
    original = elf_with_gadget()
    patched, offset = patch_elf(original)
    assert offset == 0x7C
    assert patched[:offset] == original[:offset]
    assert patched[offset + 4 :] == original[offset + 4 :]
    assert struct.unpack_from("<I", patched, offset)[0] == REPLACEMENT_INSTRUCTION
    with pytest.raises(ValueError, match="instruction differs"):
        patch_elf(patched)


def test_wrong_architecture_and_segment_are_rejected():
    wrong_arch = bytearray(elf_with_gadget())
    struct.pack_into("<H", wrong_arch, 18, 62)
    with pytest.raises(ValueError, match="RISC-V"):
        patch_elf(bytes(wrong_arch))
    missing_gadget = bytearray(elf_with_gadget())
    struct.pack_into("<Q", missing_gadget, 64 + 32, 4)
    with pytest.raises(ValueError, match="exactly one"):
        patch_elf(bytes(missing_gadget))


def test_runner_candidate_verifier_rejects_tampered_binary_or_manifest():
    source = elf_with_gadget()
    candidate, offset = patch_elf(source)
    source_sha = MODULE.digest(source)
    manifest = MODULE.manifest_for(candidate, offset, source_sha)
    MODULE.verify_candidate(source, candidate, manifest, source_sha)
    with pytest.raises(ValueError, match="candidate differs"):
        MODULE.verify_candidate(source, source, manifest, source_sha)
    with pytest.raises(ValueError, match="manifest"):
        MODULE.verify_candidate(
            source, candidate, {**manifest, "classification": "verified-fix"}, source_sha
        )
    with pytest.raises(ValueError, match="source"):
        MODULE.verify_candidate(source, candidate, manifest)


def test_diagnostic_refuses_simulator_without_waveform_support(monkeypatch):
    def simulator_help(argv, **kwargs):
        assert argv == ["/simulator", "--help"]
        assert kwargs["check"] and kwargs["timeout"] == 30
        return SimpleNamespace(stdout="Usage: simulator [--max-cycles]")

    monkeypatch.setattr(RUNNER.subprocess, "run", simulator_help)
    with pytest.raises(RuntimeError, match="trace-enabled"):
        RUNNER.require_waveform_support(Path("/simulator"))
    monkeypatch.setattr(
        RUNNER.subprocess,
        "run",
        lambda *args, **kwargs: SimpleNamespace(stdout="Usage: simulator [--vcd=FILE]"),
    )
    RUNNER.require_waveform_support(Path("/simulator"))


@pytest.mark.parametrize(
    ("suffix", "trace"),
    [
        (".log", False),
        (".loadmem.hex", False),
        (".vcd", True),
        (".witness.json", True),
    ],
)
def test_runner_refuses_to_overwrite_any_existing_artifact(tmp_path, suffix, trace):
    output = tmp_path / "diagnostic.json"
    existing = output.with_suffix(suffix)
    existing.write_text("preserve me")

    with pytest.raises(RuntimeError, match="artifact path already exists"):
        RUNNER.require_fresh_artifact_paths(output, trace=trace)

    assert existing.read_text() == "preserve me"


def test_runner_checks_exact_evidence_path_with_non_json_suffix(tmp_path):
    output = tmp_path / "diagnostic.record"
    output.write_text("preserve me")

    with pytest.raises(RuntimeError, match="artifact path already exists"):
        RUNNER.require_fresh_artifact_paths(output, trace=False)

    assert output.read_text() == "preserve me"


def test_diagnostic_witness_is_scanned_and_bound_to_raw_waveform(tmp_path):
    evidence = Path(__file__).parents[1] / "docs/evidence"
    waveform = evidence / "boom-issue-715-attachment-baseline-seed-1789717734-2026-09-17.vcd.gz"
    destination = tmp_path / "baseline.witness.json"
    witness_sha = RUNNER.write_diagnostic_witness(waveform, destination)
    checked = evidence / "boom-issue-715-attachment-baseline-2026-09-17.json"
    assert json.loads(destination.read_text()) == json.loads(checked.read_text())
    assert RUNNER.digest(destination) == witness_sha
    assert json.loads(destination.read_text())["trace_sha256"] == RUNNER.digest(waveform)
