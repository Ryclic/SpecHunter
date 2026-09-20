import hashlib
import importlib.util
import io
import json
import sys
import zipfile
from pathlib import Path

import pytest

ROOT = Path(__file__).parents[1]
SCRIPT = ROOT / "tools/boom/fetch_issue_715_attachment.py"
SPEC = importlib.util.spec_from_file_location("fetch_issue_715_attachment", SCRIPT)
FETCH = importlib.util.module_from_spec(SPEC)
assert SPEC.loader
SPEC.loader.exec_module(FETCH)
SCAN_SCRIPT = ROOT / "tools/boom/scan_issue_715_vcd.py"
SCAN_SPEC = importlib.util.spec_from_file_location("scan_issue_715_vcd", SCAN_SCRIPT)
SCAN = importlib.util.module_from_spec(SCAN_SPEC)
assert SCAN_SPEC.loader
SCAN_SPEC.loader.exec_module(SCAN)


@pytest.mark.parametrize(
    ("trace_name", "witness_name"),
    [
        ("baseline-seed-1789717734-2026-09-17.vcd.gz", "baseline-2026-09-17.json"),
        ("repaired-seed-1789717734-2026-09-17.vcd.gz", "repaired-2026-09-17.json"),
        ("repair-v2-seed-1789717734-2026-09-18.vcd.gz", "repair-v2-2026-09-18.json"),
        (
            "repair-v3-seed-1789717734-2026-09-18.vcd.gz",
            "repair-v3-witness-2026-09-18.json",
        ),
    ],
)
def test_checked_in_witness_recomputes_from_raw_waveform(trace_name, witness_name):
    evidence = ROOT / "docs/evidence"
    prefix = "boom-issue-715-attachment-"
    assert SCAN.scan(evidence / (prefix + trace_name)) == json.loads(
        (evidence / (prefix + witness_name)).read_text()
    )


def archive(payload: bytes) -> bytes:
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w") as bundle:
        bundle.writestr("program.elf", payload)
    return output.getvalue()


def test_fetcher_verifies_archive_and_elf(monkeypatch, tmp_path):
    elf = b"exact upstream attachment"
    bundle = archive(elf)
    monkeypatch.setattr(
        FETCH,
        "pins",
        lambda _: {
            "ISSUE_715_ATTACHMENT_URL": "https://example.invalid/program.elf.zip",
            "ISSUE_715_ATTACHMENT_ZIP_SHA256": hashlib.sha256(bundle).hexdigest(),
            "ISSUE_715_ATTACHMENT_ELF_SHA256": hashlib.sha256(elf).hexdigest(),
        },
    )
    monkeypatch.setattr(FETCH.urllib.request, "urlopen", lambda *args, **kwargs: io.BytesIO(bundle))
    output = tmp_path / "program.elf"
    monkeypatch.setattr(sys, "argv", [str(SCRIPT), str(output)])

    assert FETCH.main() == 0
    assert output.read_bytes() == elf


def test_fetcher_rejects_archive_digest_mismatch(monkeypatch, tmp_path):
    bundle = archive(b"altered")
    monkeypatch.setattr(
        FETCH,
        "pins",
        lambda _: {
            "ISSUE_715_ATTACHMENT_URL": "https://example.invalid/program.elf.zip",
            "ISSUE_715_ATTACHMENT_ZIP_SHA256": "0" * 64,
            "ISSUE_715_ATTACHMENT_ELF_SHA256": "0" * 64,
        },
    )
    monkeypatch.setattr(FETCH.urllib.request, "urlopen", lambda *args, **kwargs: io.BytesIO(bundle))
    monkeypatch.setattr(sys, "argv", [str(SCRIPT), str(tmp_path / "program.elf")])

    try:
        FETCH.main()
    except RuntimeError as exc:
        assert str(exc) == "issue #715 attachment archive digest mismatch"
    else:
        raise AssertionError("altered attachment was accepted")


def test_historical_trace_seal_records_ordered_issue_mechanism():
    trace = (
        ROOT / "docs/evidence/boom-issue-715-attachment-baseline-seed-1789717734-2026-09-17.vcd.gz"
    )
    evidence = json.loads(
        (ROOT / "docs/evidence/boom-issue-715-attachment-baseline-2026-09-17.json").read_text()
    )
    assert hashlib.sha256(trace.read_bytes()).hexdigest() == evidence["trace_sha256"]
    assert evidence["mechanism_witnessed"] is False
    assert evidence["architectural_secret_disclosure_proven"] is False
    assert (
        evidence["branch_frontend_pc_cycle"] < evidence["gadget_frontend_pc_cycles"]["0xd010028e00"]
    )
    assert evidence["gadget_frontend_pc_cycles"]["0xd010028e04"] == 3802
    assert evidence["tlb_miss_fast_wakeup_observations"] == [
        {
            "cycle": 3808,
            "preceding_protected_request_cycle": 3807,
            "wakeup_pdst": "0x12",
            "tlb_miss": True,
            "dcache_request_fired": False,
        }
    ]
    protected = evidence["protected_load_requests"][0]
    request = evidence["observed_address_requests"][0]
    resolution = evidence["target_mispredicts"][0]
    assert evidence["transient_dataflow_witnessed"] is False
    assert evidence["dependent_load_requests"] == []
    assert evidence["dependent_load_exe_requests"] == []
    assert evidence["dependent_load_dispatches"][0]["prs1"] == protected["pdst"]
    assert evidence["dependent_load_issues"] == [
        {
            "cycle": 3809,
            "pdst": "0x15",
            "prs1": "0x12",
            "prs1_poisoned": True,
            "load_miss": True,
            "register_read_valid": False,
            "ldq_idx": "0x1",
            "rob_idx": "0x1",
            "branch_mask": "0x1",
            "dispatch_pc_lob": "0x4",
        }
    ]
    assert request["dispatch_pc_lob"] == "0x8"
    assert protected["vaddr"] == "0xd010098000"
    assert protected["cycle"] < request["cycle"]
    assert request["vaddr"] == "0x59f"
    assert request["branch_mask"] == "0x1"
    assert request["cycle"] < resolution["cycle"]
    assert resolution["pc"] == evidence["branch_pc"]


def test_v3_suppressed_wakeup_and_dependent_issue_not_independent_request():
    evidence = json.loads(
        (
            ROOT / "docs/evidence/boom-issue-715-attachment-repair-v3-witness-2026-09-18.json"
        ).read_text()
    )
    assert evidence["tlb_miss_fast_wakeup_observations"] == []
    assert evidence["dependent_load_requests"] == []
    assert evidence["dependent_load_exe_requests"] == []
    assert evidence["dependent_load_issues"] == []
    assert all(event["dispatch_pc_lob"] == "0x8" for event in evidence["observed_address_requests"])
    assert evidence["mechanism_witnessed"] is False


def test_matched_repair_result_is_fail_closed():
    evidence = json.loads(
        (ROOT / "docs/evidence/boom-issue-715-attachment-comparison-2026-09-17.json").read_text()
    )
    assert evidence["matched_control_flow"] is True
    assert evidence["seed_provenance"] == "bound-by-run-logs"
    assert evidence["seed"] == 1789717734
    assert evidence["baseline_mechanism_witnessed"] is False
    assert evidence["repaired_mechanism_witnessed"] is False
    assert evidence["repair_effective"] is False
    assert evidence["security_fix_validated"] is False
    assert evidence["verdict"] == "inconclusive-baseline-not-reproduced"
