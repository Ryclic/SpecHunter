import hashlib
import importlib.util
import io
import json
import sys
import zipfile
from pathlib import Path

ROOT = Path(__file__).parents[1]
SCRIPT = ROOT / "tools/boom/fetch_issue_715_attachment.py"
SPEC = importlib.util.spec_from_file_location("fetch_issue_715_attachment", SCRIPT)
FETCH = importlib.util.module_from_spec(SPEC)
assert SPEC.loader
SPEC.loader.exec_module(FETCH)


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
    assert evidence["mechanism_witnessed"] is True
    assert evidence["architectural_secret_disclosure_proven"] is False
    assert evidence["branch_fetch_cycle"] < evidence["gadget_fetch_cycles"]["0xd010028e00"]
    request = evidence["speculative_dcache_requests_before_resolution"][0]
    resolution = evidence["target_mispredicts"][0]
    assert request["branch_mask"] == "0x1"
    assert request["cycle"] < resolution["cycle"]
    assert resolution["pc"] == evidence["branch_pc"]


def test_matched_repair_result_is_fail_closed():
    evidence = json.loads(
        (ROOT / "docs/evidence/boom-issue-715-attachment-comparison-2026-09-17.json").read_text()
    )
    assert evidence["matched_control_flow_and_seed"] is True
    assert evidence["baseline_mechanism_witnessed"] is True
    assert evidence["repaired_mechanism_witnessed"] is True
    assert evidence["repair_effective"] is False
    assert evidence["security_fix_validated"] is False
    assert evidence["verdict"] == "repair-ineffective"
