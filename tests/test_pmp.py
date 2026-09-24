"""Tests for RISC-V Physical Memory Protection (PMP) Speculative Boundary Oracle."""

import json
from pathlib import Path

from spechunter.pmp import (
    PMPEntry,
    PMPMatchMode,
    PMPVulnerability,
    SpeculativePMPOracle,
)


def test_pmp_entry_matching():
    # Test TOR entry
    entry_tor = PMPEntry(
        entry_id=0,
        mode=PMPMatchMode.TOR,
        base_address=0x80002000,
        size_bytes=0x1000,
        read=False,
        write=False,
        execute=False,
        locked=True,
    )
    assert entry_tor.matches(0x80002000)
    assert entry_tor.matches(0x80002800)
    assert not entry_tor.matches(0x80003000)
    assert not entry_tor.matches(0x80001FFF)
    assert not entry_tor.allows_read(priv_mode=0)  # U-mode
    assert not entry_tor.allows_read(priv_mode=3)  # M-mode denied because locked=True

    # Test NA4 entry
    entry_na4 = PMPEntry(
        entry_id=1,
        mode=PMPMatchMode.NA4,
        base_address=0x80004000,
        size_bytes=4,
        read=True,
        write=False,
        execute=False,
        locked=False,
    )
    assert entry_na4.matches(0x80004000)
    assert entry_na4.matches(0x80004003)
    assert not entry_na4.matches(0x80004004)


def test_pmp_baseline_vulnerability():
    oracle = SpeculativePMPOracle()
    report = oracle.audit(mitigated=False)

    assert not report.mitigated
    assert report.pmp_isolation_score == 0.125
    assert report.security_verdict == "VULNERABLE_SPECULATIVE_PMP_BYPASS"
    assert report.speculative_bypasses_detected > 0
    assert report.pmp_toctou_cycles == 2
    assert PMPVulnerability.SPECULATIVE_PMP_BYPASS in report.detected_vulnerabilities
    assert PMPVulnerability.PMP_TOCTOU_RACE in report.detected_vulnerabilities


def test_pmp_mitigated_isolation():
    oracle = SpeculativePMPOracle()
    report = oracle.audit(mitigated=True)

    assert report.mitigated
    assert report.pmp_isolation_score == 1.000
    assert report.security_verdict == "VERIFIED_PMP_HARDWARE_ENFORCEMENT"
    assert report.speculative_bypasses_detected == 0
    assert report.pmp_toctou_cycles == 0
    assert len(report.detected_vulnerabilities) == 0
    assert "class GatedPMPChecker" in report.generated_chisel_patch
    assert any("p_pmp_speculative_req_gate" in s for s in report.generated_sva_assertions)


def test_pmp_serialization(tmp_path: Path):
    oracle = SpeculativePMPOracle()
    report = oracle.audit(mitigated=True)

    json_str = report.to_json()
    data = json.loads(json_str)
    assert data["pmp_isolation_score"] == 1.0
    assert data["security_verdict"] == "VERIFIED_PMP_HARDWARE_ENFORCEMENT"

    md_str = report.to_markdown()
    assert "CO-DESIGNED GATED PMP [ACTIVE]" in md_str
    assert "GatedPMPChecker.scala" in md_str

    out_file = tmp_path / "pmp_report.json"
    oracle.export_report(out_file, report)
    assert out_file.is_file()
    assert "VERIFIED_PMP_HARDWARE_ENFORCEMENT" in out_file.read_text(encoding="utf-8")
