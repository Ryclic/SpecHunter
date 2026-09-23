"""Tests for Microarchitectural Store-to-Load Forwarding (STLF) & SSB Oracle."""

import json
from pathlib import Path

from spechunter.stlf import (
    SpeculativeSTLFOracle,
    STLFVulnerability,
)


def test_stlf_enums():
    assert STLFVulnerability.FALSE_STORE_FORWARDING_ALIAS == "FALSE_STORE_FORWARDING_ALIAS"
    assert STLFVulnerability.SPECULATIVE_STORE_BYPASS_SSB == "SPECULATIVE_STORE_BYPASS_SSB"
    assert STLFVulnerability.UNCOMMITTED_STORE_POLLUTION == "UNCOMMITTED_STORE_POLLUTION"


def test_stlf_unmitigated_false_forwarding():
    oracle = SpeculativeSTLFOracle(target_benchmark="spectre-v4")
    report = oracle.audit(stq_entries=16, mitigated=False)

    assert not report.mitigated
    assert report.target_benchmark == "spectre-v4"
    assert report.false_forwarding_detected
    assert report.speculative_bypass_detected
    assert report.stlf_isolation_score == 0.15
    assert STLFVulnerability.FALSE_STORE_FORWARDING_ALIAS.value in report.detected_vulnerabilities
    assert STLFVulnerability.SPECULATIVE_STORE_BYPASS_SSB.value in report.detected_vulnerabilities
    assert report.verdict == "VULNERABLE_SPECULATIVE_STORE_FORWARDING"
    assert len(report.stlf_events) == 3


def test_stlf_mitigated_phys_gated():
    oracle = SpeculativeSTLFOracle(target_benchmark="spectre-v4")
    report = oracle.audit(stq_entries=16, mitigated=True)

    assert report.mitigated
    assert not report.false_forwarding_detected
    assert not report.speculative_bypass_detected
    assert report.stlf_isolation_score == 1.00
    assert len(report.detected_vulnerabilities) == 0
    assert report.verdict == "VERIFIED_ISOLATED_STORE_FORWARDING"


def test_stlf_chisel_patch_and_sva():
    oracle = SpeculativeSTLFOracle(target_benchmark="spectre-v4")
    report = oracle.audit(mitigated=True)

    assert "class PhysGatedSTLFController extends Module" in report.chisel_stlf_patch_code
    assert "val full_pa_match = (io.ld_paddr === io.stq_paddr)" in report.chisel_stlf_patch_code

    sva_text = "\n".join(report.generated_sva_assertions)
    assert "property p_stlf_full_phys_addr_match" in sva_text
    assert "property p_ssb_speculative_bypass_gate" in sva_text
    assert "property p_stq_squash_invalidation" in sva_text


def test_stlf_serialization(tmp_path: Path):
    oracle = SpeculativeSTLFOracle(target_benchmark="spectre-v4")
    report = oracle.audit(mitigated=True)

    json_str = report.to_json()
    data = json.loads(json_str)
    assert data["target_benchmark"] == "spectre-v4"
    assert data["stlf_isolation_score"] == 1.0

    md_str = report.to_markdown()
    assert "# SpecHunter STLF & Store Bypass Audit: spectre-v4" in md_str
    assert "Executive Store-to-Load Disambiguation Summary" in md_str

    out_file = tmp_path / "stlf_report.json"
    oracle.export_report(out_file, report)
    assert out_file.exists()
    assert "VERIFIED_ISOLATED_STORE_FORWARDING" in out_file.read_text(encoding="utf-8")
