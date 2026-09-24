"""Tests for Speculative Return Address Stack (RAS) & RETbleed Oracle."""

import json
from pathlib import Path

from spechunter.ras import (
    RASVulnerability,
    SpeculativeRASOracle,
)


def test_ras_baseline_vulnerability():
    oracle = SpeculativeRASOracle()
    report = oracle.audit(mitigated=False)

    assert not report.mitigated
    assert report.ras_isolation_score == 0.125
    assert report.security_verdict == "VULNERABLE_SPECULATIVE_RETURN_HIJACK"
    assert report.speculative_divergences_detected > 0
    assert report.underflow_events > 0
    assert report.polluted_entries > 0
    assert RASVulnerability.RAS_UNDERFLOW_HIJACK in report.detected_vulnerabilities
    assert RASVulnerability.SPECULATIVE_RAS_POLLUTION in report.detected_vulnerabilities
    assert RASVulnerability.CROSS_PRIVILEGE_RETURN_ALIAS in report.detected_vulnerabilities


def test_ras_mitigated_isolation():
    oracle = SpeculativeRASOracle()
    report = oracle.audit(mitigated=True)

    assert report.mitigated
    assert report.ras_isolation_score == 1.000
    assert report.security_verdict == "VERIFIED_RAS_SPECULATIVE_ISOLATION"
    assert report.speculative_divergences_detected == 0
    assert report.underflow_events == 0
    assert report.polluted_entries == 0
    assert len(report.detected_vulnerabilities) == 0
    assert "class SpecGatedRAS" in report.generated_chisel_patch
    assert any("p_ras_checkpoint_restore" in s for s in report.generated_sva_assertions)
    assert any("p_ras_underflow_barrier" in s for s in report.generated_sva_assertions)


def test_ras_serialization(tmp_path: Path):
    oracle = SpeculativeRASOracle()
    report = oracle.audit(mitigated=True)

    json_str = report.to_json()
    data = json.loads(json_str)
    assert data["ras_isolation_score"] == 1.0
    assert data["security_verdict"] == "VERIFIED_RAS_SPECULATIVE_ISOLATION"

    md_str = report.to_markdown()
    assert "CO-DESIGNED SPEC-GATED RAS [ACTIVE]" in md_str
    assert "SpecGatedRAS.scala" in md_str

    out_file = tmp_path / "ras_report.json"
    oracle.export_report(out_file, report)
    assert out_file.is_file()
    assert "VERIFIED_RAS_SPECULATIVE_ISOLATION" in out_file.read_text(encoding="utf-8")
