"""Tests for Microarchitectural Data Sampling (MDS) & Line Fill Buffer Oracle."""

import json
from pathlib import Path

from spechunter.mds import (
    MDSVulnerability,
    SpeculativeMDSOracle,
)


def test_mds_enums():
    assert MDSVulnerability.MSHR_RESIDUAL_DATA_LEAK == "MSHR_RESIDUAL_DATA_LEAK"
    assert MDSVulnerability.LINE_FILL_BUFFER_SAMPLING == "LINE_FILL_BUFFER_SAMPLING"
    assert MDSVulnerability.SPECULATIVE_FAULT_FORWARDING == "SPECULATIVE_FAULT_FORWARDING"


def test_mds_unmitigated_leak():
    oracle = SpeculativeMDSOracle(target_benchmark="privilege-bypass")
    report = oracle.audit(mshr_entries=4, mitigated=False)

    assert not report.mitigated
    assert report.target_benchmark == "privilege-bypass"
    assert report.residual_leak_detected
    assert report.sampling_rate == 1.00
    assert report.mds_isolation_score == 0.10
    assert MDSVulnerability.MSHR_RESIDUAL_DATA_LEAK.value in report.detected_vulnerabilities
    assert MDSVulnerability.LINE_FILL_BUFFER_SAMPLING.value in report.detected_vulnerabilities
    assert report.verdict == "VULNERABLE_MICROARCHITECTURAL_DATA_SAMPLING"
    assert len(report.mds_events) == 3


def test_mds_mitigated_isolation():
    oracle = SpeculativeMDSOracle(target_benchmark="privilege-bypass")
    report = oracle.audit(mshr_entries=4, mitigated=True)

    assert report.mitigated
    assert not report.residual_leak_detected
    assert report.sampling_rate == 0.00
    assert report.mds_isolation_score == 1.00
    assert len(report.detected_vulnerabilities) == 0
    assert report.verdict == "VERIFIED_MDS_ISOLATION"


def test_mds_chisel_patch_and_sva():
    oracle = SpeculativeMDSOracle(target_benchmark="privilege-bypass")
    report = oracle.audit(mitigated=True)

    assert "val forward_permitted = io.mshr_valid_in" in report.chisel_mds_patch_code
    assert "!io.uop_fault_pending" in report.chisel_mds_patch_code

    sva_text = "\n".join(report.generated_sva_assertions)
    assert "property p_lfb_fault_quarantine" in sva_text
    assert "property p_mshr_residual_zeroization" in sva_text
    assert "property p_mds_cross_context_isolation" in sva_text


def test_mds_serialization(tmp_path: Path):
    oracle = SpeculativeMDSOracle(target_benchmark="privilege-bypass")
    report = oracle.audit(mitigated=True)

    json_str = report.to_json()
    data = json.loads(json_str)
    assert data["target_benchmark"] == "privilege-bypass"
    assert data["mds_isolation_score"] == 1.0

    md_str = report.to_markdown()
    assert "# SpecHunter MDS & Line Fill Buffer Audit: privilege-bypass" in md_str
    assert "Executive Microarchitectural Data Sampling Summary" in md_str

    out_file = tmp_path / "mds_report.json"
    oracle.export_report(out_file, report)
    assert out_file.exists()
    assert "VERIFIED_MDS_ISOLATION" in out_file.read_text(encoding="utf-8")
