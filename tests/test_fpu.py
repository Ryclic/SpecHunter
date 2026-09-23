"""Tests for Speculative Floating-Point Unit (FPU) & Constant-Time Oracle."""

import json
from pathlib import Path

from spechunter.fpu import (
    FPUVulnerability,
    SpeculativeFPUOracle,
)


def test_fpu_baseline_vulnerability():
    oracle = SpeculativeFPUOracle()
    report = oracle.audit(mitigated=False)

    assert not report.mitigated
    assert report.fpu_isolation_score == 0.200
    assert report.security_verdict == "VULNERABLE_SPECULATIVE_FPU_TIMING_CHANNEL"
    assert report.timing_differential_cycles > 0
    assert report.speculative_flag_leaks > 0
    assert FPUVulnerability.SPECULATIVE_FCSR_FLAG_LEAK in report.detected_vulnerabilities
    assert FPUVulnerability.VARIABLE_LATENCY_TIMING_CHANNEL in report.detected_vulnerabilities
    assert FPUVulnerability.SUBNORMAL_SPECULATIVE_LEAK in report.detected_vulnerabilities


def test_fpu_mitigated_isolation():
    oracle = SpeculativeFPUOracle()
    report = oracle.audit(mitigated=True)

    assert report.mitigated
    assert report.fpu_isolation_score == 1.000
    assert report.security_verdict == "VERIFIED_FPU_CONSTANT_TIME_ISOLATION"
    assert report.timing_differential_cycles == 0
    assert report.speculative_flag_leaks == 0
    assert len(report.detected_vulnerabilities) == 0
    assert "class ConstTimeFPUGate" in report.generated_chisel_patch
    assert any("p_fpu_const_time_latency" in s for s in report.generated_sva_assertions)
    assert any("p_fpu_speculative_fflags_quarantine" in s for s in report.generated_sva_assertions)


def test_fpu_serialization(tmp_path: Path):
    oracle = SpeculativeFPUOracle()
    report = oracle.audit(mitigated=True)

    json_str = report.to_json()
    data = json.loads(json_str)
    assert data["fpu_isolation_score"] == 1.0
    assert data["security_verdict"] == "VERIFIED_FPU_CONSTANT_TIME_ISOLATION"

    md_str = report.to_markdown()
    assert "CO-DESIGNED CONST-TIME FPU GATE [ACTIVE]" in md_str
    assert "ConstTimeFPUGate.scala" in md_str

    out_file = tmp_path / "fpu_report.json"
    oracle.export_report(out_file, report)
    assert out_file.is_file()
    assert "VERIFIED_FPU_CONSTANT_TIME_ISOLATION" in out_file.read_text(encoding="utf-8")
