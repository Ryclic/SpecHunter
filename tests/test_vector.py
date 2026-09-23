"""Tests for Speculative RISC-V Vector (RVV) Oracle."""

import json
from pathlib import Path

from spechunter.vector import (
    SpeculativeVectorOracle,
    VectorVulnerability,
)


def test_vector_baseline_vulnerability():
    oracle = SpeculativeVectorOracle(vlen_bits=256)
    report = oracle.audit(mitigated=False)

    assert not report.mitigated
    assert report.vector_isolation_score == 0.100
    assert report.security_verdict == "VULNERABLE_SPECULATIVE_VECTOR_REGISTER_LEAK"
    assert report.transient_leak_bits == 512
    assert report.speculative_gather_footprint_lines == 8
    assert VectorVulnerability.SPECULATIVE_VECTOR_REGISTER_LEAK in report.detected_vulnerabilities
    assert VectorVulnerability.TRANSIENT_VECTOR_GATHER_LEAK in report.detected_vulnerabilities
    assert VectorVulnerability.VECTOR_CONFIG_DESYNC in report.detected_vulnerabilities


def test_vector_mitigated_isolation():
    oracle = SpeculativeVectorOracle(vlen_bits=256)
    report = oracle.audit(mitigated=True)

    assert report.mitigated
    assert report.vector_isolation_score == 1.000
    assert report.security_verdict == "VERIFIED_VECTOR_SPECULATIVE_ISOLATION"
    assert report.transient_leak_bits == 0
    assert report.speculative_gather_footprint_lines == 0
    assert len(report.detected_vulnerabilities) == 0
    assert "class GatedVectorPipeline" in report.generated_chisel_patch
    assert any("p_vector_gather_mem_gate" in s for s in report.generated_sva_assertions)
    assert any("p_vector_reg_checkpoint_restore" in s for s in report.generated_sva_assertions)
    assert any("p_vector_context_zeroize" in s for s in report.generated_sva_assertions)


def test_vector_serialization(tmp_path: Path):
    oracle = SpeculativeVectorOracle(vlen_bits=512)
    report = oracle.audit(mitigated=True)

    json_str = report.to_json()
    data = json.loads(json_str)
    assert data["vlen_bits"] == 512
    assert data["vector_isolation_score"] == 1.0
    assert data["security_verdict"] == "VERIFIED_VECTOR_SPECULATIVE_ISOLATION"

    md_str = report.to_markdown()
    assert "CO-DESIGNED GATED VECTOR PIPELINE [ACTIVE]" in md_str
    assert "GatedVectorPipeline.scala" in md_str

    out_file = tmp_path / "vector_report.json"
    oracle.export_report(out_file, report)
    assert out_file.is_file()
    assert "VERIFIED_VECTOR_SPECULATIVE_ISOLATION" in out_file.read_text(encoding="utf-8")
