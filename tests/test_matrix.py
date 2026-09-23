"""Tests for Grand Unified Microarchitectural Security Matrix Oracle."""

import json
from pathlib import Path

from spechunter.matrix import UnifiedSecurityMatrixOracle


def test_matrix_generation():
    oracle = UnifiedSecurityMatrixOracle()
    report = oracle.generate_matrix()

    assert report.total_subsystems_audited == 11
    assert report.vulnerabilities_neutralized == 11
    assert report.average_mitigated_isolation == 100.0
    assert report.average_baseline_isolation < 30.0
    assert report.aggregate_ipc_overhead_pct < 0.10
    assert report.naive_fence_ipc_overhead_pct == 52.60
    assert report.efficiency_multiplier > 500.0
    assert report.certification_id == "HSA-CERT-2026-CHIA-001"
    assert report.certification_verdict == "SILICON_SECURITY_CO_DESIGN_CERTIFIED"

    subsystem_names = [s.subsystem for s in report.subsystems]
    assert "Branch Prediction Unit (BPU)" in subsystem_names
    assert "Store-to-Load Forwarding (STLF)" in subsystem_names
    assert "Line Fill Buffers & MSHRs (MDS)" in subsystem_names
    assert "Page Table Walker (MMU / PTW)" in subsystem_names
    assert "ROB Rename & Shadow Recovery" in subsystem_names
    assert "TileLink Multi-Core Coherence" in subsystem_names
    assert "Load-Store Unit D-Cache Interlock" in subsystem_names
    assert "Physical Memory Protection (PMP)" in subsystem_names
    assert "Return Address Stack (RAS)" in subsystem_names
    assert "Floating-Point Unit (FPU)" in subsystem_names
    assert "Vector Execution Unit (RVV)" in subsystem_names


def test_matrix_serialization(tmp_path: Path):
    oracle = UnifiedSecurityMatrixOracle()
    report = oracle.generate_matrix()

    json_str = report.to_json()
    data = json.loads(json_str)
    assert data["certification_id"] == "HSA-CERT-2026-CHIA-001"
    assert data["total_subsystems_audited"] == 11
    assert len(data["subsystems"]) == 11

    md_str = report.to_markdown()
    assert "Grand Unified Microarchitectural Co-Design Verification Matrix" in md_str
    assert "HARDWARE SECURITY CERTIFICATE" in md_str
    assert "SILICON_SECURITY_CO_DESIGN_CERTIFIED" in md_str

    out_file = tmp_path / "matrix_report.json"
    oracle.export_report(out_file, report)
    assert out_file.exists()
    assert "SILICON_SECURITY_CO_DESIGN_CERTIFIED" in out_file.read_text(encoding="utf-8")
