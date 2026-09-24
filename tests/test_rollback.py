"""Tests for Microarchitectural Speculative Rollback & Shadow State Recovery Oracle."""

import json
from pathlib import Path

from spechunter.rollback import (
    ResidualVulnerability,
    RollbackOracle,
    RollbackSubsystem,
)


def test_rollback_subsystems_and_enums():
    assert RollbackSubsystem.RAT_RENAME_TABLE == "rat_rename_table"
    assert RollbackSubsystem.PRF_DATA_STORAGE == "prf_data_storage"
    assert ResidualVulnerability.PRF_RESIDUAL_SECRET_LEAK == "PRF_RESIDUAL_SECRET_LEAK"


def test_rollback_unmitigated_vulnerabilities():
    oracle = RollbackOracle(target_benchmark="transient-cache", num_registers=16)
    report = oracle.audit(mitigated=False)

    assert not report.mitigated
    assert report.target_benchmark == "transient-cache"
    assert not report.atomic_rat_restoration_proven
    assert not report.prf_residuals_zeroized
    assert not report.uncommitted_stores_purged
    assert report.rollback_integrity_score < 0.90
    expected_vuln = ResidualVulnerability.PRF_RESIDUAL_SECRET_LEAK.value
    assert expected_vuln in report.residual_vulnerabilities_detected
    assert report.verdict == "VULNERABLE_INCOMPLETE_ROLLBACK_SHADOW_RETENTION"

    # Verify secret register retention in shadow state
    tainted_regs = [s for s in report.shadow_registers if s.is_tainted]
    assert len(tainted_regs) >= 2
    assert any("0xDEADBEEF" in s.residual_data_hex for s in tainted_regs)


def test_rollback_mitigated_zero_residual():
    oracle = RollbackOracle(target_benchmark="transient-cache", num_registers=16)
    report = oracle.audit(mitigated=True)

    assert report.mitigated
    assert report.atomic_rat_restoration_proven
    assert report.prf_residuals_zeroized
    assert report.uncommitted_stores_purged
    assert report.rollback_integrity_score == 1.000
    assert len(report.residual_vulnerabilities_detected) == 0
    assert report.verdict == "VERIFIED_CLEAN_ATOMIC_ROLLBACK"

    # All shadow registers must be zeroized and non-tainted
    assert all(not s.is_tainted for s in report.shadow_registers)
    assert all(s.is_restored for s in report.shadow_registers)
    assert all(s.residual_data_hex == "0x0000000000000000" for s in report.shadow_registers)


def test_rollback_sva_assertions():
    oracle = RollbackOracle(target_benchmark="privilege-bypass")
    report = oracle.audit(mitigated=True)

    assert len(report.generated_sva_assertions) > 10
    sva_text = "\n".join(report.generated_sva_assertions)
    assert "property p_atomic_rat_rollback" in sva_text
    assert "property p_dead_prf_zeroization" in sva_text
    assert "property p_stq_speculative_purge" in sva_text


def test_rollback_serialization(tmp_path: Path):
    oracle = RollbackOracle(target_benchmark="issue-715")
    report = oracle.audit(mitigated=True)

    json_str = report.to_json()
    data = json.loads(json_str)
    assert data["target_benchmark"] == "issue-715"
    assert data["rollback_integrity_score"] == 1.0

    md_str = report.to_markdown()
    assert "# SpecHunter Speculative Rollback & Shadow State Audit: issue-715" in md_str
    assert "Executive Rollback Verification Summary" in md_str

    out_file = tmp_path / "rollback_report.json"
    oracle.export_report(out_file, report)
    assert out_file.exists()
    assert "VERIFIED_CLEAN_ATOMIC_ROLLBACK" in out_file.read_text(encoding="utf-8")
