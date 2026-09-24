"""Tests for Microarchitectural Branch Prediction Unit (BPU) & BHI Oracle."""

import json
from pathlib import Path

from spechunter.bpu import (
    BPUVulnerability,
    BranchPredictorType,
    SpeculativeBPUOracle,
)


def test_bpu_enums():
    assert BranchPredictorType.TAGE == "tage"
    assert BranchPredictorType.GSHARE == "gshare"
    assert BPUVulnerability.CROSS_PRIVILEGE_BHI_COLLISION == "CROSS_PRIVILEGE_BHI_COLLISION"
    assert BPUVulnerability.INDIRECT_TARGET_INJECTION == "INDIRECT_TARGET_INJECTION"


def test_bpu_unmitigated_bhi_collision():
    oracle = SpeculativeBPUOracle(target_benchmark="privilege-bypass")
    report = oracle.audit(
        predictor_type=BranchPredictorType.TAGE,
        ghr_length=64,
        btb_entries=512,
        mitigated=False,
    )

    assert not report.mitigated
    assert report.target_benchmark == "privilege-bypass"
    assert report.cross_privilege_collision_detected
    assert report.bhi_vulnerability_detected
    assert report.privilege_isolation_score == 0.125
    assert BPUVulnerability.CROSS_PRIVILEGE_BHI_COLLISION.value in report.detected_vulnerabilities
    assert BPUVulnerability.INDIRECT_TARGET_INJECTION.value in report.detected_vulnerabilities
    assert report.verdict == "VULNERABLE_CROSS_PRIVILEGE_BRANCH_HISTORY_INJECTION"
    assert len(report.bhi_steps) == 3


def test_bpu_mitigated_priv_tagged():
    oracle = SpeculativeBPUOracle(target_benchmark="privilege-bypass")
    report = oracle.audit(
        predictor_type=BranchPredictorType.TAGE,
        ghr_length=64,
        btb_entries=512,
        mitigated=True,
    )

    assert report.mitigated
    assert not report.cross_privilege_collision_detected
    assert not report.bhi_vulnerability_detected
    assert report.privilege_isolation_score == 1.00
    assert len(report.detected_vulnerabilities) == 0
    assert report.verdict == "VERIFIED_BPU_PRIVILEGE_DOMAIN_ISOLATION"


def test_bpu_chisel_patch_and_sva():
    oracle = SpeculativeBPUOracle(target_benchmark="privilege-bypass")
    report = oracle.audit(mitigated=True)

    assert "class PrivTaggedBTBController extends Module" in report.chisel_bpu_patch_code
    assert "val priv_hash = io.priv_mode" in report.chisel_bpu_patch_code

    sva_text = "\n".join(report.generated_sva_assertions)
    assert "property p_bpu_privilege_domain_isolation" in sva_text
    assert "property p_btb_target_privilege_gate" in sva_text
    assert "property p_sret_history_barrier" in sva_text


def test_bpu_serialization(tmp_path: Path):
    oracle = SpeculativeBPUOracle(target_benchmark="privilege-bypass")
    report = oracle.audit(mitigated=True)

    json_str = report.to_json()
    data = json.loads(json_str)
    assert data["target_benchmark"] == "privilege-bypass"
    assert data["privilege_isolation_score"] == 1.0

    md_str = report.to_markdown()
    assert "# SpecHunter BPU & Branch History Injection Audit: privilege-bypass" in md_str
    assert "Executive Branch Prediction Security Summary" in md_str

    out_file = tmp_path / "bpu_report.json"
    oracle.export_report(out_file, report)
    assert out_file.exists()
    assert "VERIFIED_BPU_PRIVILEGE_DOMAIN_ISOLATION" in out_file.read_text(encoding="utf-8")
