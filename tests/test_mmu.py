"""Tests for Microarchitectural Virtual Memory & Speculative PTW Side-Channel Oracle."""

import json
from pathlib import Path

from spechunter.mmu import (
    MMUAccessType,
    MMUVulnerability,
    PTWState,
    SpeculativeMMUOracle,
)


def test_mmu_enums():
    assert PTWState.IDLE == "s_idle"
    assert PTWState.L2_REQ == "s_req_l2_ptw"
    assert MMUAccessType.SPECULATIVE_LOAD == "speculative_load"
    assert MMUVulnerability.SPECULATIVE_PTW_CACHE_POLLUTION == "SPECULATIVE_PTW_CACHE_POLLUTION"
    assert MMUVulnerability.PREMATURE_TAG_LOOKUP_RACE == "PREMATURE_TAG_LOOKUP_RACE"


def test_mmu_unmitigated_vulnerabilities():
    oracle = SpeculativeMMUOracle(target_benchmark="issue-715")
    report = oracle.audit(
        virtual_addr=0x7FFF_8000_1000,
        access_type=MMUAccessType.SPECULATIVE_LOAD,
        mitigated=False,
    )

    assert not report.mitigated
    assert report.target_benchmark == "issue-715"
    assert report.speculative_ptw_dispatched
    assert report.cache_lines_allocated_by_ptw == 3
    assert report.speculative_ad_bit_updated
    assert not report.translation_order_invariant_held
    assert report.speculative_ptw_side_channel_detected
    assert MMUVulnerability.PREMATURE_TAG_LOOKUP_RACE.value in report.detected_vulnerabilities
    assert MMUVulnerability.SPECULATIVE_PTW_CACHE_POLLUTION.value in report.detected_vulnerabilities
    assert report.verdict == "VULNERABLE_SPECULATIVE_PTW_SIDE_CHANNEL"
    assert len(report.walk_steps) == 3
    assert all(s.bus_req_dispatched for s in report.walk_steps)


def test_mmu_mitigated_gated_ptw():
    oracle = SpeculativeMMUOracle(target_benchmark="issue-715")
    report = oracle.audit(
        virtual_addr=0x7FFF_8000_1000,
        access_type=MMUAccessType.SPECULATIVE_LOAD,
        mitigated=True,
    )

    assert report.mitigated
    assert not report.speculative_ptw_dispatched
    assert report.cache_lines_allocated_by_ptw == 0
    assert not report.speculative_ad_bit_updated
    assert report.translation_order_invariant_held
    assert not report.speculative_ptw_side_channel_detected
    assert len(report.detected_vulnerabilities) == 0
    assert report.verdict == "VERIFIED_ISOLATED_GATED_TRANSLATION"
    assert all(not s.bus_req_dispatched for s in report.walk_steps)
    assert all(not s.cache_line_allocated for s in report.walk_steps)


def test_mmu_chisel_patch_and_sva():
    oracle = SpeculativeMMUOracle(target_benchmark="issue-715")
    report = oracle.audit(mitigated=True)

    assert "class GatedPTWController extends Module" in report.chisel_ptw_gate_code
    assert "io.dcache_lookup_gate" in report.chisel_ptw_gate_code

    sva_text = "\n".join(report.generated_sva_assertions)
    assert "property p_speculative_ptw_mem_gate" in sva_text
    assert "property p_speculative_ad_bit_gate" in sva_text
    assert "property p_issue_715_strict_translation_order" in sva_text


def test_mmu_serialization(tmp_path: Path):
    oracle = SpeculativeMMUOracle(target_benchmark="issue-715")
    report = oracle.audit(mitigated=True)

    json_str = report.to_json()
    data = json.loads(json_str)
    assert data["target_benchmark"] == "issue-715"
    assert data["cache_lines_allocated_by_ptw"] == 0

    md_str = report.to_markdown()
    assert "# SpecHunter Speculative MMU & Page Table Walker Audit: issue-715" in md_str
    assert "Executive Translation Security Summary" in md_str

    out_file = tmp_path / "mmu_report.json"
    oracle.export_report(out_file, report)
    assert out_file.exists()
    assert "VERIFIED_ISOLATED_GATED_TRANSLATION" in out_file.read_text(encoding="utf-8")
