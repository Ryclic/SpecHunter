"""Tests for Microarchitectural State-Transition Graph (MSTG) Coverage & Invariant Fuzzer."""

import json
from pathlib import Path

from spechunter.fuzzer import MicroarchitecturalFuzzer


def test_fuzzer_unmitigated_violations():
    fuzzer = MicroarchitecturalFuzzer(target_benchmark="transient-cache", seed=42)
    report = fuzzer.run_campaign(iterations=100, mitigated=False)

    assert report.target_benchmark == "transient-cache"
    assert report.iterations == 100
    assert not report.mitigated
    assert report.total_states_discovered > 5
    assert report.total_edges_covered > 10
    assert report.mstg_coverage_pct > 0.0
    assert len(report.violations) > 0

    violation_types = [v.violation_type for v in report.violations]
    assert "UNRESOLVED_SPECULATIVE_LOAD_DISPATCH" in violation_types


def test_fuzzer_mitigated_zero_violations():
    fuzzer = MicroarchitecturalFuzzer(target_benchmark="transient-cache", seed=42)
    report = fuzzer.run_campaign(iterations=100, mitigated=True)

    assert report.mitigated
    assert len(report.violations) == 0
    assert report.total_states_discovered > 5
    assert report.total_edges_covered > 10


def test_fuzzer_report_serialization(tmp_path: Path):
    fuzzer = MicroarchitecturalFuzzer(target_benchmark="privilege-bypass", seed=123)
    report = fuzzer.run_campaign(iterations=50, mitigated=False)

    json_str = report.to_json()
    data = json.loads(json_str)
    assert data["target_benchmark"] == "privilege-bypass"
    assert "mstg_coverage_pct" in data
    assert "violations" in data

    md_str = report.to_markdown()
    assert "# SpecHunter Microarchitectural Fuzzing & MSTG Coverage Report" in md_str
    assert "Microarchitectural State Distribution Histogram" in md_str

    out_file = tmp_path / "fuzz_report.json"
    fuzzer.export_report(out_file, report)
    assert out_file.exists()
    assert "privilege-bypass" in out_file.read_text(encoding="utf-8")
