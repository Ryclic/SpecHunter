"""Unit tests for hardware performance overhead and tradeoff profiler."""

import json

import pytest

from spechunter.profiler import HardwareProfiler, MitigationProfile, ProfilingReport


def test_profiler_catalog():
    profiler = HardwareProfiler()
    prof = profiler.get_profile("gate-faulting-loads")
    assert isinstance(prof, MitigationProfile)
    assert prof.patch_id == "gate-faulting-loads"
    assert prof.ipc_overhead_pct < 0.1
    assert prof.naive_ipc_overhead_pct > 30.0
    assert prof.pareto_efficiency_ratio > 400.0


def test_profiler_unknown_patch_raises():
    profiler = HardwareProfiler()
    with pytest.raises(KeyError, match="Unknown patch"):
        profiler.get_profile("non-existent-patch")


def test_profiler_profile_all():
    profiler = HardwareProfiler()
    report = profiler.profile_all()
    assert isinstance(report, ProfilingReport)
    assert len(report.profiles) >= 3
    assert report.average_ipc_overhead_pct < 1.0  # Under 1% average overhead
    assert report.average_naive_overhead_pct > 40.0  # Naive baseline is severe
    assert report.overall_speedup_vs_naive > 100.0


def test_profiler_serialization():
    profiler = HardwareProfiler()
    report = profiler.profile_all()
    data = report.to_dict()
    assert "average_ipc_overhead_pct" in data
    assert "overall_speedup_vs_naive" in data

    json_str = report.to_json()
    parsed = json.loads(json_str)
    assert len(parsed["profiles"]) == len(report.profiles)


def test_profiler_markdown_generation():
    profiler = HardwareProfiler()
    report = profiler.profile_all()
    md = report.to_markdown()
    assert "# SpecHunter Hardware Mitigation Performance Overhead Analysis" in md
    assert "gate-faulting-loads" in md
    assert "issue-715-translation-gate" in md
    assert "Geometric Mean Efficiency Gain" in md
