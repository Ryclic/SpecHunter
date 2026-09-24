"""Tests for Formal SMT-LIB2 Bounded Model Checker & Relational Prover."""

import json
from pathlib import Path

from spechunter.formal import (
    FormalVerdict,
    FormalVerificationEngine,
)


def test_formal_unmitigated_counterexample():
    engine = FormalVerificationEngine(unroll_depth=8)
    report = engine.verify_benchmark("transient-cache", mitigated=False)

    assert report.benchmark_id == "transient-cache"
    assert not report.mitigated
    assert report.verdict == FormalVerdict.COUNTEREXAMPLE_FOUND
    assert report.counterexample_cycle is not None
    assert report.secret_a_val is not None
    assert report.secret_b_val is not None
    assert report.secret_a_val != report.secret_b_val
    assert report.total_clauses > 0
    assert report.total_variables > 0


def test_formal_mitigated_proven_secure():
    engine = FormalVerificationEngine(unroll_depth=8)
    report = engine.verify_benchmark("transient-cache", mitigated=True)

    assert report.mitigated
    assert report.verdict == FormalVerdict.PROVEN_SECURE
    assert report.counterexample_cycle is None
    for step in report.symbolic_steps:
        assert not step.observable_leakage


def test_formal_smt2_export(tmp_path: Path):
    engine = FormalVerificationEngine(unroll_depth=6)
    report = engine.verify_benchmark("privilege-bypass", mitigated=False)

    assert "(set-logic QF_BV)" in report.smt2_source
    assert "(check-sat)" in report.smt2_source
    assert "(declare-const secret_A" in report.smt2_source

    out_file = tmp_path / "formula.smt2"
    engine.export_smt2(out_file, report.smt2_source)
    assert out_file.exists()
    content = out_file.read_text(encoding="utf-8")
    assert "(set-logic QF_BV)" in content


def test_formal_report_serialization():
    engine = FormalVerificationEngine(unroll_depth=8)
    report = engine.verify_benchmark("issue-715", mitigated=True)

    json_str = report.to_json()
    data = json.loads(json_str)
    assert data["benchmark_id"] == "issue-715"
    assert data["verdict"] == "PROVEN_SECURE"

    md_str = report.to_markdown()
    assert "# SpecHunter Formal SMT-LIB2 Verification Report: issue-715" in md_str
    assert "MATHEMATICALLY PROVEN SECURE" in md_str
