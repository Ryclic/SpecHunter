import json
import sys

import pytest

from spechunter.cli import main


def test_cli_waveform(capsys, monkeypatch):
    monkeypatch.setattr(sys, "argv", ["spechunter", "waveform"])
    assert main() == 0
    captured = capsys.readouterr().out
    assert "Berkeley BOOM Issue #715 Cycle-Accurate Hazard Timing" in captured
    assert "exu/core.scala" in captured
    assert "0x59F" in captured


def test_cli_audit_transient_cache(capsys, monkeypatch):
    class FakeBlock:
        def __init__(self, **kwargs):
            self.benchmark_id = kwargs.get("benchmark_id")

        def execute(self, local=True):
            return {
                "strategy": "guided",
                "metrics": {
                    "discovered": 1,
                    "positive_cases": 1,
                    "false_positives": 0,
                    "executions": 68,
                    "inconclusive_cases": 0,
                },
            }

    monkeypatch.setattr("spechunter.chia_nodes.SpecHunterSecurityAuditBlock", FakeBlock)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "spechunter",
            "audit",
            "--backend",
            "model",
            "--benchmark",
            "transient-cache",
            "--iterations",
            "4",
        ],
    )
    assert main() == 0
    captured = capsys.readouterr().out
    assert "SpecHunter CHIA Security Audit Block" in captured
    assert "Spectre-v1 Bounds Check Bypass" in captured
    assert "Vulnerabilities Discovered: 1" in captured
    assert "VIOLATION_CONFIRMED" in captured


def test_cli_audit_secure_control(capsys, monkeypatch):
    class FakeBlock:
        def __init__(self, **kwargs):
            self.benchmark_id = kwargs.get("benchmark_id")

        def execute(self, local=True):
            return {
                "strategy": "guided",
                "metrics": {
                    "discovered": 0,
                    "positive_cases": 0,
                    "false_positives": 0,
                    "executions": 32,
                    "inconclusive_cases": 0,
                },
            }

    monkeypatch.setattr("spechunter.chia_nodes.SpecHunterSecurityAuditBlock", FakeBlock)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "spechunter",
            "audit",
            "--backend",
            "model",
            "--benchmark",
            "secure-control",
            "--iterations",
            "4",
        ],
    )
    assert main() == 0
    captured = capsys.readouterr().out
    assert "SpecHunter CHIA Security Audit Block" in captured
    assert "Isolated Speculative Baseline" in captured
    assert "Vulnerabilities Discovered: 0" in captured
    assert "CLEAN" in captured


@pytest.mark.chia
def test_cli_audit_live_chia_ray(capsys, monkeypatch):
    pytest.importorskip("chia")
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "spechunter",
            "audit",
            "--backend",
            "model",
            "--benchmark",
            "transient-cache",
            "--iterations",
            "2",
        ],
    )
    assert main() == 0
    captured = capsys.readouterr().out
    assert "SpecHunter CHIA Security Audit Block" in captured
    assert "VIOLATION_CONFIRMED" in captured


def test_cli_verify_all(capsys, monkeypatch):
    monkeypatch.setattr(sys, "argv", ["spechunter", "verify"])
    assert main() == 0
    captured = capsys.readouterr().out
    assert "ALL ARTIFACTS AND SEALS 100% VERIFIED" in captured
    assert "Historical Issue #715 Attachment: VERIFIED" in captured
    assert "Submission Dossier (SUBMISSION.md): VERIFIED" in captured
    assert "Interactive Demo (docs/demo.html, zero scripts, taxonomy): VERIFIED" in captured
    assert "Paper Sources (LaTeX & Typst): VERIFIED" in captured
    assert "Packaging & Profiling Tools: VERIFIED" in captured


def test_cli_taxonomy(capsys, monkeypatch):
    monkeypatch.setattr(sys, "argv", ["spechunter", "taxonomy"])
    assert main() == 0
    captured = capsys.readouterr().out
    assert "Berkeley BOOM Microarchitectural Spectre Taxonomy" in captured
    assert "spectre-v1-bcb" in captured
    assert "spectre-v2-bti" in captured
    assert "spectre-v4-ssb" in captured
    assert "meltdown-rdcl" in captured
    assert "Total Formal Taxonomy Variants: 6" in captured


def test_cli_taxonomy_json(capsys, monkeypatch):
    monkeypatch.setattr(sys, "argv", ["spechunter", "taxonomy", "--json"])
    assert main() == 0
    captured = capsys.readouterr().out
    data = json.loads(captured)
    assert isinstance(data, list)
    assert len(data) == 6
    variants = [d["variant"] for d in data]
    assert "spectre-v1-bcb" in variants
    assert "spectre-v4-ssb" in variants
    assert "meltdown-rdcl" in variants


@pytest.mark.chia
def test_cli_audit_json(capsys, monkeypatch):
    pytest.importorskip("chia")
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "spechunter",
            "audit",
            "--benchmark",
            "secure-control",
            "--iterations",
            "2",
            "--json",
        ],
    )
    assert main() == 0
    captured = capsys.readouterr().out
    json_start = captured.find("{")
    assert json_start != -1
    data = json.loads(captured[json_start:])
    assert data["target_benchmark"] == "secure-control"
    assert data["verdict"] == "CLEAN"
    assert data["metrics"]["discovered"] == 0


def test_cli_benchmark(capsys, monkeypatch, tmp_path):
    out_file = tmp_path / "bench.json"
    monkeypatch.setattr(
        sys,
        "argv",
        ["spechunter", "benchmark", "--trials", "2", "--output", str(out_file)],
    )
    assert main() == 0
    captured = capsys.readouterr().out
    assert "SpecHunter Microarchitectural Security Performance Benchmark" in captured
    assert "Guided" in captured
    assert "Random" in captured
    assert out_file.is_file()
    data = json.loads(out_file.read_text(encoding="utf-8"))
    assert "search_strategies" in data


def test_cli_benchmark_json(capsys, monkeypatch, tmp_path):
    out_file = tmp_path / "bench.json"
    monkeypatch.setattr(
        sys,
        "argv",
        ["spechunter", "benchmark", "--trials", "2", "--output", str(out_file), "--json"],
    )
    assert main() == 0
    captured = capsys.readouterr().out
    json_start = captured.find("{")
    assert json_start != -1
    data = json.loads(captured[json_start:])
    assert "search_strategies" in data
    assert "guided" in data["search_strategies"]
    assert "random" in data["search_strategies"]
    assert data["search_strategies"]["guided"]["discovery_rate_pct"] == 100.0


def test_cli_benchmark_svg(capsys, monkeypatch, tmp_path):
    out_file = tmp_path / "bench.json"
    out_svg = tmp_path / "bench.svg"
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "spechunter",
            "benchmark",
            "--trials",
            "2",
            "--output",
            str(out_file),
            "--svg",
            str(out_svg),
        ],
    )
    assert main() == 0
    assert out_svg.is_file()
    svg_text = out_svg.read_text(encoding="utf-8")
    assert "<svg" in svg_text
    assert "SpecHunter Microarchitectural Search Performance" in svg_text
    assert "Guided Search" in svg_text


def test_cli_audit_suite_fast(capsys, monkeypatch):
    class FakeSuiteBlock:
        @classmethod
        def audit_suite(cls, **kwargs):
            return {
                "transient-cache": {"metrics": {"discovered": 1, "executions": 10}},
                "privilege-bypass": {"metrics": {"discovered": 1, "executions": 8}},
                "secure-control": {"metrics": {"discovered": 0, "executions": 4}},
            }

        @classmethod
        def summarize_suite(cls, suite_results):
            return {
                "benchmarks_audited": 3,
                "vulnerabilities_discovered": 2,
                "clean_benchmarks": ["secure-control"],
                "vulnerable_benchmarks": ["transient-cache", "privilege-bypass"],
                "all_clean": False,
            }

    monkeypatch.setattr("spechunter.chia_nodes.SpecHunterSecurityAuditBlock", FakeSuiteBlock)
    monkeypatch.setattr(
        sys,
        "argv",
        ["spechunter", "audit", "--suite", "--iterations", "2"],
    )
    assert main() == 0
    captured = capsys.readouterr().out
    assert "SpecHunter CHIA Multi-Benchmark Security Audit Suite" in captured
    assert "transient-cache" in captured
    assert "privilege-bypass" in captured
    assert "secure-control" in captured
    assert "VIOLATION_CONFIRMED" in captured
    assert "CLEAN" in captured
    assert "Suite Summary: 3 benchmarks audited | 2 vulnerabilities discovered" in captured


def test_cli_audit_suite_fast_json(capsys, monkeypatch):
    class FakeSuiteBlock:
        @classmethod
        def audit_suite(cls, **kwargs):
            return {
                "transient-cache": {"metrics": {"discovered": 1, "executions": 10}},
                "secure-control": {"metrics": {"discovered": 0, "executions": 4}},
            }

        @classmethod
        def summarize_suite(cls, suite_results):
            return {
                "benchmarks_audited": 2,
                "vulnerabilities_discovered": 1,
                "clean_benchmarks": ["secure-control"],
                "vulnerable_benchmarks": ["transient-cache"],
                "all_clean": False,
            }

    monkeypatch.setattr("spechunter.chia_nodes.SpecHunterSecurityAuditBlock", FakeSuiteBlock)
    monkeypatch.setattr(
        sys,
        "argv",
        ["spechunter", "audit", "--suite", "--iterations", "2", "--json"],
    )
    assert main() == 0
    captured = capsys.readouterr().out
    json_start = captured.find("{")
    assert json_start != -1
    data = json.loads(captured[json_start:])
    assert "suite" in data
    assert "summary" in data
    assert data["summary"]["benchmarks_audited"] == 2
    assert data["summary"]["vulnerabilities_discovered"] == 1
    assert data["suite"]["transient-cache"]["verdict"] == "VIOLATION_CONFIRMED"
    assert data["suite"]["secure-control"]["verdict"] == "CLEAN"


@pytest.mark.chia
def test_cli_audit_suite_live(capsys, monkeypatch):
    pytest.importorskip("chia")
    monkeypatch.setattr(
        sys,
        "argv",
        ["spechunter", "audit", "--suite", "--iterations", "2"],
    )
    assert main() == 0
    captured = capsys.readouterr().out
    assert "SpecHunter CHIA Multi-Benchmark Security Audit Suite" in captured
    assert "transient-cache" in captured
    assert "privilege-bypass" in captured
    assert "secure-control" in captured
