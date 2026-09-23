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


def test_cli_advisory_markdown(capsys, monkeypatch):
    monkeypatch.setattr(sys, "argv", ["spechunter", "advisory"])
    assert main() == 0
    captured = capsys.readouterr().out
    assert "Hardware Security Advisory: HSA-2026-0001" in captured
    assert "CWE-1037" in captured
    assert "exu/lsu/lsu.scala" in captured


def test_cli_advisory_json(capsys, monkeypatch):
    monkeypatch.setattr(sys, "argv", ["spechunter", "advisory", "--json"])
    assert main() == 0
    captured = capsys.readouterr().out
    data = json.loads(captured)
    assert data["advisory_id"] == "HSA-2026-0001"
    assert data["cvss_score"] == 7.4


def test_cli_advisory_html(capsys, monkeypatch, tmp_path):
    out_html = tmp_path / "advisory.html"
    monkeypatch.setattr(sys, "argv", ["spechunter", "advisory", "--html", str(out_html)])
    assert main() == 0
    assert out_html.is_file()
    html_content = out_html.read_text(encoding="utf-8")
    assert "<!DOCTYPE html>" in html_content
    assert "HSA-2026-0001" in html_content


def test_cli_poc_text(capsys, monkeypatch):
    monkeypatch.setattr(sys, "argv", ["spechunter", "poc", "--name", "issue-715"])
    assert main() == 0
    captured = capsys.readouterr().out
    assert "SpecHunter Proof-of-Concept: issue-715" in captured
    assert "0x80028e08" in captured


def test_cli_poc_json(capsys, monkeypatch):
    monkeypatch.setattr(sys, "argv", ["spechunter", "poc", "--json"])
    assert main() == 0
    captured = capsys.readouterr().out
    data = json.loads(captured)
    assert "transient-cache" in data
    assert "issue-715" in data


def test_cli_poc_export(capsys, monkeypatch, tmp_path):
    out_dir = tmp_path / "poc_export"
    monkeypatch.setattr(sys, "argv", ["spechunter", "poc", "--export", str(out_dir)])
    assert main() == 0
    captured = capsys.readouterr().out
    assert "Exported 6 PoC artifact files" in captured
    assert (out_dir / "transient-cache.s").is_file()
    assert (out_dir / "issue-715.s").is_file()


def test_cli_ablation_terminal(capsys, monkeypatch):
    monkeypatch.setattr(sys, "argv", ["spechunter", "ablation"])
    assert main() == 0
    captured = capsys.readouterr().out
    assert "SpecHunter Ablation Study" in captured
    assert "SpecHunter Guided Invariant Search" in captured
    assert "Unguided Random Fuzzing" in captured


def test_cli_ablation_json(capsys, monkeypatch):
    monkeypatch.setattr(sys, "argv", ["spechunter", "ablation", "--json"])
    assert main() == 0
    captured = capsys.readouterr().out
    data = json.loads(captured)
    assert data["benchmark_name"] == "transient-cache"
    assert len(data["strategies"]) == 4


def test_cli_ablation_markdown(capsys, monkeypatch, tmp_path):
    out_file = tmp_path / "ablation.md"
    monkeypatch.setattr(
        sys, "argv", ["spechunter", "ablation", "--markdown", "--output", str(out_file)]
    )
    assert main() == 0
    captured = capsys.readouterr().out
    assert "Ablation study saved to:" in captured
    content = out_file.read_text(encoding="utf-8")
    assert "# SpecHunter Ablation Study" in content
    assert "| Strategy | Discovery Rate (%) |" in content


def test_cli_harness_terminal(capsys, monkeypatch):
    monkeypatch.setattr(sys, "argv", ["spechunter", "harness"])
    assert main() == 0
    captured = capsys.readouterr().out
    assert "Berkeley BOOM Upstream Security Test Harness" in captured
    assert "transient-cache" in captured
    assert "VULNERABILITY_CONFIRMED" in captured


def test_cli_harness_verify_mitigations(capsys, monkeypatch):
    monkeypatch.setattr(sys, "argv", ["spechunter", "harness", "--verify-mitigations"])
    assert main() == 0
    captured = capsys.readouterr().out
    assert "MITIGATED" in captured
    assert "Confirmed Vulnerabilities: 0" in captured


def test_cli_harness_junit_xml(capsys, monkeypatch, tmp_path):
    junit_file = tmp_path / "ci_test.xml"
    monkeypatch.setattr(sys, "argv", ["spechunter", "harness", "--junit-xml", str(junit_file)])
    assert main() == 0
    captured = capsys.readouterr().out
    assert "JUnit XML exported to:" in captured
    assert junit_file.is_file()
    content = junit_file.read_text(encoding="utf-8")
    assert '<testsuite name="SpecHunter.BOOM.SecuritySuite"' in content


def test_cli_harness_json(capsys, monkeypatch):
    monkeypatch.setattr(sys, "argv", ["spechunter", "harness", "--json"])
    assert main() == 0
    captured = capsys.readouterr().out
    data = json.loads(captured)
    assert data["total_tests"] == 3
    assert data["vulnerabilities_confirmed"] == 3


def test_cli_synthesize(capsys, monkeypatch):
    monkeypatch.setattr(sys, "argv", ["spechunter", "synthesize", "--threat", "spectre_bcb"])
    assert main() == 0
    captured = capsys.readouterr().out
    assert "SpecHunter Microarchitectural Program Synthesizer" in captured
    assert "spectre_bcb" in captured


def test_cli_synthesize_assembly(capsys, monkeypatch):
    monkeypatch.setattr(
        sys, "argv", ["spechunter", "synthesize", "--threat", "boom_issue_715", "--assembly"]
    )
    assert main() == 0
    captured = capsys.readouterr().out
    assert "spechunter_issue_715" in captured
    assert ".section .text" in captured


def test_cli_synthesize_json(capsys, monkeypatch):
    monkeypatch.setattr(
        sys, "argv", ["spechunter", "synthesize", "--threat", "meltdown_rdcl", "--json"]
    )
    assert main() == 0
    captured = capsys.readouterr().out
    data = json.loads(captured)
    assert data["threat_model"] == "meltdown_rdcl"
    assert "enter_user" in data["program_ops"]


def test_cli_search_terminal(capsys, monkeypatch):
    monkeypatch.setattr(sys, "argv", ["spechunter", "search", "--benchmark", "transient-cache"])
    assert main() == 0
    captured = capsys.readouterr().out
    assert "SpecHunter Feedback-Driven Microarchitectural Search" in captured
    assert "VIOLATION_CONFIRMED" in captured


def test_cli_search_json(capsys, monkeypatch):
    monkeypatch.setattr(
        sys, "argv", ["spechunter", "search", "--benchmark", "transient-cache", "--json"]
    )
    assert main() == 0
    captured = capsys.readouterr().out
    data = json.loads(captured)
    assert data["benchmark"] == "transient-cache"
    assert data["success"] is True
    assert "train" in data["minimized_ops"]


def test_cli_minimize_terminal(capsys, monkeypatch):
    monkeypatch.setattr(sys, "argv", ["spechunter", "minimize", "--benchmark", "transient-cache"])
    assert main() == 0
    captured = capsys.readouterr().out
    assert "SpecHunter Hierarchical Delta Debugger" in captured
    assert "Reduction Ratio:" in captured


def test_cli_minimize_json(capsys, monkeypatch):
    monkeypatch.setattr(
        sys, "argv", ["spechunter", "minimize", "--benchmark", "transient-cache", "--json"]
    )
    assert main() == 0
    captured = capsys.readouterr().out
    data = json.loads(captured)
    assert data["original_length"] == 9
    assert data["minimized_length"] == 5
    assert data["reduction_percentage"] > 40.0


def test_cli_run_agent_strategy(capsys, monkeypatch, tmp_path):
    out_file = tmp_path / "agent_run.json"
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "spechunter",
            "run",
            "--strategy",
            "agent",
            "--benchmark",
            "transient-cache",
            "--output",
            str(out_file),
        ],
    )
    assert main() == 0
    captured = capsys.readouterr().out
    data = json.loads(captured)
    assert "llm" in data
    assert data["llm"]["discovered"] == 1
    assert data["llm"]["false_positives"] == 0
    assert data["llm"]["inconclusive_cases"] == 0
    assert data["llm"]["repairs_attacker_exhausted"] == 1
    assert out_file.is_file()
