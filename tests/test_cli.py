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


def test_cli_patch_list(capsys, monkeypatch):
    monkeypatch.setattr(sys, "argv", ["spechunter", "patch", "--list"])
    assert main() == 0
    captured = capsys.readouterr().out
    assert "SpecHunter Chisel RTL Hardware Patch Catalog" in captured
    assert "gate-faulting-loads" in captured
    assert "bpu-barrier-flush" in captured


def test_cli_patch_target(capsys, monkeypatch):
    monkeypatch.setattr(sys, "argv", ["spechunter", "patch", "--target", "gate-faulting-loads"])
    assert main() == 0
    captured = capsys.readouterr().out
    assert "SpecHunter Berkeley BOOM Chisel RTL Hardware Patch" in captured
    assert "CWE-1272" in captured
    assert "YES (VERIFIED)" in captured


def test_cli_patch_diff(capsys, monkeypatch):
    monkeypatch.setattr(
        sys, "argv", ["spechunter", "patch", "--target", "gate-faulting-loads", "--diff"]
    )
    assert main() == 0
    captured = capsys.readouterr().out
    assert "--- a/generators/boom" in captured
    assert "+  val pmp_check_passed" in captured


def test_cli_patch_export(capsys, monkeypatch, tmp_path):
    patch_file = tmp_path / "test.patch"
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "spechunter",
            "patch",
            "--target",
            "bpu-barrier-flush",
            "--export",
            str(patch_file),
        ],
    )
    assert main() == 0
    assert patch_file.is_file()
    assert "bht.io.flush := priv_transition" in patch_file.read_text(encoding="utf-8")


def test_cli_differential_suite(capsys, monkeypatch):
    monkeypatch.setattr(sys, "argv", ["spechunter", "differential", "--suite"])
    assert main() == 0
    captured = capsys.readouterr().out
    assert "SpecHunter Microarchitectural Differential Report" in captured
    assert "VERIFIED_MITIGATION" in captured
    assert "VERIFIED_ISOLATION" in captured
    assert "CONTROL_CLEAN" in captured


def test_cli_differential_json(capsys, monkeypatch):
    monkeypatch.setattr(
        sys, "argv", ["spechunter", "differential", "--benchmark", "transient-cache", "--json"]
    )
    assert main() == 0
    captured = capsys.readouterr().out
    data = json.loads(captured)
    assert data["benchmark_id"] == "transient-cache"
    assert data["baseline_leakage"] is True
    assert data["mitigated_leakage"] is False
    assert data["verdict"] == "VERIFIED_MITIGATION"


def test_cli_redteam_default(capsys, monkeypatch):
    monkeypatch.setattr(sys, "argv", ["spechunter", "redteam"])
    assert main() == 0
    captured = capsys.readouterr().out
    assert "SpecHunter Autonomous Red-Team Campaign" in captured
    assert "A3_HACKATHON_VICTORY_CERTIFIED" in captured
    assert "Attacker Exhaustion:    100.0%" in captured


def test_cli_redteam_markdown(capsys, monkeypatch):
    monkeypatch.setattr(sys, "argv", ["spechunter", "redteam", "--markdown"])
    assert main() == 0
    captured = capsys.readouterr().out
    assert "# SpecHunter Autonomous Red-Team Campaign" in captured
    assert "| `transient-cache` | ✓ |" in captured


def test_cli_redteam_export(capsys, monkeypatch, tmp_path):
    report_file = tmp_path / "dossier.json"
    monkeypatch.setattr(
        sys,
        "argv",
        ["spechunter", "redteam", "--export", str(report_file)],
    )
    assert main() == 0
    assert report_file.is_file()
    data = json.loads(report_file.read_text(encoding="utf-8"))
    assert data["verdict"] == "A3_HACKATHON_VICTORY_CERTIFIED"
    assert data["targets_evaluated"] == 4


def test_cli_sva_list(capsys, monkeypatch):
    monkeypatch.setattr(sys, "argv", ["spechunter", "sva", "--list"])
    assert main() == 0
    captured = capsys.readouterr().out
    assert "SystemVerilog Assertion (SVA) Catalog" in captured
    assert "pmp_speculative_isolation" in captured
    assert "issue_715_translation_order" in captured


def test_cli_sva_target(capsys, monkeypatch):
    monkeypatch.setattr(
        sys,
        "argv",
        ["spechunter", "sva", "--target", "pmp-speculative-isolation"],
    )
    assert main() == 0
    captured = capsys.readouterr().out
    assert "module pmp_speculative_isolation_checker" in captured
    assert "assert property" in captured
    assert "bind LSU" in captured


def test_cli_sva_export(capsys, monkeypatch, tmp_path):
    out_file = tmp_path / "boom_sva.sv"
    monkeypatch.setattr(
        sys,
        "argv",
        ["spechunter", "sva", "--export", str(out_file)],
    )
    assert main() == 0
    assert out_file.is_file()
    assert "`define SPECHUNTER_SVA_SV" in out_file.read_text(encoding="utf-8")


def test_cli_profile_default(capsys, monkeypatch):
    monkeypatch.setattr(sys, "argv", ["spechunter", "profile"])
    assert main() == 0
    captured = capsys.readouterr().out
    assert "Hardware Mitigation Performance Overhead Analysis" in captured
    assert "gate-faulting-loads" in captured
    assert "Average SpecHunter IPC Overhead" in captured


def test_cli_profile_markdown(capsys, monkeypatch):
    monkeypatch.setattr(sys, "argv", ["spechunter", "profile", "--markdown"])
    assert main() == 0
    captured = capsys.readouterr().out
    assert "# SpecHunter Hardware Mitigation Performance Overhead Analysis" in captured
    assert "| `gate-faulting-loads` |" in captured


def test_cli_profile_json(capsys, monkeypatch):
    monkeypatch.setattr(sys, "argv", ["spechunter", "profile", "--json"])
    assert main() == 0
    captured = capsys.readouterr().out
    data = json.loads(captured)
    assert "average_ipc_overhead_pct" in data
    assert len(data["profiles"]) >= 3


def test_cli_taint_default(capsys, monkeypatch):
    monkeypatch.setattr(sys, "argv", ["spechunter", "taint"])
    assert main() == 0
    captured = capsys.readouterr().out
    assert "Speculative Information Flow Tracking (IFT)" in captured
    assert "FAILED (LEAKAGE DETECTED)" in captured
    assert "Mutual Information Leakage" in captured


def test_cli_taint_mitigated(capsys, monkeypatch):
    monkeypatch.setattr(sys, "argv", ["spechunter", "taint", "--mitigated"])
    assert main() == 0
    captured = capsys.readouterr().out
    assert "PASSED (TAINT CONFINED)" in captured
    assert "Mutual Information Leakage:   0.00 bits" in captured
    assert "NON_INTERFERENT" in captured


def test_cli_taint_markdown(capsys, monkeypatch):
    monkeypatch.setattr(sys, "argv", ["spechunter", "taint", "--markdown"])
    assert main() == 0
    captured = capsys.readouterr().out
    assert "# SpecHunter Information Flow Tracking & Non-Interference Analysis" in captured


def test_cli_taint_json(capsys, monkeypatch):
    monkeypatch.setattr(sys, "argv", ["spechunter", "taint", "--json"])
    assert main() == 0
    captured = capsys.readouterr().out
    data = json.loads(captured)
    assert "mutual_information_leakage_bits" in data
    assert "execution_steps" in data


def test_cli_testbench_default(capsys, monkeypatch):
    monkeypatch.setattr(sys, "argv", ["spechunter", "testbench"])
    assert main() == 0
    captured = capsys.readouterr().out
    assert "package boom.tests" in captured
    assert "BoomSecurityRegressionSuite" in captured
    assert "ChiselScalatestTester" in captured


def test_cli_testbench_export(capsys, monkeypatch, tmp_path):
    out = tmp_path / "BoomSecurityTest.scala"
    monkeypatch.setattr(sys, "argv", ["spechunter", "testbench", "--export", str(out)])
    assert main() == 0
    assert out.is_file()
    assert "package boom.tests" in out.read_text(encoding="utf-8")


def test_cli_waveform_target_diagram(capsys, monkeypatch):
    monkeypatch.setattr(
        sys, "argv", ["spechunter", "waveform", "--target", "transient-cache", "--diagram"]
    )
    assert main() == 0
    captured = capsys.readouterr().out
    assert "Microarchitectural Waveform Timing Diagram" in captured
    assert "io_lsu_req_valid" in captured
    assert "TRANSIENT_COVERT_MODULATION" in captured


def test_cli_waveform_mitigated(capsys, monkeypatch):
    monkeypatch.setattr(
        sys,
        "argv",
        ["spechunter", "waveform", "--target", "transient-cache", "--mitigated", "--diagram"],
    )
    assert main() == 0
    captured = capsys.readouterr().out
    assert "SUPPRESSED BY MITIGATION" in captured
    assert "Window: 0 cycles" in captured


def test_cli_waveform_vcd(capsys, monkeypatch):
    monkeypatch.setattr(
        sys, "argv", ["spechunter", "waveform", "--target", "privilege-bypass", "--vcd"]
    )
    assert main() == 0
    captured = capsys.readouterr().out
    assert "$timescale 1ns $end" in captured
    assert "$scope module BoomTile $end" in captured


def test_cli_waveform_export_json(capsys, monkeypatch, tmp_path):
    out = tmp_path / "waveform.json"
    monkeypatch.setattr(
        sys,
        "argv",
        ["spechunter", "waveform", "--target", "privilege-bypass", "--export", str(out)],
    )
    assert main() == 0
    assert out.is_file()
    data = json.loads(out.read_text(encoding="utf-8"))
    assert data["benchmark_id"] == "privilege-bypass"
    assert "hazards" in data


def test_cli_coherence_default(capsys, monkeypatch):
    monkeypatch.setattr(sys, "argv", ["spechunter", "coherence"])
    assert main() == 0
    captured = capsys.readouterr().out
    assert "Multi-Core TileLink Coherence Snoop Security Analysis" in captured
    assert "CROSS_CORE_COHERENCE_EXPOSURE" in captured
    assert "1.00 bits" in captured


def test_cli_coherence_mitigated(capsys, monkeypatch):
    monkeypatch.setattr(sys, "argv", ["spechunter", "coherence", "--mitigated"])
    assert main() == 0
    captured = capsys.readouterr().out
    assert "NON_INTERFERENT_ISOLATED" in captured
    assert "0.00 bits" in captured


def test_cli_coherence_markdown(capsys, monkeypatch):
    monkeypatch.setattr(sys, "argv", ["spechunter", "coherence", "--markdown"])
    assert main() == 0
    captured = capsys.readouterr().out
    assert "# SpecHunter Multi-Core TileLink Coherence Snoop Security Report" in captured
    assert "TileLink-C Protocol Transaction Log" in captured


def test_cli_coherence_json(capsys, monkeypatch):
    monkeypatch.setattr(sys, "argv", ["spechunter", "coherence", "--json"])
    assert main() == 0
    captured = capsys.readouterr().out
    data = json.loads(captured)
    assert data["system_cores"] == 2
    assert "transactions" in data


def test_cli_coherence_export(capsys, monkeypatch, tmp_path):
    out = tmp_path / "coherence_report.json"
    monkeypatch.setattr(sys, "argv", ["spechunter", "coherence", "--export", str(out)])
    assert main() == 0
    assert out.is_file()
    data = json.loads(out.read_text(encoding="utf-8"))
    assert data["security_verdict"] == "CROSS_CORE_COHERENCE_EXPOSURE"


def test_cli_formal_default(capsys, monkeypatch):
    monkeypatch.setattr(sys, "argv", ["spechunter", "formal", "--target", "transient-cache"])
    assert main() == 0
    captured = capsys.readouterr().out
    assert "SpecHunter Formal SMT-LIB2 Relational Non-Interference Prover" in captured
    assert "COUNTEREXAMPLE_FOUND" in captured
    assert "Cycle" in captured


def test_cli_formal_mitigated(capsys, monkeypatch):
    monkeypatch.setattr(
        sys,
        "argv",
        ["spechunter", "formal", "--target", "transient-cache", "--mitigated"],
    )
    assert main() == 0
    captured = capsys.readouterr().out
    assert "PROVEN_SECURE" in captured


def test_cli_formal_json(capsys, monkeypatch):
    monkeypatch.setattr(
        sys,
        "argv",
        ["spechunter", "formal", "--target", "privilege-bypass", "--json"],
    )
    assert main() == 0
    captured = capsys.readouterr().out
    data = json.loads(captured)
    assert data["benchmark_id"] == "privilege-bypass"
    assert "total_clauses" in data


def test_cli_formal_export_smt2(capsys, monkeypatch, tmp_path):
    out = tmp_path / "proof.smt2"
    monkeypatch.setattr(
        sys,
        "argv",
        ["spechunter", "formal", "--target", "transient-cache", "--export", str(out)],
    )
    assert main() == 0
    assert out.is_file()
    assert "(set-logic QF_BV)" in out.read_text(encoding="utf-8")


def test_cli_fuzz_default(capsys, monkeypatch):
    monkeypatch.setattr(
        sys,
        "argv",
        ["spechunter", "fuzz", "--target", "transient-cache", "--iterations", "30"],
    )
    assert main() == 0
    captured = capsys.readouterr().out
    assert "SpecHunter Microarchitectural State-Transition Graph (MSTG) Fuzzer" in captured
    assert "MSTG Edge Coverage:" in captured


def test_cli_fuzz_mitigated(capsys, monkeypatch):
    monkeypatch.setattr(
        sys,
        "argv",
        ["spechunter", "fuzz", "--target", "transient-cache", "--iterations", "30", "--mitigated"],
    )
    assert main() == 0
    captured = capsys.readouterr().out
    assert "Invariant Violations:         0" in captured


def test_cli_fuzz_json(capsys, monkeypatch):
    monkeypatch.setattr(
        sys,
        "argv",
        ["spechunter", "fuzz", "--target", "privilege-bypass", "--iterations", "20", "--json"],
    )
    assert main() == 0
    captured = capsys.readouterr().out
    data = json.loads(captured)
    assert data["target_benchmark"] == "privilege-bypass"
    assert data["iterations"] == 20


def test_cli_mcts_default(capsys, monkeypatch):
    monkeypatch.setattr(
        sys,
        "argv",
        ["spechunter", "mcts", "--target", "transient-cache", "--iterations", "15"],
    )
    assert main() == 0
    captured = capsys.readouterr().out
    assert "SpecHunter Monte Carlo Tree Search (MCTS) Program Synthesizer" in captured
    assert "MCTS Iterations Used:" in captured


def test_cli_mcts_json(capsys, monkeypatch):
    monkeypatch.setattr(
        sys,
        "argv",
        ["spechunter", "mcts", "--target", "transient-cache", "--iterations", "10", "--json"],
    )
    assert main() == 0
    captured = capsys.readouterr().out
    data = json.loads(captured)
    assert "simulations_evaluated" in data
    assert "action_frequencies" in data


def test_cli_mcts_export(capsys, monkeypatch, tmp_path):
    out = tmp_path / "mcts_res.json"
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "spechunter",
            "mcts",
            "--target",
            "transient-cache",
            "--iterations",
            "10",
            "--export",
            str(out),
        ],
    )
    assert main() == 0
    assert out.is_file()
    assert "simulations_evaluated" in out.read_text(encoding="utf-8")


def test_cli_contract_default(capsys, monkeypatch):
    monkeypatch.setattr(
        sys,
        "argv",
        ["spechunter", "contract", "--target", "transient-cache"],
    )
    assert main() == 0
    captured = capsys.readouterr().out
    assert "SpecHunter Speculation Contract & Dual-Rail Miter Equivalence Prover" in captured
    assert "PROVEN (PASS - Zero Regression)" in captured
    assert "PROVEN (PASS - Zero Leakage)" in captured


def test_cli_contract_json(capsys, monkeypatch):
    monkeypatch.setattr(
        sys,
        "argv",
        ["spechunter", "contract", "--target", "privilege-bypass", "--json"],
    )
    assert main() == 0
    captured = capsys.readouterr().out
    data = json.loads(captured)
    assert data["benchmark_id"] == "privilege-bypass"
    assert data["functional_equivalence_proven"]


def test_cli_contract_export(capsys, monkeypatch, tmp_path):
    out = tmp_path / "miter.smt2"
    monkeypatch.setattr(
        sys,
        "argv",
        ["spechunter", "contract", "--target", "issue-715", "--export", str(out)],
    )
    assert main() == 0
    assert out.is_file()
    assert "(set-logic QF_BV)" in out.read_text(encoding="utf-8")


def test_cli_rollback_default(capsys, monkeypatch):
    monkeypatch.setattr(
        sys,
        "argv",
        ["spechunter", "rollback", "--target", "transient-cache"],
    )
    assert main() == 0
    captured = capsys.readouterr().out
    assert "SpecHunter Speculative Rollback & Shadow State Recovery Oracle" in captured
    assert "Baseline Core (Unmitigated)" in captured
    assert "FAIL (Stale Aliasing)" in captured


def test_cli_rollback_mitigated(capsys, monkeypatch):
    monkeypatch.setattr(
        sys,
        "argv",
        ["spechunter", "rollback", "--target", "transient-cache", "--mitigated"],
    )
    assert main() == 0
    captured = capsys.readouterr().out
    assert "Mitigated Core (Repaired)" in captured
    assert "PROVEN (Restored)" in captured
    assert "Rollback Integrity Score:     100.0%" in captured


def test_cli_rollback_json(capsys, monkeypatch):
    monkeypatch.setattr(
        sys,
        "argv",
        ["spechunter", "rollback", "--target", "privilege-bypass", "--json"],
    )
    assert main() == 0
    captured = capsys.readouterr().out
    data = json.loads(captured)
    assert data["target_benchmark"] == "privilege-bypass"
    assert "rollback_integrity_score" in data


def test_cli_rollback_export(capsys, monkeypatch, tmp_path):
    out = tmp_path / "rollback.json"
    monkeypatch.setattr(
        sys,
        "argv",
        ["spechunter", "rollback", "--target", "issue-715", "--mitigated", "--export", str(out)],
    )
    assert main() == 0
    assert out.is_file()
    assert "VERIFIED_CLEAN_ATOMIC_ROLLBACK" in out.read_text(encoding="utf-8")


def test_cli_mmu_default(capsys, monkeypatch):
    monkeypatch.setattr(
        sys,
        "argv",
        ["spechunter", "mmu", "--target", "issue-715"],
    )
    assert main() == 0
    captured = capsys.readouterr().out
    assert "SpecHunter Speculative MMU & Page Table Walker Oracle" in captured
    assert "Baseline Core (Vulnerable)" in captured
    assert "LEAKED (External Bus Walk)" in captured
    assert "VIOLATED (Premature Race)" in captured


def test_cli_mmu_mitigated(capsys, monkeypatch):
    monkeypatch.setattr(
        sys,
        "argv",
        ["spechunter", "mmu", "--target", "issue-715", "--mitigated"],
    )
    assert main() == 0
    captured = capsys.readouterr().out
    assert "Mitigated Core (G-PTW)" in captured
    assert "GATED (Suppressed)" in captured
    assert "ENFORCED (Strict Order)" in captured
    assert "VERIFIED_ISOLATED_GATED_TRANSLATION" in captured


def test_cli_mmu_json(capsys, monkeypatch):
    monkeypatch.setattr(
        sys,
        "argv",
        ["spechunter", "mmu", "--target", "issue-715", "--json"],
    )
    assert main() == 0
    captured = capsys.readouterr().out
    data = json.loads(captured)
    assert data["target_benchmark"] == "issue-715"
    assert data["speculative_ptw_side_channel_detected"]


def test_cli_mmu_export(capsys, monkeypatch, tmp_path):
    out = tmp_path / "mmu.json"
    monkeypatch.setattr(
        sys,
        "argv",
        ["spechunter", "mmu", "--target", "issue-715", "--mitigated", "--export", str(out)],
    )
    assert main() == 0
    assert out.is_file()
    assert "VERIFIED_ISOLATED_GATED_TRANSLATION" in out.read_text(encoding="utf-8")


def test_cli_bpu_default(capsys, monkeypatch):
    monkeypatch.setattr(
        sys,
        "argv",
        ["spechunter", "bpu", "--target", "privilege-bypass"],
    )
    assert main() == 0
    captured = capsys.readouterr().out
    assert "SpecHunter Branch Prediction & History Injection Oracle" in captured
    assert "Baseline Core (Shared)" in captured
    assert "COLLISION DETECTED (Vulnerable)" in captured
    assert "VULNERABLE_CROSS_PRIVILEGE_BRANCH_HISTORY_INJECTION" in captured


def test_cli_bpu_mitigated(capsys, monkeypatch):
    monkeypatch.setattr(
        sys,
        "argv",
        ["spechunter", "bpu", "--target", "privilege-bypass", "--mitigated"],
    )
    assert main() == 0
    captured = capsys.readouterr().out
    assert "Mitigated Core (Priv-Tagged)" in captured
    assert "ISOLATED (Privilege Partitioned)" in captured
    assert "VERIFIED_BPU_PRIVILEGE_DOMAIN_ISOLATION" in captured


def test_cli_bpu_json(capsys, monkeypatch):
    monkeypatch.setattr(
        sys,
        "argv",
        ["spechunter", "bpu", "--target", "privilege-bypass", "--json"],
    )
    assert main() == 0
    captured = capsys.readouterr().out
    data = json.loads(captured)
    assert data["target_benchmark"] == "privilege-bypass"
    assert data["cross_privilege_collision_detected"]


def test_cli_bpu_export(capsys, monkeypatch, tmp_path):
    out = tmp_path / "bpu.json"
    monkeypatch.setattr(
        sys,
        "argv",
        ["spechunter", "bpu", "--target", "privilege-bypass", "--mitigated", "--export", str(out)],
    )
    assert main() == 0
    assert out.is_file()
    assert "VERIFIED_BPU_PRIVILEGE_DOMAIN_ISOLATION" in out.read_text(encoding="utf-8")


def test_cli_stlf_default(capsys, monkeypatch):
    monkeypatch.setattr(
        sys,
        "argv",
        ["spechunter", "stlf", "--target", "spectre-v4"],
    )
    assert main() == 0
    captured = capsys.readouterr().out
    assert "SpecHunter Store-to-Load Forwarding & SSB Oracle" in captured
    assert "Baseline Core (12-bit Aliased)" in captured
    assert "COLLISION DETECTED (Vulnerable)" in captured
    assert "VULNERABLE_SPECULATIVE_STORE_FORWARDING" in captured


def test_cli_stlf_mitigated(capsys, monkeypatch):
    monkeypatch.setattr(
        sys,
        "argv",
        ["spechunter", "stlf", "--target", "spectre-v4", "--mitigated"],
    )
    assert main() == 0
    captured = capsys.readouterr().out
    assert "Mitigated Core (Phys-Gated)" in captured
    assert "ISOLATED (Full PA Match)" in captured
    assert "VERIFIED_ISOLATED_STORE_FORWARDING" in captured


def test_cli_stlf_json(capsys, monkeypatch):
    monkeypatch.setattr(
        sys,
        "argv",
        ["spechunter", "stlf", "--target", "spectre-v4", "--json"],
    )
    assert main() == 0
    captured = capsys.readouterr().out
    data = json.loads(captured)
    assert data["target_benchmark"] == "spectre-v4"
    assert data["false_forwarding_detected"]


def test_cli_stlf_export(capsys, monkeypatch, tmp_path):
    out = tmp_path / "stlf.json"
    monkeypatch.setattr(
        sys,
        "argv",
        ["spechunter", "stlf", "--target", "spectre-v4", "--mitigated", "--export", str(out)],
    )
    assert main() == 0
    assert out.is_file()
    assert "VERIFIED_ISOLATED_STORE_FORWARDING" in out.read_text(encoding="utf-8")


def test_cli_mds_default(capsys, monkeypatch):
    monkeypatch.setattr(
        sys,
        "argv",
        ["spechunter", "mds", "--target", "privilege-bypass"],
    )
    assert main() == 0
    captured = capsys.readouterr().out
    assert "SpecHunter Microarchitectural Data Sampling (MDS) Oracle" in captured
    assert "Baseline Core (Unmitigated MSHR)" in captured
    assert "LEAK DETECTED (Vulnerable)" in captured
    assert "VULNERABLE_MICROARCHITECTURAL_DATA_SAMPLING" in captured


def test_cli_mds_mitigated(capsys, monkeypatch):
    monkeypatch.setattr(
        sys,
        "argv",
        ["spechunter", "mds", "--target", "privilege-bypass", "--mitigated"],
    )
    assert main() == 0
    captured = capsys.readouterr().out
    assert "Mitigated Core (LFB-Gate)" in captured
    assert "ISOLATED (0 Leaks)" in captured
    assert "VERIFIED_MDS_ISOLATION" in captured


def test_cli_mds_json(capsys, monkeypatch):
    monkeypatch.setattr(
        sys,
        "argv",
        ["spechunter", "mds", "--target", "privilege-bypass", "--json"],
    )
    assert main() == 0
    captured = capsys.readouterr().out
    data = json.loads(captured)
    assert data["target_benchmark"] == "privilege-bypass"
    assert data["residual_leak_detected"]


def test_cli_mds_export(capsys, monkeypatch, tmp_path):
    out = tmp_path / "mds.json"
    monkeypatch.setattr(
        sys,
        "argv",
        ["spechunter", "mds", "--target", "privilege-bypass", "--mitigated", "--export", str(out)],
    )
    assert main() == 0
    assert out.is_file()
    assert "VERIFIED_MDS_ISOLATION" in out.read_text(encoding="utf-8")


def test_cli_matrix_default(capsys, monkeypatch):
    monkeypatch.setattr(
        sys,
        "argv",
        ["spechunter", "matrix"],
    )
    assert main() == 0
    captured = capsys.readouterr().out
    assert "HARDWARE SECURITY CERTIFICATE" in captured
    assert "HSA-CERT-2026-CHIA-001" in captured
    assert "SILICON_SECURITY_CO_DESIGN_CERTIFIED" in captured
    assert "Subsystems Formally Audited:      11" in captured


def test_cli_matrix_json(capsys, monkeypatch):
    monkeypatch.setattr(
        sys,
        "argv",
        ["spechunter", "matrix", "--json"],
    )
    assert main() == 0
    captured = capsys.readouterr().out
    data = json.loads(captured)
    assert data["certification_id"] == "HSA-CERT-2026-CHIA-001"
    assert data["total_subsystems_audited"] == 11
    assert data["average_mitigated_isolation"] == 100.0


def test_cli_matrix_markdown(capsys, monkeypatch):
    monkeypatch.setattr(
        sys,
        "argv",
        ["spechunter", "matrix", "--markdown"],
    )
    assert main() == 0
    captured = capsys.readouterr().out
    assert "# SpecHunter Grand Unified Microarchitectural Co-Design Verification Matrix" in captured
    assert "SILICON_SECURITY_CO_DESIGN_CERTIFIED" in captured


def test_cli_matrix_export(capsys, monkeypatch, tmp_path):
    out = tmp_path / "matrix.json"
    monkeypatch.setattr(
        sys,
        "argv",
        ["spechunter", "matrix", "--export", str(out)],
    )
    assert main() == 0
    assert out.is_file()
    assert "SILICON_SECURITY_CO_DESIGN_CERTIFIED" in out.read_text(encoding="utf-8")


def test_cli_pmp_default(capsys, monkeypatch):
    monkeypatch.setattr(
        sys,
        "argv",
        ["spechunter", "pmp"],
    )
    assert main() == 0
    captured = capsys.readouterr().out
    assert "RISC-V PHYSICAL MEMORY PROTECTION (PMP) SPECULATIVE BOUNDARY ORACLE" in captured
    assert "BASELINE UNMITIGATED PMP" in captured
    assert "VULNERABLE_SPECULATIVE_PMP_BYPASS" in captured


def test_cli_pmp_mitigated(capsys, monkeypatch):
    monkeypatch.setattr(
        sys,
        "argv",
        ["spechunter", "pmp", "--mitigated"],
    )
    assert main() == 0
    captured = capsys.readouterr().out
    assert "CO-DESIGNED GATED PMP [ACTIVE]" in captured
    assert "VERIFIED_PMP_HARDWARE_ENFORCEMENT" in captured
    assert "100.0%" in captured


def test_cli_pmp_json(capsys, monkeypatch):
    monkeypatch.setattr(
        sys,
        "argv",
        ["spechunter", "pmp", "--json"],
    )
    assert main() == 0
    captured = capsys.readouterr().out
    data = json.loads(captured)
    assert data["pmp_isolation_score"] == 0.125
    assert data["security_verdict"] == "VULNERABLE_SPECULATIVE_PMP_BYPASS"


def test_cli_pmp_export(capsys, monkeypatch, tmp_path):
    out = tmp_path / "pmp.json"
    monkeypatch.setattr(
        sys,
        "argv",
        ["spechunter", "pmp", "--mitigated", "--export", str(out)],
    )
    assert main() == 0
    assert out.is_file()
    assert "VERIFIED_PMP_HARDWARE_ENFORCEMENT" in out.read_text(encoding="utf-8")


def test_cli_ras_default(capsys, monkeypatch):
    monkeypatch.setattr(
        sys,
        "argv",
        ["spechunter", "ras"],
    )
    assert main() == 0
    captured = capsys.readouterr().out
    assert "SPECULATIVE RETURN ADDRESS STACK (RAS) & RETBLEED ORACLE" in captured
    assert "BASELINE UNMITIGATED RAS" in captured
    assert "VULNERABLE_SPECULATIVE_RETURN_HIJACK" in captured


def test_cli_ras_mitigated(capsys, monkeypatch):
    monkeypatch.setattr(
        sys,
        "argv",
        ["spechunter", "ras", "--mitigated"],
    )
    assert main() == 0
    captured = capsys.readouterr().out
    assert "CO-DESIGNED SPEC-GATED RAS [ACTIVE]" in captured
    assert "VERIFIED_RAS_SPECULATIVE_ISOLATION" in captured
    assert "100.0%" in captured


def test_cli_ras_json(capsys, monkeypatch):
    monkeypatch.setattr(
        sys,
        "argv",
        ["spechunter", "ras", "--json"],
    )
    assert main() == 0
    captured = capsys.readouterr().out
    data = json.loads(captured)
    assert data["ras_isolation_score"] == 0.125
    assert data["security_verdict"] == "VULNERABLE_SPECULATIVE_RETURN_HIJACK"


def test_cli_ras_export(capsys, monkeypatch, tmp_path):
    out = tmp_path / "ras.json"
    monkeypatch.setattr(
        sys,
        "argv",
        ["spechunter", "ras", "--mitigated", "--export", str(out)],
    )
    assert main() == 0
    assert out.is_file()
    assert "VERIFIED_RAS_SPECULATIVE_ISOLATION" in out.read_text(encoding="utf-8")


def test_cli_fpu_default(capsys, monkeypatch):
    monkeypatch.setattr(
        sys,
        "argv",
        ["spechunter", "fpu"],
    )
    assert main() == 0
    captured = capsys.readouterr().out
    assert "SPECULATIVE FLOATING-POINT (FPU) & CONSTANT-TIME TIMING ORACLE" in captured
    assert "BASELINE UNMITIGATED FPU" in captured
    assert "VULNERABLE_SPECULATIVE_FPU_TIMING_CHANNEL" in captured


def test_cli_fpu_mitigated(capsys, monkeypatch):
    monkeypatch.setattr(
        sys,
        "argv",
        ["spechunter", "fpu", "--mitigated"],
    )
    assert main() == 0
    captured = capsys.readouterr().out
    assert "CO-DESIGNED CONST-TIME FPU GATE [ACTIVE]" in captured
    assert "VERIFIED_FPU_CONSTANT_TIME_ISOLATION" in captured
    assert "100.0%" in captured


def test_cli_fpu_json(capsys, monkeypatch):
    monkeypatch.setattr(
        sys,
        "argv",
        ["spechunter", "fpu", "--json"],
    )
    assert main() == 0
    captured = capsys.readouterr().out
    data = json.loads(captured)
    assert data["fpu_isolation_score"] == 0.2
    assert data["security_verdict"] == "VULNERABLE_SPECULATIVE_FPU_TIMING_CHANNEL"


def test_cli_fpu_export(capsys, monkeypatch, tmp_path):
    out = tmp_path / "fpu.json"
    monkeypatch.setattr(
        sys,
        "argv",
        ["spechunter", "fpu", "--mitigated", "--export", str(out)],
    )
    assert main() == 0
    assert out.is_file()
    assert "VERIFIED_FPU_CONSTANT_TIME_ISOLATION" in out.read_text(encoding="utf-8")


def test_cli_vector_default(capsys, monkeypatch):
    monkeypatch.setattr(
        sys,
        "argv",
        ["spechunter", "vector"],
    )
    assert main() == 0
    captured = capsys.readouterr().out
    assert "SPECULATIVE VECTOR (RVV) & SIMD REGISTER LEAKAGE ORACLE" in captured
    assert "BASELINE UNMITIGATED VECTOR UNIT" in captured
    assert "VULNERABLE_SPECULATIVE_VECTOR_REGISTER_LEAK" in captured


def test_cli_vector_mitigated(capsys, monkeypatch):
    monkeypatch.setattr(
        sys,
        "argv",
        ["spechunter", "vector", "--mitigated", "--vlen", "512"],
    )
    assert main() == 0
    captured = capsys.readouterr().out
    assert "CO-DESIGNED GATED VECTOR PIPELINE [ACTIVE]" in captured
    assert "VERIFIED_VECTOR_SPECULATIVE_ISOLATION" in captured
    assert "512 bits" in captured
    assert "100.0%" in captured


def test_cli_vector_json(capsys, monkeypatch):
    monkeypatch.setattr(
        sys,
        "argv",
        ["spechunter", "vector", "--json"],
    )
    assert main() == 0
    captured = capsys.readouterr().out
    data = json.loads(captured)
    assert data["vector_isolation_score"] == 0.1
    assert data["security_verdict"] == "VULNERABLE_SPECULATIVE_VECTOR_REGISTER_LEAK"


def test_cli_vector_export(capsys, monkeypatch, tmp_path):
    out = tmp_path / "vector.json"
    monkeypatch.setattr(
        sys,
        "argv",
        ["spechunter", "vector", "--mitigated", "--export", str(out)],
    )
    assert main() == 0
    assert out.is_file()
    assert "VERIFIED_VECTOR_SPECULATIVE_ISOLATION" in out.read_text(encoding="utf-8")
