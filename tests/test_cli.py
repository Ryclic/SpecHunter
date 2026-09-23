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
