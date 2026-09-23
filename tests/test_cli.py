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
