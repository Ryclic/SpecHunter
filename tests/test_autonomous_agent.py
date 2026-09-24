"""Unit tests for the autonomous offline agent provider and closed loop."""

from spechunter.agent_loop import agent_experiment
from spechunter.autonomous_agent import AutonomousAgentProvider
from spechunter.backends import BackendConfig
from spechunter.domain import BENCHMARKS, Op, Program


def test_autonomous_agent_provider_protocol():
    provider = AutonomousAgentProvider()
    assert provider.name == "autonomous-symbolic"
    assert provider.calls == 0

    benchmark = BENCHMARKS[1]  # transient-cache
    hypothesis = provider.recon(benchmark, 1, [])
    assert provider.calls == 1
    assert hypothesis["agent"] == "recon"
    assert hypothesis["invariant"] == "observable-isolation"

    attack = provider.attack(benchmark, hypothesis, [], repaired=False)
    assert provider.calls == 2
    assert attack.outcome == "candidate"
    assert attack.program is not None

    repair = provider.repair(benchmark, attack.program, None, [])
    assert provider.calls == 3
    assert repair.repair_id == "gate-faulting-loads"
    assert "Gate speculative load" in repair.proposal


def test_autonomous_agent_repair_positive_control():
    provider = AutonomousAgentProvider()
    benchmark = next(b for b in BENCHMARKS if b.id == "boom-positive-control")
    repair = provider.repair(benchmark, Program((Op.LOAD_SECRET, Op.PROBE)), None, [])
    assert repair.repair_id == "remove-seeded-cache-leak"


def test_autonomous_agent_experiment_closed_loop():
    provider = AutonomousAgentProvider()
    config = BackendConfig(kind="model")
    report = agent_experiment(
        provider,
        config,
        recon_cycles=1,
        attack_limit=8,
        repair_limit=2,
    )

    assert report["strategy"] == "llm"
    assert report["provider"] == "autonomous-symbolic"
    metrics = report["metrics"]
    assert metrics["discovered"] == 3
    assert metrics["positive_cases"] == 3
    assert metrics["false_positives"] == 0
    assert metrics["inconclusive_cases"] == 0
    assert metrics["repairs_attacker_exhausted"] == 3
    assert metrics["llm_calls"] > 0
    assert metrics["executions"] > 0

    for result in report["results"]:
        b_id = result["benchmark"]["id"]
        assert b_id in {b.id for b in BENCHMARKS}
        if result["benchmark"]["positive"]:
            assert len(result["findings"]) > 0
            assert result["repair"]["verified"] is True
            assert result["repair"]["attacker_exhausted"] is True
        else:
            assert len(result["findings"]) == 0
            assert result["repair"]["verified"] is False
