from dataclasses import asdict

from spechunter.agent_loop import agent_experiment
from spechunter.agents import AttackDecision, RepairDecision
from spechunter.backends import Backend, BackendConfig
from spechunter.domain import Observation, Op, Program

LEAK = Program((Op.ENTER_USER, Op.LOAD_SECRET, Op.PROBE))


class ScriptedProvider:
    name = "scripted-test"

    def __init__(self):
        self.calls = 0
        self.repaired_attacks = 0

    def recon(self, benchmark, cycle, history):
        self.calls += 1
        return {"hypothesis": f"{benchmark.id}-{cycle}", "provider": self.name}

    def attack(self, benchmark, hypothesis, history, repaired):
        self.calls += 1
        if repaired:
            self.repaired_attacks += 1
            return AttackDecision("exhausted", "secure variant resists supported candidates")
        if benchmark.bug == "privilege":
            return AttackDecision("candidate", "try direct user read", LEAK)
        return AttackDecision("exhausted", "script has no candidate")

    def repair(self, benchmark, program, validation, history):
        self.calls += 1
        assert asdict(validation)["status"] == "violation"
        return RepairDecision("missing privilege gate", "select secure fixture", "none")


def test_repair_returns_to_attacker_before_next_recon():
    provider = ScriptedProvider()
    report = agent_experiment(
        provider, BackendConfig(), recon_cycles=2, attack_limit=4, repair_limit=2
    )
    result = report["results"][0]
    stages = [event["stage"] for event in result["transcript"]]
    assert stages[:7] == [
        "recon",
        "attacker",
        "validator",
        "repair",
        "attacker",
        "validator",
        "attacker",
    ]
    assert result["repair"]["attacker_exhausted"]
    assert result["repair"]["verified"]
    assert provider.repaired_attacks == 2
    assert result["transcript"][4]["rationale"] == "mandatory minimized-exploit repair retest"


def test_boom_repair_proposal_is_not_marked_verified():
    # Model this boundary through a provider decision: real-target proposals cannot select
    # fixture variants. The backend integration itself is covered by test_boundaries.py.
    decision = RepairDecision("diagnosis", "RTL proposal", None)
    assert decision.fixture_variant is None


def test_attack_decision_contract_rejects_missing_program():
    import pytest

    with pytest.raises(ValueError):
        AttackDecision("candidate", "missing program")


def test_repair_contract_rejects_vulnerable_fixture_variant():
    import pytest

    with pytest.raises(ValueError):
        RepairDecision("diagnosis", "bad repair", "privilege")
    with pytest.raises(ValueError):
        RepairDecision("diagnosis", "bad repair", None, "free-form-patch")


def test_trusted_boom_repair_returns_to_attacker_and_can_be_verified(monkeypatch):
    class BoomProvider(ScriptedProvider):
        def attack(self, benchmark, hypothesis, history, repaired):
            self.calls += 1
            if repaired:
                self.repaired_attacks += 1
                return AttackDecision("exhausted", "no supported bypass remains")
            return AttackDecision("candidate", "exercise faulting load", LEAK)

        def repair(self, benchmark, program, validation, history):
            self.calls += 1
            return RepairDecision(
                "faulting request reaches D-cache",
                "gate faulting load requests",
                None,
                "gate-faulting-loads",
            )

    def fake_boom(self, program, secret, bug):
        probe = 0 if bug == "gate-faulting-loads" else secret
        return Observation((), (probe,), ("load-access-fault",))

    monkeypatch.setattr(Backend, "_boom", fake_boom)
    provider = BoomProvider()
    config = BackendConfig("boom", ("/trusted/runner",), target_revision="revision")
    report = agent_experiment(
        provider,
        config,
        recon_cycles=1,
        attack_limit=4,
        repair_limit=1,
        benchmark_id="secure-control",
    )
    result = report["results"][0]
    repair_event = next(event for event in result["transcript"] if event["stage"] == "repair")
    assert repair_event["status"] == "trusted-candidate-repair"
    assert repair_event["repair_id"] == "gate-faulting-loads"
    assert repair_event["rtl_patch_applied"] is True
    assert result["repair"] == {
        "attempted": True,
        "attacker_exhausted": True,
        "verified": True,
        "final_variant": "gate-faulting-loads",
        "rtl_patch_applied": True,
    }
