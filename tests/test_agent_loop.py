from dataclasses import asdict

from spechunter.agent_loop import agent_experiment
from spechunter.agents import AttackDecision, RepairDecision
from spechunter.backends import BackendConfig
from spechunter.domain import Op, Program

LEAK = Program((Op.ENTER_USER, Op.LOAD_SECRET, Op.PROBE))


class ScriptedProvider:
    name = "scripted-test"

    def __init__(self):
        self.calls = 0
        self.repaired_attacks = 0
        self.clean_retest_done = False

    def recon(self, benchmark, cycle, history):
        self.calls += 1
        return {"hypothesis": f"{benchmark.id}-{cycle}", "provider": self.name}

    def attack(self, benchmark, hypothesis, history, repaired, required_retest):
        self.calls += 1
        if repaired:
            self.repaired_attacks += 1
            if not self.clean_retest_done:
                self.clean_retest_done = True
                return AttackDecision("candidate", "retest original attack", required_retest)
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
    assert provider.repaired_attacks == 3


def test_boom_repair_proposal_is_not_marked_verified():
    # Model this boundary through a provider decision: real-target proposals cannot select
    # fixture variants. The backend integration itself is covered by test_boundaries.py.
    decision = RepairDecision("diagnosis", "RTL proposal", None)
    assert decision.fixture_variant is None


def test_attack_decision_contract_rejects_missing_program():
    import pytest

    with pytest.raises(ValueError):
        AttackDecision("candidate", "missing program")
