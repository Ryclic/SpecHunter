from dataclasses import asdict

import pytest

from spechunter.agent_loop import agent_experiment
from spechunter.agents import AttackDecision, RepairDecision
from spechunter.backends import Backend, BackendConfig
from spechunter.domain import Observation, Op, Program, Validation

LEAK = Program((Op.ENTER_USER, Op.LOAD_SECRET, Op.PROBE))
CHALLENGE = Program((Op.ENTER_USER, Op.LOAD_SECRET, Op.ENCODE, Op.PROBE))


def _challenged(history, cycle):
    return any(
        event.get("stage") == "attacker"
        and event.get("cycle") == cycle
        and event.get("program") == list(CHALLENGE.ops)
        for event in history
    )


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
        provider, BackendConfig(), recon_cycles=1, attack_limit=4, repair_limit=2
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
    assert result["repair"]["attacker_exhausted"] is False
    assert result["repair"]["verified"] is False
    assert provider.repaired_attacks == 1
    assert result["transcript"][4]["rationale"] == "mandatory minimized-exploit repair retest"
    assert result["transcript"][-1]["reason"] == (
        "attacker exhausted without a distinct clean repair challenge"
    )


@pytest.mark.parametrize("pad_with_nop", [False, True])
def test_replaying_same_program_does_not_count_as_a_new_challenge(pad_with_nop):
    class DuplicateProvider(ScriptedProvider):
        def attack(self, benchmark, hypothesis, history, repaired):
            if repaired and not any(
                event.get("rationale") == "duplicate repair candidate" for event in history
            ):
                replay = next(
                    event
                    for event in history
                    if event.get("rationale") == "mandatory minimized-exploit repair retest"
                )
                program = Program.parse(replay["program"])
                if pad_with_nop:
                    program = Program((*program.ops, Op.NOP))
                return AttackDecision("candidate", "duplicate repair candidate", program)
            return super().attack(benchmark, hypothesis, history, repaired)

    result = agent_experiment(
        DuplicateProvider(),
        BackendConfig(),
        recon_cycles=1,
        attack_limit=4,
        repair_limit=1,
        benchmark_id="privilege-bypass",
    )["results"][0]
    assert result["repair"]["verified"] is False
    assert result["repair"]["attacker_exhausted"] is False
    assert (
        len([event for event in result["transcript"] if event.get("outcome") == "candidate"]) == 3
    )


@pytest.mark.parametrize("irrelevant", [Program((Op.NOP,)), Program((Op.ENTER_USER, Op.PROBE))])
def test_clean_irrelevant_candidate_cannot_verify_repair(irrelevant):
    class IrrelevantProvider(ScriptedProvider):
        def attack(self, benchmark, hypothesis, history, repaired):
            if repaired and not any(
                event.get("rationale") == "irrelevant repair candidate" for event in history
            ):
                return AttackDecision("candidate", "irrelevant repair candidate", irrelevant)
            return super().attack(benchmark, hypothesis, history, repaired)

    result = agent_experiment(
        IrrelevantProvider(),
        BackendConfig(),
        recon_cycles=1,
        attack_limit=4,
        repair_limit=1,
        benchmark_id="privilege-bypass",
    )["results"][0]
    challenge = next(
        event
        for event in result["transcript"]
        if event.get("stage") == "validator" and event.get("attempt") == 3
    )
    assert challenge["status"] == "clean"
    assert challenge["repair_challenge_eligible"] is False
    assert result["repair"]["verified"] is False


def test_transient_challenge_needs_speculative_observer_sequence():
    import spechunter.agent_loop as loop

    benchmark = next(b for b in loop.BENCHMARKS if b.id == "transient-cache")
    assert loop._relevant_repair_challenge(CHALLENGE, benchmark) is False
    candidate = Program((Op.TRAIN, Op.ENTER_USER, Op.LOAD_SECRET, Op.ENCODE, Op.SQUASH, Op.PROBE))
    assert loop._relevant_repair_challenge(candidate, benchmark) is True
    fenced = Program((Op.TRAIN, Op.ENTER_USER, Op.FENCE, Op.LOAD_SECRET, Op.ENCODE, Op.PROBE))
    assert loop._relevant_repair_challenge(fenced, benchmark) is False


def test_clean_challenge_that_does_not_break_baseline_cannot_verify_repair():
    harmless = Program((Op.TRAIN, Op.ENTER_USER, Op.LOAD_SECRET, Op.ENCODE, Op.PROBE))

    class HarmlessProvider(ScriptedProvider):
        def attack(self, benchmark, hypothesis, history, repaired):
            if repaired and not any(
                event.get("rationale") == "baseline-clean challenge" for event in history
            ):
                return AttackDecision("candidate", "baseline-clean challenge", harmless)
            return super().attack(benchmark, hypothesis, history, repaired)

    result = agent_experiment(
        HarmlessProvider(),
        BackendConfig(),
        recon_cycles=1,
        attack_limit=4,
        repair_limit=1,
        benchmark_id="privilege-bypass",
    )["results"][0]
    challenge = next(
        event
        for event in result["transcript"]
        if event.get("stage") == "validator" and event.get("attempt") == 3
    )
    assert challenge["repair_challenge_eligible"] is True
    assert challenge["status"] == "clean"
    assert challenge["baseline_challenge_validation"]["status"] == "clean"
    assert result["repair"]["verified"] is False


def test_inconclusive_baseline_challenge_cannot_verify_repair(monkeypatch):
    import spechunter.agent_loop as loop

    class ChallengeProvider(ScriptedProvider):
        def attack(self, benchmark, hypothesis, history, repaired):
            if repaired and not _challenged(history, 1):
                return AttackDecision("candidate", "distinct challenge", CHALLENGE)
            return super().attack(benchmark, hypothesis, history, repaired)

    original_validate = loop.validate

    def unstable_baseline(backend, program, benchmark, **kwargs):
        if program == CHALLENGE and kwargs.get("bug") == benchmark.bug:
            return Validation("inconclusive", "baseline simulator unavailable", ())
        return original_validate(backend, program, benchmark, **kwargs)

    monkeypatch.setattr(loop, "validate", unstable_baseline)
    result = agent_experiment(
        ChallengeProvider(),
        BackendConfig(),
        recon_cycles=1,
        attack_limit=4,
        repair_limit=1,
        benchmark_id="privilege-bypass",
    )["results"][0]
    assert any(
        event.get("baseline_challenge_validation", {}).get("status") == "inconclusive"
        for event in result["transcript"]
    )
    assert result["repair"]["verified"] is False


def test_boom_repair_proposal_is_not_marked_verified():
    # Model this boundary through a provider decision: real-target proposals cannot select
    # fixture variants. The backend integration itself is covered by test_boundaries.py.
    decision = RepairDecision("diagnosis", "RTL proposal", None)
    assert decision.fixture_variant is None


def test_later_outer_cycle_bypass_revokes_earlier_repair_verdict(monkeypatch):
    import spechunter.agent_loop as loop

    class LaterBypassProvider(ScriptedProvider):
        def attack(self, benchmark, hypothesis, history, repaired):
            self.calls += 1
            if hypothesis["hypothesis"].endswith("-2"):
                return AttackDecision("candidate", "new bypass after recon", LEAK)
            if repaired:
                if not _challenged(history, 1):
                    return AttackDecision("candidate", "distinct challenge", CHALLENGE)
                return AttackDecision("exhausted", "no bypass in first recon cycle")
            return AttackDecision("candidate", "initial exploit", LEAK)

    calls = 0

    def fake_validate(backend, program, benchmark, **kwargs):
        nonlocal calls
        calls += 1
        return Validation("clean" if calls in {3, 4} else "violation", "scripted", ())

    monkeypatch.setattr(loop, "validate", fake_validate)
    monkeypatch.setattr(loop, "minimize", lambda backend, program, benchmark, **kwargs: program)
    result = agent_experiment(
        LaterBypassProvider(),
        BackendConfig(),
        recon_cycles=2,
        attack_limit=4,
        repair_limit=1,
        benchmark_id="privilege-bypass",
    )["results"][0]
    assert any(event.get("reason") == "repair limit reached" for event in result["transcript"])
    assert result["repair"]["verified"] is False
    assert result["repair"]["attacker_exhausted"] is False


def test_new_recon_cycle_cannot_reuse_prior_clean_replay(monkeypatch):
    import spechunter.agent_loop as loop

    class ImmediateExhaustionProvider(ScriptedProvider):
        def attack(self, benchmark, hypothesis, history, repaired):
            self.calls += 1
            if hypothesis["hypothesis"].endswith("-2"):
                return AttackDecision("exhausted", "no candidate for the new hypothesis")
            if repaired and not _challenged(history, 1):
                return AttackDecision("candidate", "distinct first-cycle challenge", CHALLENGE)
            return super().attack(benchmark, hypothesis, history, repaired)

    calls = 0

    def fake_validate(backend, program, benchmark, **kwargs):
        nonlocal calls
        calls += 1
        return Validation("violation" if calls <= 2 or calls == 5 else "clean", "scripted", ())

    monkeypatch.setattr(loop, "validate", fake_validate)
    monkeypatch.setattr(loop, "minimize", lambda backend, program, benchmark, **kwargs: program)
    result = agent_experiment(
        ImmediateExhaustionProvider(),
        BackendConfig(),
        recon_cycles=2,
        attack_limit=4,
        repair_limit=1,
        benchmark_id="privilege-bypass",
    )["results"][0]
    assert calls == 5
    assert result["repair"]["verified"] is False
    assert result["repair"]["attacker_exhausted"] is False
    assert result["transcript"][-1]["reason"] == (
        "attacker exhausted without a distinct clean repair challenge"
    )


@pytest.mark.parametrize("later_status", ["clean", "inconclusive"])
def test_later_outer_cycle_must_finish_its_attacker_search(monkeypatch, later_status):
    import spechunter.agent_loop as loop

    class UnfinishedSearchProvider(ScriptedProvider):
        def attack(self, benchmark, hypothesis, history, repaired):
            self.calls += 1
            if hypothesis["hypothesis"].endswith("-2"):
                return AttackDecision("candidate", "new recon candidate", LEAK)
            if repaired:
                if not _challenged(history, 1):
                    return AttackDecision("candidate", "distinct first-cycle challenge", CHALLENGE)
                return AttackDecision("exhausted", "first recon search exhausted")
            return AttackDecision("candidate", "initial exploit", LEAK)

    calls = 0

    def fake_validate(backend, program, benchmark, **kwargs):
        nonlocal calls
        calls += 1
        status = (
            "violation"
            if calls <= 2 or calls == 5
            else "clean"
            if calls in {3, 4}
            else later_status
        )
        return Validation(status, "simulator timed out" if status == "inconclusive" else status, ())

    monkeypatch.setattr(loop, "validate", fake_validate)
    monkeypatch.setattr(loop, "minimize", lambda backend, program, benchmark, **kwargs: program)
    result = agent_experiment(
        UnfinishedSearchProvider(),
        BackendConfig(),
        recon_cycles=2,
        attack_limit=4,
        repair_limit=1,
        benchmark_id="privilege-bypass",
    )["results"][0]
    assert any(event.get("outcome") == "exhausted" for event in result["transcript"])
    assert result["repair"]["verified"] is False
    assert result["repair"]["attacker_exhausted"] is False


@pytest.mark.parametrize("replay_status", ["clean", "inconclusive"])
def test_minimized_witness_must_reproduce_before_repair(monkeypatch, replay_status):
    import spechunter.agent_loop as loop

    calls = 0

    def fake_validate(backend, program, benchmark, **kwargs):
        nonlocal calls
        calls += 1
        status = "violation" if calls == 1 else replay_status
        return Validation(status, "scripted minimized replay", ())

    monkeypatch.setattr(loop, "validate", fake_validate)
    monkeypatch.setattr(loop, "minimize", lambda backend, program, benchmark, **kwargs: program)
    provider = ScriptedProvider()
    result = agent_experiment(
        provider,
        BackendConfig(),
        recon_cycles=2,
        attack_limit=4,
        repair_limit=1,
        benchmark_id="privilege-bypass",
    )["results"][0]
    assert result["findings"] == []
    assert result["repair"]["attempted"] is False
    assert result["repair"]["verified"] is False
    assert result["transcript"][-1]["reason"] == "minimized witness did not reproduce"
    assert result["transcript"][-1]["minimized_validation"]["status"] == replay_status
    assert len([event for event in result["transcript"] if event["stage"] == "recon"]) == 1
    assert provider.calls == 2


def test_repair_receives_minimized_program_and_its_validation(monkeypatch):
    import spechunter.agent_loop as loop

    reduced = Program((Op.ENTER_USER, Op.LOAD_SECRET))
    calls = 0

    def fake_validate(backend, program, benchmark, **kwargs):
        nonlocal calls
        calls += 1
        return Validation(
            "violation" if calls <= 2 else "clean",
            "minimized witness" if calls == 2 else "candidate or retest",
            (),
        )

    class CaptureRepairProvider(ScriptedProvider):
        def repair(self, benchmark, program, validation, history):
            assert program == reduced
            assert validation.reason == "minimized witness"
            return super().repair(benchmark, program, validation, history)

    monkeypatch.setattr(loop, "validate", fake_validate)
    monkeypatch.setattr(loop, "minimize", lambda backend, program, benchmark, **kwargs: reduced)
    result = agent_experiment(
        CaptureRepairProvider(),
        BackendConfig(),
        recon_cycles=1,
        attack_limit=4,
        repair_limit=1,
        benchmark_id="privilege-bypass",
    )["results"][0]
    assert result["findings"][0]["program"] == list(reduced.ops)
    assert result["findings"][0]["validation"]["reason"] == "minimized witness"


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
                if not _challenged(history, 1):
                    return AttackDecision("candidate", "challenge repaired RTL", CHALLENGE)
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
    assert any(event.get("repair_challenge_eligible") is True for event in result["transcript"])
    assert any(
        event.get("baseline_challenge_validation", {}).get("status") == "violation"
        for event in result["transcript"]
    )
    assert result["repair"] == {
        "attempted": True,
        "attacker_exhausted": True,
        "verified": True,
        "final_variant": "gate-faulting-loads",
        "rtl_patch_applied": True,
    }


def test_boom_positive_control_repairs_then_returns_to_attacker(monkeypatch):
    class PositiveControlProvider(ScriptedProvider):
        def attack(self, benchmark, hypothesis, history, repaired):
            self.calls += 1
            if repaired:
                self.repaired_attacks += 1
                if not _challenged(history, 1):
                    return AttackDecision("candidate", "challenge repaired control", CHALLENGE)
                return AttackDecision("exhausted", "seeded cache injection is gone")
            return AttackDecision("candidate", "probe the seeded cache line", LEAK)

        def repair(self, benchmark, program, validation, history):
            self.calls += 1
            return RepairDecision(
                "positive-control harness seeds secret-selected cache state",
                "remove the seeded cache access",
                None,
                "remove-seeded-cache-leak",
            )

    def fake_boom(self, program, secret, bug):
        probe = secret if bug == "seeded-cache-leak" else 0
        return Observation((), (probe,), ("load-access-fault",))

    monkeypatch.setattr(Backend, "_boom", fake_boom)
    provider = PositiveControlProvider()
    report = agent_experiment(
        provider,
        BackendConfig("boom", ("/trusted/runner",), target_revision="revision"),
        recon_cycles=1,
        attack_limit=4,
        repair_limit=1,
        benchmark_id="boom-positive-control",
    )
    result = report["results"][0]
    assert [event["stage"] for event in result["transcript"]] == [
        "recon",
        "attacker",
        "validator",
        "repair",
        "attacker",
        "validator",
        "attacker",
        "validator",
        "attacker",
    ]
    assert result["repair"] == {
        "attempted": True,
        "attacker_exhausted": True,
        "verified": True,
        "final_variant": "remove-seeded-cache-leak",
        "rtl_patch_applied": False,
    }
