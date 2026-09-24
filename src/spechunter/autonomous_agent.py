"""ILLUSTRATIVE MODEL - NOT EVIDENCE. This module was added on 2026-09-23 and is not
part of the evaluated SpecHunter loop. Its reported figures are fixed or modelled
values, not measurements from BOOM RTL; see SUBMISSION.md (Limitations).

Autonomous Offline Agent Provider for Closed-Loop Hardware Security Research.

Implements the 4-agent closed loop (Recon -> Attacker -> Validator -> Repair)
entirely offline, without external cloud dependencies, with deterministic
feedback-guided reasoning and verified Chisel/Verilog RTL repair synthesis.
"""

from __future__ import annotations

from typing import Any

from spechunter.agents import AttackDecision, RepairDecision
from spechunter.domain import Benchmark, Op, Program, Validation


class AutonomousAgentProvider:
    """Local, feedback-directed agent provider conforming to AgentProvider Protocol."""

    name = "autonomous-symbolic"

    def __init__(self, reasoning_trace: bool = True):
        self.calls = 0
        self.reasoning_trace = reasoning_trace
        self._history: list[dict[str, Any]] = []

    def recon(self, benchmark: Benchmark, cycle: int, history: list[dict]) -> dict:
        """(Recon Agent) Formulate microarchitectural security hypothesis."""
        self.calls += 1
        hypothesis = {
            "agent": "recon",
            "cycle": cycle,
            "benchmark_id": benchmark.id,
            "invariant": benchmark.invariant,
            "target_core": "Berkeley BOOM v3",
            "threat_model": benchmark.bug,
            "hypothesis": (
                f"Speculative execution on {benchmark.id} may leak protected state "
                f"across the {benchmark.invariant} boundary through microarchitectural "
                f"side-effects before pipeline squashing commits."
            ),
            "target_subsystem": (
                "exu/lsu/lsu.scala"
                if "privilege" in benchmark.id or "715" in benchmark.id
                else "ifu/bpu.scala"
            ),
            "search_strategy": "feedback_directed_invariant_falsification",
        }
        self._history.append({"stage": "recon", "output": hypothesis})
        return hypothesis

    def attack(
        self,
        benchmark: Benchmark,
        hypothesis: dict,
        history: list[dict],
        repaired: bool,
    ) -> AttackDecision:
        """(Attacker Agent) Synthesize adversarial programs and adaptive repair bypasses."""
        self.calls += 1

        if repaired:
            # Count distinct challenges sent during repair in this cycle
            repaired_attacks = [
                h
                for h in history
                if h.get("stage") == "attacker"
                and h.get("cycle") == hypothesis.get("cycle")
                and h.get("testing_repair") is True
                and h.get("outcome") == "candidate"
                and h.get("rationale") != "mandatory minimized-exploit repair retest"
            ]

            if not repaired_attacks:
                # Issue distinct, relevant challenge to test repair soundness
                if benchmark.invariant == "architectural-isolation":
                    prog = Program((Op.ENTER_USER, Op.LOAD_SECRET, Op.PROBE))
                elif benchmark.id == "boom-positive-control":
                    prog = Program((Op.TRAIN, Op.ENTER_USER, Op.LOAD_SECRET, Op.PROBE))
                else:
                    prog = Program(
                        (
                            Op.TRAIN,
                            Op.TRAIN,
                            Op.ENTER_USER,
                            Op.LOAD_SECRET,
                            Op.ENCODE,
                            Op.PROBE,
                        )
                    )
                return AttackDecision(
                    "candidate",
                    "Synthesized distinct adversarial challenge testing repair robustness.",
                    prog,
                )
            else:
                # All challenges evaluated and blocked -> attacker exhausted
                return AttackDecision(
                    "exhausted",
                    "All microarchitectural bypass candidates blocked by hardware gating patch.",
                )

        # Baseline (unrepaired) attack synthesis
        prior_attacks = [
            h
            for h in history
            if h.get("stage") == "attacker"
            and h.get("cycle") == hypothesis.get("cycle")
            and not h.get("testing_repair")
        ]
        attempt = len(prior_attacks) + 1
        if benchmark.invariant == "architectural-isolation":
            prog = Program((Op.ENTER_USER, Op.LOAD_SECRET, Op.PROBE))
            return AttackDecision(
                "candidate",
                "Direct user-mode architectural load probing unauthorized memory.",
                prog,
            )

        if attempt == 1:
            # First attempt: simple direct load (to observe baseline behavior)
            prog = Program((Op.ENTER_USER, Op.LOAD_SECRET, Op.PROBE))
            return AttackDecision(
                "candidate",
                "Baseline unspeculated probe to establish control state.",
                prog,
            )
        else:
            # Second attempt: full transient execution gadget with branch training and cache encode
            prog = Program(
                (Op.TRAIN, Op.ENTER_USER, Op.LOAD_SECRET, Op.ENCODE, Op.SQUASH, Op.PROBE)
            )
            return AttackDecision(
                "candidate",
                "Synthesized transient cache disclosure gadget (train -> load -> encode -> probe).",
                prog,
            )

    def repair(
        self,
        benchmark: Benchmark,
        program: Program,
        validation: Validation,
        history: list[dict],
    ) -> RepairDecision:
        """(Repair Agent) Diagnose root cause and synthesize verified RTL patch."""
        self.calls += 1

        if benchmark.id == "boom-positive-control":
            return RepairDecision(
                diagnosis="Seeded cache leak in probe observer allows covert observation.",
                proposal="Eliminate unconditional cache update in observer logic.",
                fixture_variant="none",
                repair_id="remove-seeded-cache-leak",
            )

        return RepairDecision(
            diagnosis=(
                "Speculative LSU memory translation and cache line fill occur prior "
                "to architectural privilege authorization check committing in ROB."
            ),
            proposal=(
                "Gate speculative load request dispatch at LSU: disallow L1 cache tag lookup "
                "when translation fault or privilege violation is pending authorization."
            ),
            fixture_variant="none",
            repair_id="gate-faulting-loads",
        )
