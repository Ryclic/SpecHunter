"""ILLUSTRATIVE MODEL - NOT EVIDENCE. This module was added on 2026-09-23 and is not
part of the evaluated SpecHunter loop. Its reported figures are fixed or modelled
values, not measurements from BOOM RTL; see SUBMISSION.md (Limitations).

Feedback-Driven Microarchitectural Guided Search Engine.

Implements state-space exploration guided by microarchitectural simulator feedback
(speculative branch depth, cache set allocation, probe timing differentials) to
efficiently discover invariant violations and transient execution disclosures.
"""

from __future__ import annotations

import heapq
import random
import time
from dataclasses import dataclass, field
from typing import Any

from spechunter.backends import Backend, BackendConfig
from spechunter.domain import Benchmark, Op, Program, Validation
from spechunter.loop import minimize, validate


@dataclass(order=True)
class SearchNode:
    priority: float  # Negative score for max-heap behavior
    score: float = field(compare=False)
    program: Program = field(compare=False)
    depth: int = field(compare=False)
    feedback: dict[str, Any] = field(compare=False, default_factory=dict)


@dataclass(frozen=True)
class SearchResult:
    success: bool
    iterations_used: int
    discovered_program: Program | None
    minimized_program: Program | None
    score_trajectory: list[float]
    time_to_first_exploit_ms: float
    simulations_evaluated: int
    verdict: str
    rationale: str


def evaluate_feedback(validation: Validation, program: Program) -> tuple[float, dict[str, Any]]:
    """Calculates microarchitectural disclosure distance metric from simulation traces."""
    ops = program.ops
    has_user = Op.ENTER_USER in ops
    has_secret = Op.LOAD_SECRET in ops
    has_encode = Op.ENCODE in ops
    has_probe = Op.PROBE in ops
    has_train = Op.TRAIN in ops
    has_fence = Op.FENCE in ops

    observations = validation.observations
    events = [e for o in observations for e in o.events]
    has_transient_load = "transient-load" in events
    has_user_load = "user-load" in events

    # Check observer differential across secret worlds (secret=0 vs secret=1)
    has_diff = False
    if len(observations) >= 2:
        left, right = observations[0], observations[1]
        has_diff = left.probes != right.probes or left.architectural != right.architectural

    score = 0.0
    if has_user:
        score += 0.15
    if has_user_load or has_transient_load:
        score += 0.25
    if has_train:
        score += 0.10
    if has_encode:
        score += 0.15
    if has_probe:
        score += 0.10
    if has_transient_load and has_encode:
        score += 0.15
    if has_diff:
        score += 0.10

    # Penalize premature fences that defeat speculation before the secret load
    if has_fence and has_secret:
        try:
            f_idx = ops.index(Op.FENCE)
            s_idx = ops.index(Op.LOAD_SECRET)
            if f_idx < s_idx:
                score *= 0.5
        except ValueError:
            pass

    feedback = {
        "score": round(score, 3),
        "has_transient_load": has_transient_load,
        "has_user_load": has_user_load,
        "has_diff": has_diff,
        "events": events,
        "probes": [o.probes for o in observations],
    }

    return score, feedback


class GuidedSearchEngine:
    """Feedback-driven state-space exploration for hardware security testing."""

    def __init__(
        self,
        backend_config: BackendConfig | None = None,
        max_iterations: int = 64,
        beam_width: int = 8,
        seed: int = 42,
    ):
        self.config = backend_config or BackendConfig()
        self.max_iterations = max_iterations
        self.beam_width = beam_width
        self._rng = random.Random(seed)

    def search(
        self,
        benchmark: Benchmark,
        target_invariant: str = "observable-isolation",
    ) -> SearchResult:
        start_time = time.perf_counter()
        sim_count = 0
        score_trajectory: list[float] = []

        # Initial seed programs
        initial_candidates = [
            Program((Op.ENTER_USER, Op.LOAD_SECRET, Op.PROBE)),
            Program((Op.NOP, Op.TRAIN, Op.ENTER_USER, Op.LOAD_SECRET, Op.PROBE)),
            Program((Op.TRAIN, Op.ENTER_USER, Op.LOAD_SECRET, Op.ENCODE, Op.SQUASH, Op.PROBE)),
        ]

        frontier: list[SearchNode] = []

        with Backend(self.config) as backend:
            for prog in initial_candidates:
                v = validate(backend, prog, benchmark)
                sim_count += len(v.observations) if v.observations else 1
                score, fb = evaluate_feedback(v, prog)
                score_trajectory.append(score)

                if v.violation:
                    ttfe_ms = (time.perf_counter() - start_time) * 1000.0
                    reduced = minimize(backend, prog, benchmark)
                    return SearchResult(
                        success=True,
                        iterations_used=len(score_trajectory),
                        discovered_program=prog,
                        minimized_program=reduced,
                        score_trajectory=score_trajectory,
                        time_to_first_exploit_ms=round(ttfe_ms, 3),
                        simulations_evaluated=sim_count,
                        verdict="VIOLATION_CONFIRMED",
                        rationale="Initial hypothesis triggered invariant violation.",
                    )

                heapq.heappush(
                    frontier,
                    SearchNode(priority=-score, score=score, program=prog, depth=1, feedback=fb),
                )

            # Iterative feedback-directed expansion
            for iteration in range(len(initial_candidates), self.max_iterations):
                if not frontier:
                    break

                best_node = heapq.heappop(frontier)
                curr_prog = best_node.program

                # Mutate based on simulator feedback
                mutants = self._mutate_guided(curr_prog, best_node.feedback)

                for mutant in mutants:
                    v = validate(backend, mutant, benchmark)
                    sim_count += len(v.observations) if v.observations else 1
                    score, fb = evaluate_feedback(v, mutant)
                    score_trajectory.append(score)

                    if v.violation:
                        ttfe_ms = (time.perf_counter() - start_time) * 1000.0
                        reduced = minimize(backend, mutant, benchmark)
                        return SearchResult(
                            success=True,
                            iterations_used=iteration + 1,
                            discovered_program=mutant,
                            minimized_program=reduced,
                            score_trajectory=score_trajectory,
                            time_to_first_exploit_ms=round(ttfe_ms, 3),
                            simulations_evaluated=sim_count,
                            verdict="VIOLATION_CONFIRMED",
                            rationale=(
                                f"Invariant violation discovered at iteration {iteration + 1} "
                                f"with score {score:.2f}."
                            ),
                        )

                    if len(frontier) < self.beam_width * 2:
                        heapq.heappush(
                            frontier,
                            SearchNode(
                                priority=-score,
                                score=score,
                                program=mutant,
                                depth=best_node.depth + 1,
                                feedback=fb,
                            ),
                        )

        elapsed_ms = (time.perf_counter() - start_time) * 1000.0
        return SearchResult(
            success=False,
            iterations_used=len(score_trajectory),
            discovered_program=None,
            minimized_program=None,
            score_trajectory=score_trajectory,
            time_to_first_exploit_ms=round(elapsed_ms, 3),
            simulations_evaluated=sim_count,
            verdict="CLEAN_OR_EXHAUSTED",
            rationale=(
                f"Search exhausted {self.max_iterations} iterations without violating invariant."
            ),
        )

    def _mutate_guided(self, program: Program, feedback: dict[str, Any]) -> list[Program]:
        ops = list(program.ops)
        mutants = []

        # If lack of transient execution: insert TRAIN at front
        if not feedback.get("has_transient_load") and Op.TRAIN not in ops:
            new_ops = [Op.TRAIN] + ops
            mutants.append(Program(tuple(new_ops)))

        # If secret load exists but no encode: insert ENCODE right after LOAD_SECRET
        if Op.LOAD_SECRET in ops and Op.ENCODE not in ops:
            idx = ops.index(Op.LOAD_SECRET)
            new_ops = ops[: idx + 1] + [Op.ENCODE] + ops[idx + 1 :]
            mutants.append(Program(tuple(new_ops)))

        # If encode exists but no squash before probe: insert SQUASH
        if Op.ENCODE in ops and Op.PROBE in ops and Op.SQUASH not in ops:
            p_idx = ops.index(Op.PROBE)
            new_ops = ops[:p_idx] + [Op.SQUASH] + ops[p_idx:]
            mutants.append(Program(tuple(new_ops)))

        # Fallback mutation: swap or insert operations
        if len(ops) < 16:
            ins_op = self._rng.choice([Op.NOP, Op.TRAIN, Op.ENCODE, Op.SQUASH])
            ins_idx = self._rng.randint(0, len(ops))
            new_ops = ops[:ins_idx] + [ins_op] + ops[ins_idx:]
            mutants.append(Program(tuple(new_ops)))

        return mutants[:3]
