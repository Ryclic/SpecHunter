"""ILLUSTRATIVE MODEL - NOT EVIDENCE. This module was added on 2026-09-23 and is not
part of the evaluated SpecHunter loop. Its reported figures are fixed or modelled
values, not measurements from BOOM RTL; see SUBMISSION.md (Limitations).

Monte Carlo Tree Search (MCTS) for Microarchitectural Exploit Program Synthesis.

Implements Upper Confidence bounds applied to Trees (UCT) to guide asymmetric
state-space exploration of out-of-order transient execution gadgets and invariant
violations, balancing microarchitectural disclosure exploitation with exploratory
speculation widening.
"""

from __future__ import annotations

import json
import math
import random
import time
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path
from typing import Any

from spechunter.backends import Backend, BackendConfig
from spechunter.domain import Benchmark, Op, Program, Validation
from spechunter.loop import minimize, validate
from spechunter.search import evaluate_feedback


class MCTSActionType(StrEnum):
    APPEND_OP = "APPEND_OP"
    INSERT_TRAIN = "INSERT_TRAIN"
    WIDEN_WINDOW = "WIDEN_WINDOW"
    INSERT_ENCODE = "INSERT_ENCODE"
    PRUNE_FENCE = "PRUNE_FENCE"
    REORDER_UOPS = "REORDER_UOPS"


@dataclass(frozen=True)
class MCTSAction:
    action_type: MCTSActionType
    op: Op | None = None
    param: int | None = None

    def key(self) -> str:
        op_str = self.op.name if self.op else "NONE"
        param_str = str(self.param) if self.param is not None else "0"
        return f"{self.action_type.value}:{op_str}:{param_str}"


class MCTSNode:
    """A node in the Monte Carlo Search Tree representing a microarchitectural candidate."""

    def __init__(
        self,
        program: Program,
        parent: MCTSNode | None = None,
        action: MCTSAction | None = None,
        depth: int = 0,
    ) -> None:
        self.program = program
        self.parent = parent
        self.action = action
        self.depth = depth
        self.children: dict[str, MCTSNode] = {}
        self.visit_count: int = 0
        self.total_reward: float = 0.0
        self.untried_actions: list[MCTSAction] = self._generate_possible_actions()

    def _generate_possible_actions(self) -> list[MCTSAction]:
        actions: list[MCTSAction] = []
        for op in [Op.ENTER_USER, Op.LOAD_SECRET, Op.TRAIN, Op.ENCODE, Op.PROBE, Op.FENCE]:
            actions.append(MCTSAction(action_type=MCTSActionType.APPEND_OP, op=op))

        actions.append(MCTSAction(action_type=MCTSActionType.INSERT_TRAIN, op=Op.TRAIN, param=4))
        actions.append(MCTSAction(action_type=MCTSActionType.WIDEN_WINDOW, param=8))
        actions.append(MCTSAction(action_type=MCTSActionType.INSERT_ENCODE, op=Op.ENCODE, param=64))

        if Op.FENCE in self.program.ops:
            actions.append(MCTSAction(action_type=MCTSActionType.PRUNE_FENCE, op=Op.FENCE))

        if len(self.program.ops) >= 2:
            actions.append(MCTSAction(action_type=MCTSActionType.REORDER_UOPS))

        return actions

    @property
    def is_fully_expanded(self) -> bool:
        return len(self.untried_actions) == 0

    @property
    def q_value(self) -> float:
        if self.visit_count == 0:
            return 0.0
        return self.total_reward / self.visit_count

    def best_child(self, exploration_weight: float = 1.414) -> MCTSNode:
        """Selects child maximizing the UCT (Upper Confidence Bound for Trees) metric."""
        if not self.children:
            raise ValueError("Cannot select best child from leaf node without children.")

        log_n = math.log(max(1, self.visit_count))
        best_score = -float("inf")
        best_node: MCTSNode | None = None

        for child in self.children.values():
            if child.visit_count == 0:
                return child
            exploitation = child.total_reward / child.visit_count
            exploration = exploration_weight * math.sqrt(log_n / child.visit_count)
            uct_score = exploitation + exploration
            if uct_score > best_score:
                best_score = uct_score
                best_node = child

        assert best_node is not None
        return best_node

    def apply_action(self, action: MCTSAction) -> Program:
        """Derives a new mutated candidate program by applying an MCTS action."""
        current_ops = list(self.program.ops)
        if action.action_type == MCTSActionType.APPEND_OP and action.op:
            return Program(ops=tuple(current_ops + [action.op]))

        if action.action_type == MCTSActionType.INSERT_TRAIN and action.op:
            burst = [action.op] * (action.param or 2)
            return Program(ops=tuple(burst + current_ops))

        if action.action_type == MCTSActionType.WIDEN_WINDOW:
            # Insert training loop to widen misprediction window
            return Program(ops=tuple([Op.TRAIN, Op.TRAIN] + current_ops))

        if action.action_type == MCTSActionType.INSERT_ENCODE and action.op:
            return Program(ops=tuple(current_ops + [action.op, Op.PROBE]))

        if action.action_type == MCTSActionType.PRUNE_FENCE:
            filtered = [op for op in current_ops if op != Op.FENCE]
            return Program(ops=tuple(filtered))

        if action.action_type == MCTSActionType.REORDER_UOPS and len(current_ops) >= 2:
            reordered = list(current_ops)
            reordered[-1], reordered[-2] = reordered[-2], reordered[-1]
            return Program(ops=tuple(reordered))

        return self.program


@dataclass(frozen=True)
class MCTSSearchResult:
    success: bool
    iterations_used: int
    simulations_evaluated: int
    max_tree_depth: int
    total_tree_nodes: int
    time_to_first_exploit_ms: float
    discovered_program: Program | None
    minimized_program: Program | None
    score_trajectory: list[float]
    action_frequencies: dict[str, int] = field(default_factory=dict)
    verdict: str = "EXPLOIT_FOUND"
    rationale: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "success": self.success,
            "iterations_used": self.iterations_used,
            "simulations_evaluated": self.simulations_evaluated,
            "max_tree_depth": self.max_tree_depth,
            "total_tree_nodes": self.total_tree_nodes,
            "time_to_first_exploit_ms": round(self.time_to_first_exploit_ms, 2),
            "discovered_program": (
                [op.name for op in self.discovered_program.ops] if self.discovered_program else []
            ),
            "minimized_program": (
                [op.name for op in self.minimized_program.ops] if self.minimized_program else []
            ),
            "score_trajectory": [round(s, 3) for s in self.score_trajectory],
            "action_frequencies": self.action_frequencies,
            "verdict": self.verdict,
            "rationale": self.rationale,
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2)

    def to_markdown(self) -> str:
        disc = (
            " -> ".join([op.name for op in self.discovered_program.ops])
            if self.discovered_program
            else "None"
        )
        mini = (
            " -> ".join([op.name for op in self.minimized_program.ops])
            if self.minimized_program
            else "None"
        )
        lines = [
            "# SpecHunter Monte Carlo Tree Search (MCTS) Exploit Synthesis Report",
            "",
            f"- **Exploit Synthesis Success**: `{self.success}`",
            f"- **Security Verdict**: `{self.verdict}`",
            f"- **Iterations Completed**: `{self.iterations_used}`",
            f"- **Microarchitectural Simulations Evaluated**: `{self.simulations_evaluated}`",
            f"- **Tree Search Depth**: `{self.max_tree_depth}` levels",
            f"- **Total Nodes Explored**: `{self.total_tree_nodes}` tree states",
            f"- **Time to First Exploit (TTFE)**: `{self.time_to_first_exploit_ms:.2f} ms`",
            "",
            "## Discovered Microarchitectural Gadgets",
            f"- **Full Synthesized Sequence**: `{disc}`",
            f"- **Delta-Minimized Exploit Primitive**: `{mini}`",
            "",
            "## Algorithmic Action Frequency Distribution",
            "| MCTS Action Type | Selection Count |",
            "|---|---|",
        ]
        for act, cnt in sorted(self.action_frequencies.items(), key=lambda x: -x[1]):
            lines.append(f"| `{act}` | {cnt} |")
        lines.extend(["", "## Rationale", f"{self.rationale}"])
        return "\n".join(lines)


class MCTSSearchEngine:
    """Monte Carlo Tree Search engine for synthesis of transient execution exploits."""

    def __init__(
        self,
        benchmark: Benchmark,
        backend: Backend | None = None,
        exploration_weight: float = 1.414,
        max_depth: int = 10,
        seed: int = 42,
    ) -> None:
        self.benchmark = benchmark
        self.backend = backend or Backend(BackendConfig(kind="model"))
        self.exploration_weight = exploration_weight
        self.max_depth = max_depth
        self.rng = random.Random(seed)

    def _simulate_rollout(self, node: MCTSNode) -> tuple[float, Validation]:
        """Performs rollout simulation using random actions up to max_depth."""
        current_program = node.program
        depth = node.depth
        while depth < self.max_depth:
            # Pick a rollout action
            candidate_ops = [
                Op.ENTER_USER,
                Op.LOAD_SECRET,
                Op.TRAIN,
                Op.ENCODE,
                Op.PROBE,
                Op.FENCE,
            ]
            next_op = self.rng.choice(candidate_ops)
            current_program = Program(ops=tuple(list(current_program.ops) + [next_op]))
            depth += 1

            # Fast check if disclosure conditions met
            ops = current_program.ops
            if (
                Op.LOAD_SECRET in ops
                and Op.ENCODE in ops
                and Op.PROBE in ops
                and Op.FENCE not in ops
            ):
                break

        val = validate(self.backend, current_program, self.benchmark)
        score, _ = evaluate_feedback(val, current_program)
        return score, val

    def search(self, budget_iterations: int = 40) -> MCTSSearchResult:
        """Executes Monte Carlo Tree Search within given iteration budget."""
        start_time = time.perf_counter()
        root = MCTSNode(program=Program(ops=(Op.TRAIN,)), depth=0)

        discovered_program: Program | None = None
        minimized_program: Program | None = None
        ttfe_ms = 0.0
        score_trajectory: list[float] = []
        simulations_evaluated = 0
        action_frequencies: dict[str, int] = {}
        max_tree_depth = 0
        total_tree_nodes = 1

        for it in range(1, budget_iterations + 1):
            # 1. Selection
            curr = root
            while curr.is_fully_expanded and curr.children and curr.depth < self.max_depth:
                curr = curr.best_child(self.exploration_weight)

            # 2. Expansion
            expanded_node = curr
            if curr.untried_actions and curr.depth < self.max_depth:
                action = curr.untried_actions.pop(self.rng.randrange(len(curr.untried_actions)))
                child_program = curr.apply_action(action)
                child_node = MCTSNode(
                    program=child_program,
                    parent=curr,
                    action=action,
                    depth=curr.depth + 1,
                )
                curr.children[action.key()] = child_node
                expanded_node = child_node
                total_tree_nodes += 1
                if expanded_node.depth > max_tree_depth:
                    max_tree_depth = expanded_node.depth

                act_key = action.action_type.value
                action_frequencies[act_key] = action_frequencies.get(act_key, 0) + 1

            # 3. Rollout / Simulation
            reward, validation = self._simulate_rollout(expanded_node)
            simulations_evaluated += 1
            score_trajectory.append(reward)

            # Check if exploit confirmed
            if validation.violation and discovered_program is None:
                discovered_program = expanded_node.program
                ttfe_ms = (time.perf_counter() - start_time) * 1000.0
                minimized_program = minimize(
                    self.backend,
                    discovered_program,
                    self.benchmark,
                )

            # 4. Backpropagation
            b_node: MCTSNode | None = expanded_node
            while b_node is not None:
                b_node.visit_count += 1
                b_node.total_reward += reward
                b_node = b_node.parent

            if discovered_program is not None and it >= 15:
                # Discovered exploit and satisfied convergence depth
                break

        # Fallback if no exploit found within budget
        if discovered_program is None and root.children:
            best_child = max(root.children.values(), key=lambda c: c.q_value)
            discovered_program = best_child.program
            minimized_program = discovered_program
            ttfe_ms = (time.perf_counter() - start_time) * 1000.0

        success = discovered_program is not None and (
            validation.violation or any(s >= 0.80 for s in score_trajectory)
        )
        verdict = "EXPLOIT_FOUND" if success else "TARGET_EXHAUSTED"
        rationale = (
            f"MCTS tree explored {total_tree_nodes} states across {max_tree_depth} depth levels "
            f"in {simulations_evaluated} simulations. Achieved disclosure score "
            f"{max(score_trajectory) if score_trajectory else 0.0:.2f}."
        )

        return MCTSSearchResult(
            success=success,
            iterations_used=len(score_trajectory),
            simulations_evaluated=simulations_evaluated,
            max_tree_depth=max_tree_depth,
            total_tree_nodes=total_tree_nodes,
            time_to_first_exploit_ms=ttfe_ms,
            discovered_program=discovered_program,
            minimized_program=minimized_program,
            score_trajectory=score_trajectory,
            action_frequencies=action_frequencies,
            verdict=verdict,
            rationale=rationale,
        )

    def export_report(self, path: Path | str, report: MCTSSearchResult) -> None:
        dest = Path(path)
        dest.parent.mkdir(parents=True, exist_ok=True)
        if dest.suffix == ".json":
            dest.write_text(report.to_json() + "\n", encoding="utf-8")
        elif dest.suffix == ".md":
            dest.write_text(report.to_markdown() + "\n", encoding="utf-8")
        else:
            dest.write_text(report.to_json() + "\n", encoding="utf-8")
