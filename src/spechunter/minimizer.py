"""Hierarchical Delta Debugger for Microarchitectural Counterexamples.

Reduces complex adversarial instruction sequences into minimal 1-minimal witnesses
while strictly preserving the microarchitectural violation semantics across simulation.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from spechunter.backends import Backend
from spechunter.domain import Benchmark, Op, Program
from spechunter.loop import validate


@dataclass(frozen=True)
class MinimizationReport:
    original_ops: list[str]
    minimized_ops: list[str]
    original_length: int
    minimized_length: int
    reduction_percentage: float
    total_validations: int
    minimized_digest: str
    steps_record: list[dict[str, Any]]

    def to_dict(self) -> dict[str, Any]:
        return {
            "original_length": self.original_length,
            "minimized_length": self.minimized_length,
            "reduction_percentage": round(self.reduction_percentage, 1),
            "total_validations": self.total_validations,
            "minimized_digest": self.minimized_digest,
            "minimized_ops": self.minimized_ops,
            "steps_record": self.steps_record,
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2)


class HierarchicalDeltaDebugger:
    """Multi-stage delta-debugging algorithm for microarchitectural test cases."""

    def __init__(self, preserve_positive_control: bool = True):
        self.preserve_positive_control = preserve_positive_control

    def minimize(
        self,
        backend: Backend,
        program: Program,
        benchmark: Benchmark,
        bug: str | None = None,
    ) -> MinimizationReport:
        original_ops = [op.value for op in program.ops]
        original_len = len(program.ops)
        curr_program = program
        total_evals = 0
        steps: list[dict[str, Any]] = []

        # Stage 1: Chunk-based Delta Debugging (Coarse-to-fine granularity)
        granularity = 2
        while granularity <= len(curr_program.ops):
            chunk_size = max(1, len(curr_program.ops) // granularity)
            reduced_in_pass = False

            i = 0
            while i < len(curr_program.ops):
                candidate_ops = curr_program.ops[:i] + curr_program.ops[i + chunk_size :]
                if not candidate_ops:
                    i += chunk_size
                    continue

                candidate = Program(candidate_ops)
                if (
                    self.preserve_positive_control
                    and benchmark.id == "boom-positive-control"
                    and Op.LOAD_SECRET not in candidate.ops
                ):
                    i += chunk_size
                    continue

                total_evals += 1
                v = validate(backend, candidate, benchmark, bug=bug)
                if v.violation:
                    steps.append(
                        {
                            "stage": "chunk_prune",
                            "removed_range": [i, i + chunk_size],
                            "prev_len": len(curr_program.ops),
                            "new_len": len(candidate.ops),
                        }
                    )
                    curr_program = candidate
                    reduced_in_pass = True
                    break  # Restart with new length
                else:
                    i += chunk_size

            if not reduced_in_pass:
                granularity *= 2

        # Stage 2: Fine-Grained 1-Minimal Pass
        changed = True
        while changed and len(curr_program.ops) > 1:
            changed = False
            for i in range(len(curr_program.ops)):
                candidate_ops = curr_program.ops[:i] + curr_program.ops[i + 1 :]
                if not candidate_ops:
                    continue

                candidate = Program(candidate_ops)
                if (
                    self.preserve_positive_control
                    and benchmark.id == "boom-positive-control"
                    and Op.LOAD_SECRET not in candidate.ops
                ):
                    continue

                total_evals += 1
                v = validate(backend, candidate, benchmark, bug=bug)
                if v.violation:
                    steps.append(
                        {
                            "stage": "single_op_prune",
                            "removed_op": curr_program.ops[i].value,
                            "index": i,
                            "new_len": len(candidate.ops),
                        }
                    )
                    curr_program = candidate
                    changed = True
                    break

        minimized_len = len(curr_program.ops)
        reduction = (
            ((original_len - minimized_len) / original_len * 100.0) if original_len > 0 else 0.0
        )

        return MinimizationReport(
            original_ops=original_ops,
            minimized_ops=[op.value for op in curr_program.ops],
            original_length=original_len,
            minimized_length=minimized_len,
            reduction_percentage=reduction,
            total_validations=total_evals,
            minimized_digest=curr_program.digest,
            steps_record=steps,
        )
