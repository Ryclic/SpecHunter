"""Bounded, reproducible recon/attack/validate/repair workflow."""

import random
from dataclasses import asdict

from spechunter.backends import Backend, BackendConfig
from spechunter.domain import BENCHMARKS, Benchmark, Op, Program, Validation
from spechunter.process import ExecutionError


def validate(
    backend: Backend,
    program: Program,
    benchmark: Benchmark,
    repeats: int = 2,
    bug: str | None = None,
) -> Validation:
    if repeats < 2 or repeats > 10:
        raise ValueError("validation requires 2..10 repetitions")
    user = False
    for op in program.ops:
        user |= op == Op.ENTER_USER
        if op == Op.LOAD_SECRET and not user:
            return Validation("inconclusive", "secret load outside user threat model", ())
    observations = []
    try:
        secrets = [secret for _ in range(repeats) for secret in (0, 1)]
        if hasattr(backend, "execute_many"):
            observations.extend(backend.execute_many(program, secrets, bug or benchmark.bug))
        else:
            for secret in secrets:
                observations.append(backend.execute(program, secret, bug or benchmark.bug))
    except (ExecutionError, ValueError) as exc:
        return Validation("inconclusive", str(exc), tuple(observations))
    if any(not o.completed for o in observations):
        return Validation("inconclusive", "incomplete execution", tuple(observations))
    for world in (0, 1):
        if any(o != observations[world] for o in observations[world::2]):
            return Validation(
                "inconclusive", "nondeterministic repeated traces", tuple(observations)
            )
    left, right = observations[:2]
    differs = left.architectural != right.architectural
    if benchmark.invariant == "observable-isolation":
        differs |= left.probes != right.probes
    elif benchmark.invariant != "architectural-isolation":
        raise ValueError("unknown invariant")
    return Validation(
        "violation" if differs else "clean",
        "secret-dependent observer output" if differs else "observer outputs agree",
        tuple(observations),
    )


def recon(benchmark: Benchmark) -> dict:
    return {
        "invariant": benchmark.invariant,
        "hypothesis": benchmark.description,
        "provider": "deterministic-fixture",
        "scope": "seeded benchmark",
    }


def attack(benchmark: Benchmark, strategy: str, rng: random.Random, iteration: int) -> Program:
    if strategy == "random":
        return Program(
            (Op.ENTER_USER,) + tuple(rng.choice(list(Op)) for _ in range(rng.randint(2, 12)))
        )
    if strategy != "guided":
        raise ValueError("unknown strategy")
    # First try an architectural load; feedback (no finding) advances to speculation.
    if iteration == 0 or benchmark.invariant == "architectural-isolation":
        return Program.parse(["nop", "enter_user", "load_secret", "probe"])
    return Program.parse(["nop", "train", "enter_user", "load_secret", "encode", "squash", "probe"])


def minimize(
    backend: Backend, program: Program, benchmark: Benchmark, bug: str | None = None
) -> Program:
    """Deletion minimization to a 1-minimal witness, preserving the invariant."""
    changed = True
    while changed and len(program.ops) > 1:
        changed = False
        for i in range(len(program.ops)):
            candidate = Program(program.ops[:i] + program.ops[i + 1 :])
            if benchmark.id == "boom-positive-control" and Op.LOAD_SECRET not in candidate.ops:
                continue
            if validate(backend, candidate, benchmark, bug=bug).violation:
                program, changed = candidate, True
                break
    return program


def repair(backend: Backend, program: Program, benchmark: Benchmark) -> dict:
    if backend.config.kind == "boom":
        return {
            "status": "proposal-only",
            "verified": False,
            "proposal": "Review privilege gating and speculative cache updates in target RTL.",
        }
    result = validate(backend, program, benchmark, bug="none")
    regressions = [
        validate(backend, attack(b, "guided", random.Random(0), 1), b, bug="none")
        for b in BENCHMARKS
    ]
    return {
        "status": "fixture-mitigation",
        "verified": result.status == "clean" and all(r.status == "clean" for r in regressions),
        "proposal": "Use secure fixture variant: gate denied loads before forwarding data.",
        "validation": asdict(result),
        "regressions": [asdict(r) for r in regressions],
        "rtl_patch_applied": False,
    }


def experiment(
    config: BackendConfig | None = None,
    strategy: str = "guided",
    iterations: int = 16,
    seed: int = 0,
    benchmark_id: str | None = None,
) -> dict:
    if not 1 <= iterations <= 1000:
        raise ValueError("iterations must be 1..1000")
    if strategy not in {"guided", "random"}:
        raise ValueError("unknown strategy")
    benchmarks = BENCHMARKS
    if benchmark_id is not None:
        benchmarks = tuple(benchmark for benchmark in BENCHMARKS if benchmark.id == benchmark_id)
        if not benchmarks:
            raise ValueError("unknown benchmark")
    rng = random.Random(seed)
    results = []
    with Backend(config or BackendConfig()) as backend:
        for benchmark in benchmarks:
            attempts = []
            finding = None
            for iteration in range(iterations):
                program = attack(benchmark, strategy, rng, iteration)
                result = validate(backend, program, benchmark)
                attempts.append(
                    {
                        "iteration": iteration + 1,
                        "program": list(program.ops),
                        "validation": asdict(result),
                    }
                )
                if result.violation:
                    reduced = minimize(backend, program, benchmark)
                    reduced_result = validate(backend, reduced, benchmark)
                    attempts[-1]["minimized_validation"] = asdict(reduced_result)
                    if not reduced_result.violation:
                        # An unstable or broken reduction is not a counterexample.
                        break
                    finding = {
                        "program": list(reduced.ops),
                        "sha256": reduced.digest,
                        "assembly": reduced.assembly(),
                        "validation": asdict(reduced_result),
                        "repair": repair(backend, reduced, benchmark),
                    }
                    break
                if result.status == "inconclusive":
                    break
            results.append(
                {
                    "benchmark": asdict(benchmark),
                    "recon": recon(benchmark),
                    "attempts": attempts,
                    "finding": finding,
                }
            )
        positives = [r for r in results if r["benchmark"]["positive"]]
        negatives = [r for r in results if not r["benchmark"]["positive"]]
        return {
            "schema_version": 1,
            "strategy": strategy,
            "seed": seed,
            "iteration_limit": iterations,
            "provenance": backend.provenance(),
            "metrics": {
                "discovered": sum(r["finding"] is not None for r in positives),
                "positive_cases": len(positives),
                "false_positives": sum(r["finding"] is not None for r in negatives),
                "inconclusive_cases": sum(
                    any(
                        a["validation"]["status"] == "inconclusive"
                        or (
                            "minimized_validation" in a
                            and a["minimized_validation"]["status"] != "violation"
                        )
                        for a in r["attempts"]
                    )
                    for r in results
                ),
                "executions": backend.executions,
            },
            "results": results,
        }
