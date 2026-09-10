"""Bounded nested recon and repair-red-team loops driven by an agent provider."""

from dataclasses import asdict

from spechunter.agents import AgentProvider
from spechunter.backends import Backend, BackendConfig
from spechunter.domain import BENCHMARKS, Benchmark
from spechunter.loop import minimize, validate


def _run_benchmark(
    backend: Backend,
    provider: AgentProvider,
    benchmark: Benchmark,
    recon_cycles: int,
    attack_limit: int,
    repair_limit: int,
) -> dict:
    transcript: list[dict] = []
    findings: list[dict] = []
    active_variant = benchmark.bug
    repair_round = 0
    repair_verified = False
    clean_since_repair = False
    required_retest = None

    for cycle in range(1, recon_cycles + 1):
        hypothesis = provider.recon(benchmark, cycle, transcript)
        transcript.append({"stage": "recon", "cycle": cycle, "output": hypothesis})
        repaired = active_variant != benchmark.bug
        exhausted = False
        for attempt in range(1, attack_limit + 1):
            decision = provider.attack(benchmark, hypothesis, transcript, repaired, required_retest)
            attack_event = {
                "stage": "attacker",
                "cycle": cycle,
                "attempt": attempt,
                "testing_repair": repaired,
                "outcome": decision.outcome,
                "rationale": decision.rationale,
                "program": list(decision.program.ops) if decision.program else None,
            }
            transcript.append(attack_event)
            if decision.outcome == "exhausted":
                exhausted = True
                if repaired and clean_since_repair and required_retest is None:
                    repair_verified = True
                elif repaired:
                    transcript.append(
                        {
                            "stage": "validator",
                            "status": "inconclusive",
                            "reason": "attacker exhausted without testing the repair",
                            "observations": [],
                        }
                    )
                break

            result = validate(backend, decision.program, benchmark, bug=active_variant)
            transcript.append(
                {"stage": "validator", "cycle": cycle, "attempt": attempt, **asdict(result)}
            )
            if result.status == "inconclusive":
                break
            if not result.violation:
                if repaired and (
                    required_retest is None or decision.program.digest == required_retest.digest
                ):
                    clean_since_repair = True
                    required_retest = None
                continue

            reduced = minimize(backend, decision.program, benchmark, bug=active_variant)
            findings.append(
                {
                    "cycle": cycle,
                    "program": list(reduced.ops),
                    "sha256": reduced.digest,
                    "assembly": reduced.assembly(),
                    "validation": asdict(validate(backend, reduced, benchmark, bug=active_variant)),
                    "variant": active_variant,
                }
            )
            if repair_round >= repair_limit:
                transcript.append({"stage": "limit", "reason": "repair limit reached"})
                break
            repair_round += 1
            repair = provider.repair(benchmark, reduced, result, transcript)
            if backend.config.kind == "boom":
                active_variant = benchmark.bug
                status = "proposal-only"
            else:
                active_variant = repair.fixture_variant or benchmark.bug
                status = "fixture-mitigation"
            repaired = True
            repair_verified = False
            clean_since_repair = False
            required_retest = reduced
            transcript.append(
                {
                    "stage": "repair",
                    "round": repair_round,
                    "status": status,
                    "diagnosis": repair.diagnosis,
                    "proposal": repair.proposal,
                    "active_variant": active_variant,
                    "rtl_patch_applied": False,
                }
            )
            # Deliberately continue this same loop at attacker after every repair.
        if transcript[-1].get("stage") == "limit":
            break
        if not exhausted and transcript[-1].get("status") == "inconclusive":
            break

    return {
        "benchmark": asdict(benchmark),
        "transcript": transcript,
        "findings": findings,
        "repair": {
            "attempted": repair_round > 0,
            "attacker_exhausted": repair_verified,
            "verified": repair_verified and backend.config.kind != "boom",
            "final_variant": active_variant,
            "rtl_patch_applied": False,
        },
    }


def agent_experiment(
    provider: AgentProvider,
    config: BackendConfig | None = None,
    recon_cycles: int = 2,
    attack_limit: int = 8,
    repair_limit: int = 4,
) -> dict:
    for value, name, maximum in (
        (recon_cycles, "recon cycles", 100),
        (attack_limit, "attack limit", 1000),
        (repair_limit, "repair limit", 100),
    ):
        if not 1 <= value <= maximum:
            raise ValueError(f"{name} must be 1..{maximum}")
    with Backend(config or BackendConfig()) as backend:
        results = [
            _run_benchmark(backend, provider, benchmark, recon_cycles, attack_limit, repair_limit)
            for benchmark in BENCHMARKS
        ]
        positives = [r for r in results if r["benchmark"]["positive"]]
        negatives = [r for r in results if not r["benchmark"]["positive"]]
        return {
            "schema_version": 2,
            "strategy": "llm",
            "provider": provider.name,
            "limits": {
                "recon_cycles": recon_cycles,
                "attacks_per_cycle": attack_limit,
                "repairs_per_benchmark": repair_limit,
            },
            "provenance": backend.provenance(),
            "metrics": {
                "discovered": sum(bool(r["findings"]) for r in positives),
                "positive_cases": len(positives),
                "false_positives": sum(bool(r["findings"]) for r in negatives),
                "inconclusive_cases": sum(
                    any(e.get("status") == "inconclusive" for e in r["transcript"]) for r in results
                ),
                "repairs_attacker_exhausted": sum(
                    r["repair"]["attacker_exhausted"] for r in results
                ),
                "executions": backend.executions,
                "llm_calls": provider.calls,
            },
            "results": results,
        }
