"""Local-first command line interface; never provisions cloud resources."""

import argparse
import json
import sys
from decimal import Decimal
from pathlib import Path

from spechunter.backends import BackendConfig
from spechunter.domain import BENCHMARKS
from spechunter.loop import experiment


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=["run", "compare"])
    parser.add_argument("--backend", choices=["model", "rtl", "boom"], default="model")
    parser.add_argument("--strategy", choices=["guided", "random", "llm"], default="guided")
    parser.add_argument("--iterations", type=int, default=16)
    parser.add_argument("--seed", type=int, default=0)
    parser.add_argument("--output", type=Path, default=Path("artifacts/run.json"))
    parser.add_argument(
        "--runner", type=Path, help="Trusted BOOM runner executable (absolute path)"
    )
    parser.add_argument(
        "--runner-arg",
        action="append",
        default=[],
        help="Argument passed to the trusted runner before the request path (repeatable)",
    )
    parser.add_argument("--target-revision", default="")
    parser.add_argument(
        "--timeout", type=int, help="per-execution seconds (default: 900 for BOOM, 30 otherwise)"
    )
    parser.add_argument("--benchmark", choices=[benchmark.id for benchmark in BENCHMARKS])
    parser.add_argument("--chia", action="store_true", help="Run through optional local CHIA node")
    parser.add_argument("--llm-provider", choices=["vertex"], default="vertex")
    parser.add_argument("--llm-project", default="spechunter")
    parser.add_argument("--llm-location", default="global")
    parser.add_argument("--llm-model", help="Vertex model name; required for --strategy llm")
    parser.add_argument("--llm-max-calls", type=int, default=64)
    parser.add_argument("--llm-budget-usd", type=Decimal, default=Decimal("1.00"))
    parser.add_argument("--llm-ledger", type=Path, default=Path("artifacts/llm-cost.json"))
    parser.add_argument("--llm-max-output-tokens", type=int, default=2048)
    parser.add_argument("--llm-retries", type=int, default=2)
    parser.add_argument("--recon-cycles", type=int, default=2)
    parser.add_argument("--attack-limit", type=int, default=8)
    parser.add_argument("--repair-limit", type=int, default=4)
    args = parser.parse_args()
    try:
        if args.runner and not args.runner.is_absolute():
            raise ValueError("runner must be an absolute executable path")
        if args.runner_arg and not args.runner:
            raise ValueError("--runner-arg requires --runner")
        timeout = (
            args.timeout if args.timeout is not None else (900 if args.backend == "boom" else 30)
        )
        config = BackendConfig(
            args.backend,
            (str(args.runner), *args.runner_arg) if args.runner else (),
            timeout,
            args.target_revision,
        )
        benchmark_id = args.benchmark
        if args.backend == "boom" and benchmark_id is None:
            benchmark_id = "secure-control"
        execute = experiment
        if args.chia:
            from spechunter.chia_nodes import run_local

            execute = run_local
        strategies = ["guided", "random"] if args.command == "compare" else [args.strategy]
        if "llm" in strategies:
            if not args.llm_model:
                raise ValueError("--llm-model is required for --strategy llm")
            if args.chia:
                from spechunter.chia_nodes import run_agent_local

                report = run_agent_local(
                    config,
                    args.llm_project,
                    args.llm_location,
                    args.llm_model,
                    args.llm_max_calls,
                    args.recon_cycles,
                    args.attack_limit,
                    args.repair_limit,
                    args.llm_budget_usd,
                    args.llm_ledger,
                    args.llm_max_output_tokens,
                    args.llm_retries,
                    benchmark_id,
                )
            else:
                from spechunter.agent_loop import agent_experiment
                from spechunter.agents import VertexAgentProvider

                provider = VertexAgentProvider(
                    args.llm_project,
                    args.llm_location,
                    args.llm_model,
                    args.llm_max_calls,
                    args.llm_budget_usd,
                    args.llm_ledger,
                    args.llm_max_output_tokens,
                    args.llm_retries,
                )
                report = agent_experiment(
                    provider,
                    config,
                    args.recon_cycles,
                    args.attack_limit,
                    args.repair_limit,
                    benchmark_id,
                )
            reports = [report]
        else:
            reports = [
                execute(config, strategy, args.iterations, args.seed, benchmark_id)
                for strategy in strategies
            ]
        args.output.parent.mkdir(parents=True, exist_ok=True)
        temporary = args.output.with_suffix(args.output.suffix + ".tmp")
        temporary.write_text(
            json.dumps(reports if args.command == "compare" else reports[0], indent=2) + "\n"
        )
        temporary.replace(args.output)
        print(json.dumps({r["strategy"]: r["metrics"] for r in reports}, indent=2))
        return 2 if any(r["metrics"]["inconclusive_cases"] for r in reports) else 0
    except (ValueError, OSError, ImportError, RuntimeError) as exc:
        print(f"spechunter: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
