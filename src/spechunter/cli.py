"""Local-first command line interface; never provisions cloud resources."""

import argparse
import json
import sys
from pathlib import Path

from spechunter.backends import BackendConfig
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
    parser.add_argument("--target-revision", default="")
    parser.add_argument("--timeout", type=int, default=30)
    parser.add_argument("--chia", action="store_true", help="Run through optional local CHIA node")
    parser.add_argument("--llm-provider", choices=["vertex"], default="vertex")
    parser.add_argument("--llm-project", default="spechunter")
    parser.add_argument("--llm-location", default="global")
    parser.add_argument("--llm-model", help="Vertex model name; required for --strategy llm")
    parser.add_argument("--llm-max-calls", type=int, default=64)
    parser.add_argument("--recon-cycles", type=int, default=2)
    parser.add_argument("--attack-limit", type=int, default=8)
    parser.add_argument("--repair-limit", type=int, default=4)
    args = parser.parse_args()
    try:
        if args.runner and not args.runner.is_absolute():
            raise ValueError("runner must be an absolute executable path")
        config = BackendConfig(
            args.backend,
            (str(args.runner),) if args.runner else (),
            args.timeout,
            args.target_revision,
        )
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
                )
            else:
                from spechunter.agent_loop import agent_experiment
                from spechunter.agents import VertexAgentProvider

                provider = VertexAgentProvider(
                    args.llm_project, args.llm_location, args.llm_model, args.llm_max_calls
                )
                report = agent_experiment(
                    provider,
                    config,
                    args.recon_cycles,
                    args.attack_limit,
                    args.repair_limit,
                )
            reports = [report]
        else:
            reports = [
                execute(config, strategy, args.iterations, args.seed) for strategy in strategies
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
