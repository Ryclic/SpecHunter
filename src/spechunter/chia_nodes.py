"""Optional CHIA node; local invocation does not create a cluster."""

from decimal import Decimal
from pathlib import Path

from chia.base.ChiaFunction import ChiaFunction

from spechunter.agent_loop import agent_experiment
from spechunter.agents import VertexAgentProvider
from spechunter.backends import BackendConfig
from spechunter.loop import experiment


@ChiaFunction(num_cpus=1, max_retries=0)
def run_experiment(
    config: BackendConfig,
    strategy: str = "guided",
    iterations: int = 16,
    seed: int = 0,
    benchmark_id: str | None = None,
) -> dict:
    return experiment(config, strategy, iterations, seed, benchmark_id)


def run_local(
    config: BackendConfig,
    strategy: str = "guided",
    iterations: int = 16,
    seed: int = 0,
    benchmark_id: str | None = None,
) -> dict:
    """Own a one-CPU local Ray runtime; never attach to a cloud cluster."""
    import ray

    owned = not ray.is_initialized()
    try:
        if owned:
            ray.init(
                address="local",
                num_cpus=1,
                include_dashboard=False,
                object_store_memory=80 * 1024 * 1024,
            )
        return run_experiment(config, strategy, iterations, seed, benchmark_id)
    finally:
        if owned:
            ray.shutdown()


@ChiaFunction(num_cpus=1, max_retries=0)
def run_agent_experiment(
    config: BackendConfig,
    project: str,
    location: str,
    model: str,
    max_calls: int = 64,
    recon_cycles: int = 2,
    attack_limit: int = 8,
    repair_limit: int = 4,
    budget_usd: Decimal = Decimal("1.00"),
    ledger_path: Path = Path("artifacts/llm-cost.json"),
    max_output_tokens: int = 2048,
    retries: int = 2,
    benchmark_id: str | None = None,
) -> dict:
    provider = VertexAgentProvider(
        project,
        location,
        model,
        max_calls,
        budget_usd,
        ledger_path,
        max_output_tokens,
        retries,
    )
    return agent_experiment(
        provider, config, recon_cycles, attack_limit, repair_limit, benchmark_id
    )


def run_agent_local(
    config: BackendConfig,
    project: str,
    location: str,
    model: str,
    max_calls: int = 64,
    recon_cycles: int = 2,
    attack_limit: int = 8,
    repair_limit: int = 4,
    budget_usd: Decimal = Decimal("1.00"),
    ledger_path: Path = Path("artifacts/llm-cost.json"),
    max_output_tokens: int = 2048,
    retries: int = 2,
    benchmark_id: str | None = None,
) -> dict:
    """Run the LLM workflow through a locally owned one-CPU Ray runtime."""
    import ray

    owned = not ray.is_initialized()
    try:
        if owned:
            ray.init(
                address="local",
                num_cpus=1,
                include_dashboard=False,
                object_store_memory=80 * 1024 * 1024,
            )
        return run_agent_experiment(
            config,
            project,
            location,
            model,
            max_calls,
            recon_cycles,
            attack_limit,
            repair_limit,
            budget_usd,
            ledger_path,
            max_output_tokens,
            retries,
            benchmark_id,
        )
    finally:
        if owned:
            ray.shutdown()
