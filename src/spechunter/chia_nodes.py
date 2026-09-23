"""Optional CHIA node; local invocation does not create a cluster."""

from decimal import Decimal
from importlib.metadata import version
from pathlib import Path

from chia.base.ChiaFunction import ChiaFunction

from spechunter.agent_loop import agent_experiment
from spechunter.agents import VertexAgentProvider
from spechunter.backends import BackendConfig
from spechunter.loop import experiment


def _orchestration(node: str) -> dict:
    import ray

    return {
        "engine": "chia",
        "execution": "local-ray",
        "node": node,
        "chialoops_version": version("chialoops"),
        "ray_version": ray.__version__,
    }


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
        report = run_experiment(config, strategy, iterations, seed, benchmark_id)
        report["orchestration"] = _orchestration("run_experiment")
        return report
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
        report = run_agent_experiment(
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
        report["orchestration"] = _orchestration("run_agent_experiment")
        return report
    finally:
        if owned:
            ray.shutdown()


class SpecHunterSecurityAuditBlock:
    """Composable CHIA block for microarchitectural security red-teaming and repair.

    Can be composed into CHIA DAG pipelines or executed as an autonomous auditing node.
    """

    def __init__(
        self,
        config: BackendConfig | None = None,
        strategy: str = "guided",
        iterations: int = 16,
        seed: int = 0,
        benchmark_id: str | None = None,
    ):
        self.config = config or BackendConfig()
        self.strategy = strategy
        self.iterations = iterations
        self.seed = seed
        self.benchmark_id = benchmark_id

    def execute(self, local: bool = True) -> dict:
        """Execute the security audit block, returning a structured findings report."""
        if local:
            return run_local(
                self.config,
                strategy=self.strategy,
                iterations=self.iterations,
                seed=self.seed,
                benchmark_id=self.benchmark_id,
            )
        return run_experiment(
            self.config,
            strategy=self.strategy,
            iterations=self.iterations,
            seed=self.seed,
            benchmark_id=self.benchmark_id,
        )
