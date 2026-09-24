"""Optional CHIA node; local invocation does not create a cluster."""

from decimal import Decimal
from importlib.metadata import version
from pathlib import Path

try:
    from chia.base.ChiaFunction import ChiaFunction
except ImportError:

    def ChiaFunction(*_args, **_kwargs):
        def decorator(fn):
            return fn

        return decorator


from spechunter.agent_loop import agent_experiment
from spechunter.agents import VertexAgentProvider
from spechunter.backends import BackendConfig
from spechunter.loop import experiment


def _orchestration(node: str) -> dict:
    try:
        import ray

        ray_version = ray.__version__
    except ImportError:
        ray_version = "not-installed"

    try:
        chia_version = version("chialoops")
    except Exception:
        chia_version = "not-installed"

    return {
        "engine": "chia",
        "execution": "local-ray",
        "node": node,
        "chialoops_version": chia_version,
        "ray_version": ray_version,
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
    try:
        import ray
    except ImportError:
        report = experiment(config, strategy, iterations, seed, benchmark_id)
        report["orchestration"] = _orchestration("run_experiment")
        return report

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
        try:
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
        except ImportError:
            from spechunter.loop import experiment

            return experiment(
                self.config,
                strategy=self.strategy,
                iterations=self.iterations,
                seed=self.seed,
                benchmark_id=self.benchmark_id,
            )

    @classmethod
    def audit_suite(
        cls,
        benchmark_ids: tuple[str, ...] = ("transient-cache", "privilege-bypass", "secure-control"),
        config: BackendConfig | None = None,
        strategy: str = "guided",
        iterations: int = 16,
        seed: int = 0,
        local: bool = True,
    ) -> dict[str, dict]:
        """Execute a full multi-benchmark security co-design audit suite across threat models."""
        cfg = config or BackendConfig()
        results = {}
        for bid in benchmark_ids:
            block = cls(
                config=cfg,
                strategy=strategy,
                iterations=iterations,
                seed=seed,
                benchmark_id=bid,
            )
            results[bid] = block.execute(local=local)
        return results

    @classmethod
    def summarize_suite(cls, suite_results: dict[str, dict]) -> dict:
        """Summarize security red-teaming metrics across an audited suite."""
        total_discovered = sum(
            r.get("metrics", {}).get("discovered", 0) for r in suite_results.values()
        )
        total_fp = sum(
            r.get("metrics", {}).get("false_positives", 0) for r in suite_results.values()
        )
        total_execs = sum(r.get("metrics", {}).get("executions", 0) for r in suite_results.values())
        clean = [
            b for b, r in suite_results.items() if r.get("metrics", {}).get("discovered", 0) == 0
        ]
        vulnerable = [
            b for b, r in suite_results.items() if r.get("metrics", {}).get("discovered", 0) > 0
        ]
        return {
            "benchmarks_audited": len(suite_results),
            "vulnerabilities_discovered": total_discovered,
            "false_positives": total_fp,
            "total_executions": total_execs,
            "clean_benchmarks": clean,
            "vulnerable_benchmarks": vulnerable,
            "all_clean": len(vulnerable) == 0,
        }

    def execute_agent(self, local: bool = True) -> dict:
        """Execute the 4-agent closed-loop via CHIA autonomous agent provider."""
        return run_autonomous_agent_local(
            self.config,
            recon_cycles=1,
            attack_limit=8,
            repair_limit=2,
            benchmark_id=self.benchmark_id,
        )


def run_autonomous_agent_local(
    config: BackendConfig,
    recon_cycles: int = 1,
    attack_limit: int = 8,
    repair_limit: int = 2,
    benchmark_id: str | None = None,
) -> dict:
    """Execute the 4-stage closed loop locally using the autonomous agent provider."""
    from spechunter.agent_loop import agent_experiment
    from spechunter.autonomous_agent import AutonomousAgentProvider

    provider = AutonomousAgentProvider()
    try:
        import ray

        owned = not ray.is_initialized()
        if owned:
            ray.init(
                address="local",
                num_cpus=1,
                include_dashboard=False,
                object_store_memory=80 * 1024 * 1024,
            )
        try:
            report = agent_experiment(
                provider,
                config,
                recon_cycles=recon_cycles,
                attack_limit=attack_limit,
                repair_limit=repair_limit,
                benchmark_id=benchmark_id,
            )
            report["orchestration"] = _orchestration("run_autonomous_agent")
            return report
        finally:
            if owned:
                ray.shutdown()
    except ImportError:
        report = agent_experiment(
            provider,
            config,
            recon_cycles=recon_cycles,
            attack_limit=attack_limit,
            repair_limit=repair_limit,
            benchmark_id=benchmark_id,
        )
        report["orchestration"] = _orchestration("run_autonomous_agent")
        return report
