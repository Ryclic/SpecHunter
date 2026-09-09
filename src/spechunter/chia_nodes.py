"""Optional CHIA node; local invocation does not create a cluster."""

from chia.base.ChiaFunction import ChiaFunction

from spechunter.backends import BackendConfig
from spechunter.loop import experiment


@ChiaFunction(num_cpus=1, max_retries=0)
def run_experiment(
    config: BackendConfig, strategy: str = "guided", iterations: int = 16, seed: int = 0
) -> dict:
    return experiment(config, strategy, iterations, seed)


def run_local(
    config: BackendConfig, strategy: str = "guided", iterations: int = 16, seed: int = 0
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
        return run_experiment(config, strategy, iterations, seed)
    finally:
        if owned:
            ray.shutdown()
