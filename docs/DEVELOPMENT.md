# Development

`uv sync --locked --group dev` installs the dependency-free core and developer tools.
Run `uv run ruff check .`, `uv run ruff format --check .`, `uv run pytest`, and `uv build`.
The RTL differential test checks both secrets and every fixture variant across
seeded random and guided programs; install `iverilog` to enable it locally.

The optional `chia` extra is pinned to a source commit. `spechunter run --chia`
invokes the decorated node in a one-CPU local Ray runtime and shuts it down afterward.
Local sockets must be permitted. The pinned CHIA profiler requires Ray even for local calls.
The source archive avoids an unavailable upstream example-submodule commit. Cluster owners may dispatch
`run_experiment.chia_remote(...)` on an already configured worker with SpecHunter
installed. No cluster is provisioned by this project. See the official
[ChiaFunction guide](https://docs.chialoops.ai/en/latest/user_guides/chia_function.html).
Remote execution is an integration surface, not a validated cloud deployment.

Pull requests run lint, tests, model/RTL comparisons and package builds on Python
3.12 and 3.13. Main builds deliver downloadable wheel/source artifacts. Configure
repository rules to require CI and review before merge; workflows cannot themselves
guarantee branch protection. There is no automatic merge or push to main.
