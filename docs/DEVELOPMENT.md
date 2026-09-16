# Development

`uv sync --locked --group dev` installs the dependency-free core and developer tools.
Run `uv run ruff check .`, `uv run ruff format --check .`, `uv run pytest`, and `uv build`.
The RTL differential test checks both secrets and every fixture variant across
seeded random and guided programs; install `iverilog` to enable it locally.

Run the reproducible quantitative fixture comparison with:

```bash
uv run spechunter evaluate --trials 1000 --iterations 16 \
  --output artifacts/fixture-evaluation.json
```

The command records every random seed and trial, reports discovery and false-positive
rates, attempts and executions, and attaches 95% Wilson intervals to stochastic rates.
It is fixture evaluation and must not be cited as real BOOM vulnerability evidence.

The optional `chia` extra is pinned to a source commit. `spechunter run --chia`
invokes the decorated node in a one-CPU local Ray runtime and shuts it down afterward.
Local sockets must be permitted. The pinned CHIA profiler requires Ray even for local calls.
The source archive avoids an unavailable upstream example-submodule commit. Cluster owners may dispatch
`run_experiment.chia_remote(...)` on an already configured worker with SpecHunter
installed. No cluster is provisioned by this project. See the official
[ChiaFunction guide](https://docs.chialoops.ai/en/latest/user_guides/chia_function.html).
Remote execution is an integration surface, not a validated cloud deployment.

## LLM agent loop

Install the `vertex` extra, configure Google Application Default Credentials, and pass
an explicit model with `--strategy llm --llm-model MODEL_NAME`. The CLI defaults to the
`spechunter` project and `global` location. This path can incur Vertex AI charges; no
model call is made by installation, tests, or the default strategy.

The LLM boundary accepts only schema-constrained data. Candidate programs contain the
fixture's supported abstract operations and are always evaluated by the simulator. Each
repair returns control to the attacker in the same outer recon cycle. A fixture repair
is reported as verified only after at least one clean post-repair validation and the
attacker subsequently reports that it has exhausted materially different candidates.
All loops and LLM calls have independent CLI limits. `--llm-budget-usd` is enforced
against the persistent `--llm-ledger` file. Each request reserves its UTF-8 input byte
count as a conservative token upper bound plus the configured maximum output tokens;
successful calls reconcile against Vertex usage metadata. Unknown failures keep their
full reservation because billing status may be ambiguous. The provider refuses models
without a pricing record verified from the official Vertex pricing page in the last 30
days. This application guard complements cloud billing controls; it is not a statement
of the final Google Cloud invoice.
Adding `--chia` executes the same agent workflow through the optional local CHIA node;
the node receives provider configuration and creates its own client on the worker.

Pull requests run lint, tests, model/RTL comparisons and package builds on Python
3.12 and 3.13. Main builds deliver downloadable wheel/source artifacts. Configure
repository rules to require CI and review before merge; workflows cannot themselves
guarantee branch protection. There is no automatic merge or push to main.
