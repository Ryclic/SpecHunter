# SpecHunter

A local-first foundation for reproducible microarchitectural security experiments.
The default recon → attack → validate → minimize → repair loop uses deterministic
hypotheses and small seeded security fixtures. An optional Vertex AI integration runs
the proposal's agent stages with bounded, structured LLM calls. Neither mode by itself
is a BOOM vulnerability discovery result or a complete Chipyard integration.

## Run

Requires Python 3.12 or 3.13 and [uv](https://docs.astral.sh/uv/).

```bash
uv sync --locked --group dev
uv run spechunter run
uv run spechunter compare --iterations 32 --seed 42 --output artifacts/comparison.json
uv run pytest
```

Install the optional Vertex dependency and select a model to run the agent loop:

```bash
uv sync --extra vertex --group dev
uv run spechunter run --strategy llm --llm-project spechunter \
  --llm-location global --llm-model gemini-2.5-flash-lite \
  --llm-budget-usd 1.00 --output artifacts/llm.json
```

This command makes paid model calls using Application Default Credentials. A persistent
ledger reserves a conservative maximum cost before each request and reconciles usage
metadata afterward. Limits for cost, output tokens, retries, outer recon cycles, attacks,
repairs, and total LLM calls default to small finite values and have corresponding flags.

The default semantic backend requires no simulator, API key, or cloud spending.
Install Icarus Verilog (`sudo apt-get install iverilog`) to run the executable RTL fixture:

```bash
uv run spechunter run --backend rtl --output artifacts/rtl.json
```

Reports include candidates, repeated two-secret observations, minimized witnesses,
fixture mitigation checks, provenance, discovery counts, false positives, inconclusive
cases, and simulator execution counts. A simulator failure produces an inconclusive
result and CLI exit code 2; a finding is a valid experiment result (exit code 0).

## Scope

- Three seeded cases: architectural privilege bypass, transient cache leakage, secure control.
- Guided deterministic candidate templates and a seeded random baseline.
- Repeated secret-world comparison, deletion minimization, secure-variant regression checks.
- Model and executable SystemVerilog fixtures, plus a strict external BOOM runner contract.
- Pinned Chipyard 1.14/SmallBoomV3 build automation with a hash-evidenced, successfully
  executed Verilator bare-metal smoke test.
- Optional pinned CHIA node (`uv sync --extra chia`; `uv run spechunter run --chia`).
- Optional Vertex agents with schema-constrained recon, attack, and repair responses.
- Nested repair red-teaming: every repair returns to attacker → validator; a fixture
  repair is verified only after a clean retest followed by attacker exhaustion. The
  outer loop then returns to recon for a fresh hypothesis.
- Pull request CI and artifact delivery after reviewed changes reach main.

The guided baseline knows the benchmark templates; its results do not establish LLM
performance. Mitigation verification selects the secure fixture variant; it does not
apply or verify a BOOM RTL patch. Candidate assembly requires a trusted runtime harness.

See [development](docs/DEVELOPMENT.md), [BOOM integration](docs/BOOM.md),
[cloud policy](docs/CLOUD.md), and [remaining research work](docs/ROADMAP.md).
