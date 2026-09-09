# SpecHunter

A local-first foundation for reproducible microarchitectural security experiments.
The recon → attack → validate → minimize → repair loop currently uses deterministic
hypotheses and small seeded security fixtures. It is not an autonomous LLM researcher,
a BOOM vulnerability discovery result, or a complete Chipyard integration.

## Run

Requires Python 3.12 or 3.13 and [uv](https://docs.astral.sh/uv/).

```bash
uv sync --locked --group dev
uv run spechunter run
uv run spechunter compare --iterations 32 --seed 42 --output artifacts/comparison.json
uv run pytest
```

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
- Optional pinned CHIA node (`uv sync --extra chia`; `uv run spechunter run --chia`).
- Pull request CI and artifact delivery after reviewed changes reach main.

The guided baseline knows the benchmark templates; its results do not establish LLM
performance. Mitigation verification selects the secure fixture variant; it does not
apply or verify a BOOM RTL patch. Candidate assembly requires a trusted runtime harness.

See [development](docs/DEVELOPMENT.md), [BOOM integration](docs/BOOM.md),
[cloud policy](docs/CLOUD.md), and [remaining research work](docs/ROADMAP.md).
