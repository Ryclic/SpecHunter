# SpecHunter

An LLM-driven microarchitectural security system that attacks a real RISC-V BOOM RTL
simulation, validates observations, minimizes a witness, selects a bounded repair, and
returns to the attacker until the supported search is exhausted.

The sealed live demonstration used Gemini 2.5 Flash-Lite and 28 SmallBoomV3 executions
to discover and repair an intentional cache-leak positive control. Open the
[self-contained evidence demo](docs/demo.html), or inspect the hash-bound report and
cost ledger in [`docs/evidence/`](docs/evidence/). The positive control proves the full
workflow; it is explicitly not an upstream BOOM vulnerability claim.

The repair also passes a held-out gate of eight distinct programs and 64 additional
SmallBoomV3 executions: every intentional mutation was detected, every repaired case was
clean, and none was inconclusive. The corpus is bound to the same simulator as the live
Vertex run.

On the separate deterministic fixture benchmark, guided search discovered 100% of seeded
positive cases in 1.5 attempts on average. Across 1,000 seeds, random search discovered
57.25% within the same 16-attempt limit (95% Wilson interval 55.07%–59.40%) and required
8.48 attempts on average. Both approaches produced zero false positives and inconclusive
cases. These search-quality results are explicitly separated from real BOOM evidence.

Ten additional independent Gemini trials completed the entire fixture discovery, repair,
mandatory retest, and attacker-exhaustion loop successfully. The 40 calls and complete
transcripts are sealed with their settled $0.0053752 cost ledger. This measures LLM-loop
repeatability; it does not replace the live BOOM run.

The Vertex loop has also executed through the pinned CHIA 1.0.1 node on a locally owned
Ray 2.54.0 runtime. Its four-call discovery-and-repair transcript, CHIA provenance, and
$0.0005130 settled ledger are sealed as a separate integration artifact.

Generate the presentation locally from its sealed evidence:

```bash
uv run spechunter present \
  --input docs/evidence/vertex-boom-demo-2026-09-11.json \
  --seal docs/evidence/vertex-boom-demo-seal-2026-09-11.json \
  --corpus docs/evidence/boom-attack-corpus-2026-09-16.json \
  --corpus-seal docs/evidence/boom-attack-corpus-seal-2026-09-16.json \
  --evaluation docs/evidence/fixture-guided-vs-random-2026-09-16.json \
  --evaluation-seal docs/evidence/fixture-guided-vs-random-seal-2026-09-16.json \
  --repeatability docs/evidence/vertex-fixture-repeatability-2026-09-16.json \
  --repeatability-seal docs/evidence/vertex-fixture-repeatability-seal-2026-09-16.json \
  --chia-evidence docs/evidence/chia-vertex-loop-2026-09-16.json \
  --chia-seal docs/evidence/chia-vertex-loop-seal-2026-09-16.json \
  --output artifacts/demo.html
```

The default local mode uses deterministic hypotheses and small security fixtures. Vertex
AI and real BOOM execution are optional, bounded integrations.

## Run

Requires Python 3.12 or 3.13 and [uv](https://docs.astral.sh/uv/).

```bash
uv sync --locked --group dev
uv run spechunter run
uv run spechunter compare --iterations 32 --seed 42 --output artifacts/comparison.json
uv run spechunter evaluate --trials 1000 --iterations 16 \
  --output artifacts/fixture-evaluation.json
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
- A strict trusted BOOM request compiler with pinned Spike comparison, PMP/trap runtime,
  fixed secret-independent cache probes, bounded execution, and structured observations.
- A closed trusted repair catalog: the LLM may select a source-audited load-gate patch,
  which is rebuilt in an isolated checkout and returned to attacker retesting.
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
