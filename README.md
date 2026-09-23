# SpecHunter

> **MICRO 2026 A³ Workshop — CHIA Hackathon Submission**
> **Track:** *Discovery and resolution of architectural and microarchitectural bugs in widely-used open-source designs such as the BOOM core.*
>
> 📄 **4-Page Submission Paper:** [`paper/spechunter_micro2026.pdf`](paper/spechunter_micro2026.pdf) (LaTeX: [`paper/spechunter.tex`](paper/spechunter.tex))
> 🖥️ **Interactive Sealed Evidence Demo:** [`docs/demo.html`](docs/demo.html)
> 🚀 **Push-Button Reproducibility Kit:** `./tools/run_reproducibility_kit.sh`
> 🧩 **Composable CHIA Block:** [`spechunter.chia_nodes.SpecHunterSecurityAuditBlock`](src/spechunter/chia_nodes.py) (See [`examples/run_chia_pipeline.py`](examples/run_chia_pipeline.py))

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

Those September 11 and 16 agent transcripts used the earlier exhaustion criterion:
the agent stopped after the mandatory exploit replay. Current runs require an additional
distinct, clean attacker-generated candidate that exercises the protected user load
and relevant observer *and* reproduces a violation on the original vulnerable variant
before reporting a repair as verified.
The separate eight-program held-out gate remains evidence for the historical positive
control, not a substitute for that current agent-loop requirement.

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

The source-reviewed BOOM LSU candidate patch has now also been built into a distinct
SmallBoomV3 simulator. Its eight target-regression executions were deterministic and
clean, and a seal binds the baseline binary, patch, repaired binary, and matrix. This
validates patch buildability and regression behavior; it is not a validated security fix
because the pristine baseline did not exhibit the hypothesized violation.

A reviewed adaptation of upstream BOOM issue #715 was also executed four times on the
current pinned simulator. It used a delayed trained branch, wrong-path protected load,
dependent cache encode, and matched secret worlds. All observations were deterministically
clean, so the sealed assessment records that the older reported issue was not reproduced
on this revision and makes no vulnerability or fix claim.

The separately executed original issue #715 ELF on historical BOOM also has no
validated vulnerability or fix claim: waveform attribution identifies its later
`0x59f` requests as coming from an independent third instruction. The
protected-data-dependent load issues from the memory queue in baseline and v1/v2
but has no matching valid LSU execute request or branch-masked translation request;
v3 lacks its matched issue.
Three candidate repair comparisons are consequently inconclusive.

Generate the presentation locally from its sealed evidence:

```bash
uv run spechunter present \
  --input docs/evidence/vertex-boom-demo-2026-09-11.json \
  --seal docs/evidence/vertex-boom-demo-seal-2026-09-11.json \
  --corpus docs/evidence/boom-attack-corpus-2026-09-16.json \
  --corpus-seal docs/evidence/boom-attack-corpus-seal-2026-09-16.json \
  --evaluation docs/evidence/fixture-guided-vs-random-2026-09-19.json \
  --evaluation-seal docs/evidence/fixture-guided-vs-random-seal-2026-09-19.json \
  --repeatability docs/evidence/vertex-fixture-repeatability-2026-09-16.json \
  --repeatability-seal docs/evidence/vertex-fixture-repeatability-seal-2026-09-16.json \
  --chia-evidence docs/evidence/chia-vertex-loop-2026-09-16.json \
  --chia-seal docs/evidence/chia-vertex-loop-seal-2026-09-16.json \
  --rtl-repair-seal docs/evidence/boom-load-gate-regression-seal-2026-09-16.json \
  --issue-715-seal docs/evidence/boom-issue-715-assessment-seal-2026-09-16.json \
  --issue-715-attachment-seal docs/evidence/boom-issue-715-attachment-demo-seal-2026-09-20.json \
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

# Interactive engineering and verification subcommands
uv run spechunter verify           # Cryptographic verification of all 8 seals & paper
uv run spechunter waveform         # Terminal cycle-accurate hazard timing explorer
uv run spechunter taxonomy         # Formal Spectre microarchitectural taxonomy table
uv run spechunter taxonomy --json  # Machine-readable JSON taxonomy export
uv run spechunter audit --benchmark transient-cache --iterations 4 --json
uv run spechunter audit --suite    # Multi-benchmark audit across all threat models
uv run spechunter audit --suite --json  # Machine-readable suite summary & findings
uv run spechunter benchmark        # Microarchitectural latency, throughput & memory profiler
uv run spechunter benchmark --json # Machine-readable performance metrics export

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
  repair is verified only after a clean retest, a distinct relevant challenge that
  fails on the original variant but passes on the repair, and attacker exhaustion.
  The outer loop then returns to recon for a fresh hypothesis.
- Pull request CI and artifact delivery after reviewed changes reach main.

The guided baseline knows the benchmark templates; its results do not establish LLM
performance. Mitigation verification selects the secure fixture variant; it does not
apply or verify a BOOM RTL patch. Candidate assembly requires a trusted runtime harness.

See [development](docs/DEVELOPMENT.md), [BOOM integration](docs/BOOM.md),
[cloud policy](docs/CLOUD.md), and [remaining research work](docs/ROADMAP.md).
