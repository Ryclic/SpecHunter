# SpecHunter

SpecHunter is an LLM-driven microarchitectural security loop for the BOOM out-of-order
RISC-V core. Agents propose attack programs and repairs; a deterministic validator decides
every verdict from cycle-accurate simulation. The design rule is *agents propose, the
validator disposes*: an untrusted model may steer the search, but no result is accepted
unless a deterministic oracle and a recomputable cryptographic seal independently support
it.

- Paper: [`paper/spechunter_a3_2026.pdf`](paper/spechunter_a3_2026.pdf)
  (source [`paper/main.tex`](paper/main.tex))
- Sealed-evidence viewer: [`docs/demo.html`](docs/demo.html)
- Evidence index and results summary: [`SUBMISSION.md`](SUBMISSION.md)

## How it works

The loop runs four stages:

1. **Recon** states a hypothesis against a security invariant (user code must not observe a
   PMP-protected secret, architecturally or through cache timing).
2. **Attacker** turns the hypothesis into a program over a closed set of reviewed
   operations. The trusted runner compiles these into fixed RV64 instruction templates.
3. **Validator** runs each candidate under two secret worlds, twice each, on the pinned
   SmallBoomV3 simulator with Spike as the architectural reference. A violation requires a
   deterministic, secret-dependent observation; anything else is inconclusive, never clean.
   Findings are reduced to a 1-minimal witness that must still reproduce.
4. **Repair** selects a closed repair identifier. The orchestrator replays the exact
   witness, which must retest clean, then returns control to the attacker. A repair is
   verified only after attacker exhaustion.

Every experiment binds its source, binary, runner, and outputs into a SHA-256 seal, and a
single verifier recomputes all of them.

## Requirements

- Python 3.12 or 3.13 and [uv](https://docs.astral.sh/uv/).
- Optional: Icarus Verilog (`iverilog`) for the executable RTL fixture.
- Optional: a Google Cloud project with Vertex AI for the live LLM agent loop.
- Real BOOM runs use a pinned Chipyard/BOOM build; see [`docs/BOOM.md`](docs/BOOM.md).

## Installation

```bash
uv sync --locked --group dev
```

The core is dependency-free. The `chia` and `vertex` extras are optional (below).

## Usage

Run the default local loop and the fixture experiments:

```bash
uv run spechunter run
uv run spechunter compare --iterations 32 --seed 42 --output artifacts/comparison.json
uv run spechunter evaluate --trials 1000 --iterations 16 \
  --output artifacts/fixture-evaluation.json
```

Reports include candidates, repeated two-secret observations, minimized witnesses, fixture
mitigation checks, provenance, discovery and false-positive counts, and simulator execution
counts. A simulator failure yields an inconclusive result and exit code 2; a finding exits 0.

**Executable RTL fixture.** With `iverilog` installed:

```bash
uv run spechunter run --backend rtl --output artifacts/rtl.json
```

**LLM agent loop (Vertex AI).** Makes paid model calls via Application Default Credentials;
a persistent ledger reserves a conservative cost before each request and reconciles usage
afterward. Cost, output-token, retry, and loop limits all default to small finite values.

```bash
uv sync --extra vertex --group dev
uv run spechunter run --strategy llm --llm-project PROJECT \
  --llm-location global --llm-model gemini-2.5-flash-lite \
  --llm-budget-usd 1.00 --output artifacts/llm.json
```

**CHIA node.** The optional `chia` extra runs the loop as a decorated node on a local Ray
runtime (`uv sync --extra chia`; `uv run spechunter run --chia`).

**Real BOOM.** The trusted runner executes reviewed programs on the pinned SmallBoomV3
simulator with Spike cross-checking. See [`docs/BOOM.md`](docs/BOOM.md) for the build and
run procedure.

## Validation and reproduction

```bash
uv run ruff check . && uv run ruff format --check .
uv run pytest -m 'not chia'          # core suite; rescans the raw issue #715 waveforms
uv run python tools/verify_evidence.py   # recompute every sealed-evidence digest
```

`tools/run_reproducibility_kit.sh` runs lint, tests, the evidence verifier, and rebuilds the
sealed-evidence viewer, checking it matches the committed `docs/demo.html`. See
[`docs/DEVELOPMENT.md`](docs/DEVELOPMENT.md) for details.

## Evidence

Cryptographically sealed results live in [`docs/evidence/`](docs/evidence/) and are indexed
in [`SUBMISSION.md`](SUBMISSION.md). Results are labelled by the kind of target they were
measured on (real BOOM RTL, a seeded harness mutation, or a deterministic/model fixture) and
are never combined across kinds. The seeded positive control exercises the full loop on real
BOOM; it is not an upstream BOOM vulnerability claim.

## Repository layout

```
src/spechunter/   loop, agents, backends, validator, CHIA node, presentation
tools/            evidence verifier, reproducibility kit, pinned BOOM runners (tools/boom)
tests/            unit and integration tests
docs/             BOOM and cloud guides, development notes, demo, sealed evidence
paper/            submission paper (LaTeX + PDF); overleaf/ mirrors it for Overleaf
```
