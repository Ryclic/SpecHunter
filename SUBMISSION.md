# SpecHunter: A³ CHIA Hackathon Submission (MICRO 2026)

- **Track:** Discovery and resolution of architectural/microarchitectural bugs in open-source designs (BOOM).
- **Paper:** [`paper/spechunter_a3_2026.pdf`](paper/spechunter_a3_2026.pdf) (source: [`paper/main.tex`](paper/main.tex), IEEEtran two-column, ≤ 4 pages)
- **Repository:** https://github.com/Ryclic/SpecHunter
- **Submission site:** https://a3-chia-hackathon-26.hotcrp.com/

## Author-identified highlights

Every number below comes from a sealed file in [`docs/evidence/`](docs/evidence/).
Each row says what kind of target it was measured on, and we don't mix results across kinds.

1. **A live LLM loop on real BOOM RTL that must earn its "fixed" verdict.**
   Gemini 2.5 Flash-Lite drove the recon, attacker and repair agents against a Verilator build of
   Chipyard 1.14 `SmallBoomV3Config`, with Spike as the architectural reference. It found an
   *intentionally seeded* harness cache leak and minimized it to `enter_user, load_secret, probe`.
   It then chose the closed repair. The orchestrator replayed the witness clean and returned
   to the attacker until exhaustion. That took 28 BOOM executions, 4 model calls, and $0.0006038
   of settled cost.
   Seal: `vertex-boom-demo-seal-2026-09-11.json`.
2. **Validator and repair gate generalize across program shape.** Eight held-out attack programs
   ran in two secret worlds with two repetitions each. All 32 mutated executions were
   deterministic violations and all 32 repaired executions were clean, with 0 inconclusive.
   This tests the loop's decision procedure on BOOM, not an RTL fix.
   Seal: `boom-attack-corpus-seal-2026-09-16.json`.
3. **An honest negative result on upstream BOOM issue #715.** We tested it on the exact reported
   Chipyard `004297b6`/BOOM `fac2c370`, including the reporter's original ELF with a captured
   waveform. The `0x59f` address comes from an independent load's immediate
   (`lb s1,1439(a0)`). The dependent load issues with a poisoned operand and is dropped by BOOM's
   existing register-read gate (`exu/core.scala` L973–978). The issue did not reproduce, and none
   of four candidate LSU patches is credited (`security_fix_validated: false`).
   Seal: `boom-issue-715-attachment-demo-seal-2026-09-20.json`.
4. **Eleven verifier defects found and closed.** Each one would have let an agent claim a false
   finding or a false fix: the minimizer dropping the protected load, same-program retests
   counting as exhaustion, challenges that are clean on *both* variants, stale verdicts across
   cycles, a VCD scanner reading intermediate values, and more. Each is now a regression test
   (paper Table IV).
5. **Reusable CHIA block with cost guardrails.** `run_agent_experiment` runs as a CHIA node on
   local Ray (CHIA 1.0.1, Ray 2.54.0) with a locked reserve-then-settle cost ledger. The whole
   lifecycle cost $0.0005130 on a model fixture. Seal: `chia-vertex-loop-seal-2026-09-16.json`.

## Evidence summary

| Experiment | Target | Result | Seal |
|---|---|---|---|
| PMP privilege gate | BOOM RTL + Spike | pass; cause-5 trap; no value | `boom-privilege-smoke-2026-09-10.json` |
| Pristine baseline matrix | BOOM RTL | 8/8 clean | `boom-secure-matrix-2026-09-11.json` |
| Seeded positive control | BOOM + harness mutation | 8/8 violating → 8/8 clean | `boom-positive-control.json` |
| Live Vertex loop | BOOM + harness mutation | found, repaired, exhausted | `vertex-boom-demo-seal-2026-09-11.json` |
| Held-out corpus | BOOM + harness mutation | 64/64 correct | `boom-attack-corpus-seal-2026-09-16.json` |
| LSU fault-gate patch | patched BOOM RTL | builds; 8/8 clean; **no security claim** | `boom-load-gate-regression-seal-2026-09-16.json` |
| Issue #715 (current, historical, attachment) | BOOM RTL | not reproduced; 4 repairs not credited | `boom-issue-715-*-seal-*.json` |
| Guided vs random (1000 seeds) | deterministic fixture | 2/2 in 1.5 attempts vs 57.25% (55.1–59.4%) in 8.48 | `fixture-guided-vs-random-seal-2026-09-19.json` |
| 10× loop repeatability | model fixture | 10/10; 40 calls; $0.0053752 | `vertex-fixture-repeatability-seal-2026-09-16.json` |

## Limitations (stated up front)

- No new BOOM vulnerability was found. Every successful discovery-and-repair is on an
  intentional harness mutation.
- The live BOOM loop ran once. Repeatability is shown only on a model fixture.
- The guided-vs-random comparison uses three small deterministic fixtures and one deterministic
  guided run.
- Repairs come from a closed, reviewed list, so the agent chooses a repair rather than writing RTL.
- Seals bind the source files used at the time of each run. Several BOOM runners were hardened
  afterward (see `agents/HANDOFF.md`), so those digests describe the historical run rather than
  the current file. The CHIA seal matches the current `chia_nodes.py`, and the 2026-09-19 fixture
  seal matches the current `evaluation.py`, `loop.py`, and `domain.py`.
- A 2026-09-23 batch of modules that returned fixed illustrative values (e.g. ablation, matrix,
  profiler, advisory) was removed before submission. No sealed evidence used them.

## Reproduce

```bash
git clone https://github.com/Ryclic/SpecHunter && cd SpecHunter
uv sync --locked --group dev
uv run python tools/verify_evidence.py   # recompute all seal digests (10 seals, 43 bindings)
uv run pytest -q -m 'not chia'           # includes rescans of the four raw issue #715 waveforms
```

Live BOOM reruns need a pinned Chipyard worker. See [`docs/BOOM.md`](docs/BOOM.md) and
[`docs/CLOUD.md`](docs/CLOUD.md).

## AI assistance

Gemini 2.5 Flash-Lite is a component of the evaluated loop. AI coding assistants (OpenAI Codex,
Google Gemini/Antigravity, Anthropic Claude Code) helped write code, tests, evidence analysis and
the paper. The human authors are responsible for all content.
