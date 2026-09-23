# SpecHunter: MICRO 2026 A³ CHIA Hackathon Submission Dossier

- **Track:** *Discovery and resolution of architectural and microarchitectural bugs in widely-used open-source designs such as the BOOM core.*
- **Conference:** A³ Workshop: Agentic Approaches to Architecture (Co-located with MICRO 2026, Athens, Greece)
- **HotCRP Submission URL:** `https://a3-chia-hackathon-26.hotcrp.com/`
- **Open-Source Repository:** `https://github.com/Ryclic/SpecHunter`
- **Pull Request:** [PR #19: Add MICRO 2026 A3 CHIA hackathon submission package](https://github.com/Ryclic/SpecHunter/pull/19)

---

## 1. Author-Identified Highlights

1. **Cycle-Accurate Real BOOM RTL Grounding & Live Autonomous Loop:**
   - Deployed Google Gemini 2.5 Flash-Lite against real cycle-accurate Berkeley BOOM (`SmallBoomV3`) RTL in Verilator with Spike golden ISA co-simulation.
   - Autonomously discovered a speculative cache side-channel violation within 28 BOOM executions and 4 LLM calls, minimized the exploit to a 3-instruction trigger, applied targeted mitigation, and proved clean retest and attacker exhaustion on real BOOM simulation with an average cost of under **$0.0006 per run**.
2. **First Verifiable Chisel RTL Repair in BOOM's Load-Store Unit (`lsu.scala`):**
   - Synthesized and compiled a Chisel RTL patch in BOOM's LSU (`exu/lsu/lsu.scala`) into a distinct Verilator binary (`fd4a264c...`).
   - Verified across a held-out test suite of 8 diverse attack programs across 64 cycle-accurate BOOM executions: **100% detection on vulnerable core, 100% clean execution on repaired core, and 0 functional regressions**.
3. **Disambiguation of Long-Standing Upstream BOOM Issue #715:**
   - Traced cycle-by-cycle VCD signal propagation across cycles 3804–3811 on historical BOOM commit `fac2c370...`.
   - Identified the exact hardware interlock gate in `generators/boom/src/main/scala/exu/core.scala:973-978` (`iss_valid && !(ld_miss && poisoned)`), proving the dependent speculative load was suppressed at runtime before reaching LSU execute stage (`io_core_exe_0_req_valid = 0`).
   - Proved that the observed `0x59F` TLB translation request was hardcoded in the independent instruction `lb s1, 1439(a0)` (`1439 == 0x59F`), conclusively resolving an ambiguous historical vulnerability report.
4. **Formal Microarchitectural Spectre Taxonomy:**
   - Formally maps speculative vulnerability variants (Spectre-v1, Spectre-v2, Spectre-v4, Meltdown-RDCL) directly to Berkeley BOOM hardware units (`ifu/bpu.scala`, `exu/core.scala`, `exu/lsu/lsu.scala`), speculation windows, and RTL interlock gates in `spechunter.taxonomy`.
5. **Composable CHIA Ecosystem Integration:**
   - Released `SpecHunterSecurityAuditBlock` in `spechunter.chia_nodes` as an upstream-ready, reusable CHIA node running on single-CPU local Ray 2.54.0 runtime with graceful fallbacks.
6. **Publication-Ready 4-Page IEEE/ACM Research Paper:**
   - Included as `paper/spechunter_micro2026.pdf` (strictly 4 pages in IEEE/ACM two-column format) with complete Typst/LaTeX source, vector figures, and BibTeX citations.
7. **Zero-Trust Push-Button Reproducibility Kit:**
   - Single command (`./tools/run_reproducibility_kit.sh`) executes code quality checks, 184 unit tests, verifies 8 cryptographic SHA-256 evidence seals, and compiles the standalone interactive viewer.

---

## 2. Abstract

Modern out-of-order processors deploy aggressive speculative execution mechanisms that frequently interact with privilege checks, cache hierarchies, and memory disambiguation logic in ways unanticipated by designers. While functional fuzzing has made significant strides, microarchitectural security analysis requires semantic guidance to construct multi-stage gadgets that cross privilege boundaries and observe transient microarchitectural residue. We introduce **SpecHunter**, an agentic red-teaming and automated repair framework integrated into the open-source CHIA (Co-design with Heterogeneous Intelligent Agents) architecture. SpecHunter coordinates four specialized agent stages—Reconnaissance, Attacker, Validator, and Repair—backed by schema-constrained LLM generation, cycle-accurate simulation in Berkeley BOOM (SmallBoomV3), Spike golden reference co-simulation, and an atomic cost-accounting ledger.

We demonstrate real-world impact across three critical dimensions: (1) In a live, end-to-end experiment using Gemini 2.5 Flash-Lite against cycle-accurate BOOM RTL, SpecHunter autonomously discovered a transient side-channel leak, minimized it to a 3-instruction trigger, applied targeted mitigation, and verified clean retest and attacker exhaustion on real BOOM simulation with Spike co-simulation; additionally, a candidate Chisel RTL repair in BOOM's LSU (`lsu.scala`) was compiled into a distinct Verilator binary and verified across target regressions with zero functional regression; (2) In a rigorous microarchitectural investigation of upstream BOOM Issue #715, SpecHunter's automated VCD waveform tracer disambiguated physical registers, ROB identity, and LSU queue slots to demonstrate that the reported dependent load was actually suppressed at runtime by historical BOOM's load-miss-plus-poison register-read gate (`exu/core.scala`), resolving an ambiguous vulnerability report; (3) In systematic evaluations, SpecHunter achieved 100% vulnerability discovery in 1.5 attempts compared to 57.25% across 1,000 unguided random fuzzing seeds (8.48 attempts), generalized across an 8-program held-out corpus (100% detection and repair verification across 64 BOOM runs), and maintained 100% repeatability across 10 independent trials at an average cost of under $0.0006 per run. SpecHunter is open-sourced as a modular, composable CHIA block ready for upstream integration.

---

## 3. Quickstart Reproducibility (Judge's 1-Step Evaluation)

Judges can reproduce and verify the entire package in a single command on any Linux machine with Python 3.12 or 3.13:

```bash
# Clone repository
git clone https://github.com/Ryclic/SpecHunter.git
cd SpecHunter
git checkout feat/hackathon-paper-and-submission

# Run the complete reproducibility kit
./tools/run_reproducibility_kit.sh
```

### Verification Output Summary
- **Linting & Code Quality**: 85 files verified, 0 errors, 100% formatted.
- **Unit Test Suite**: 186 passed, 1 skipped, 3 deselected in 38s.
- **Cryptographic Seal Verification**: All 8 evidence streams verified 100%.
- **Paper Deliverable**: `paper/spechunter_micro2026.pdf` verified (strictly 4 pages, publication-ready format).
- **Interactive Presentation**: `docs/demo.html` verified (zero `<script>` tags, inline SVG waveform, formal microarchitectural taxonomy table).
- **Paper Sources**: `paper/spechunter.tex` and `paper/spechunter.typ` verified.
- **Submission Dossier**: `SUBMISSION.md` complete and verified.

---

## 4. Interactive Command Line Tools

```bash
# 1. Cryptographically verify all 8 evidence seals and paper deliverable
uv run spechunter verify

# 2. View cycle-accurate microarchitectural hazard timing diagram in terminal
uv run spechunter waveform

# 3. View formal Berkeley BOOM Spectre microarchitectural taxonomy
uv run spechunter taxonomy

# 4. Execute composable CHIA security audit block on Spectre-v1 benchmark
uv run spechunter audit --benchmark transient-cache --iterations 4

# 5. View interactive HTML demonstration
xdg-open docs/demo.html  # or open in any modern browser
```

---

## 5. Deliverable Inventory

| Deliverable | Location | Format / Verification |
|---|---|---|
| **4-Page Paper PDF** | [`paper/spechunter_micro2026.pdf`](paper/spechunter_micro2026.pdf) | IEEE/ACM 2-column format, strictly 4 pages |
| **Paper Typst Source** | [`paper/spechunter.typ`](paper/spechunter.typ) | Reproducible compilation via `tools/bin/typst` |
| **Paper LaTeX Source** | [`paper/spechunter.tex`](paper/spechunter.tex) | Standard LaTeX with `paper/references.bib` |
| **Interactive Demo** | [`docs/demo.html`](docs/demo.html) | Standalone HTML5 viewer, zero `<script>` tags, inline SVG |
| **Formal Taxonomy** | [`src/spechunter/taxonomy.py`](src/spechunter/taxonomy.py) | Full mapping of Spectre variants to BOOM Chisel RTL |
| **Composable CHIA Node** | [`src/spechunter/chia_nodes.py`](src/spechunter/chia_nodes.py) | `SpecHunterSecurityAuditBlock` on Ray runtime |
| **Reproducibility Kit** | [`tools/run_reproducibility_kit.sh`](tools/run_reproducibility_kit.sh) | Single-command automated verification |
| **Artifact Verifier** | [`tools/verify_all_artifacts.py`](tools/verify_all_artifacts.py) | Cryptographic seal checker |
| **Cryptographic Evidence** | [`docs/evidence/*.json`](docs/evidence/) | 8 SHA-256 bound evidence streams |

---

## 6. Cryptographic Provenance Manifest

| Seal File | Target Stream | Verification Method |
|---|---|---|
| `docs/evidence/vertex-boom-demo-seal-2026-09-11.json` | Live Vertex BOOM Run | SHA-256 report & binary binding |
| `docs/evidence/boom-attack-corpus-seal-2026-09-16.json` | 8-Program Held-Out Corpus | 64 BOOM execution digests |
| `docs/evidence/fixture-guided-vs-random-seal-2026-09-19.json` | Guided vs Random Fuzzing | 1,000 seed evaluation & code hash |
| `docs/evidence/vertex-fixture-repeatability-seal-2026-09-16.json` | 10-Trial Repeatability | 40 Gemini call transcripts & cost |
| `docs/evidence/chia-vertex-loop-seal-2026-09-16.json` | CHIA Ray Runtime Loop | Provenance and Ray/CHIA version |
| `docs/evidence/boom-load-gate-regression-seal-2026-09-16.json` | BOOM LSU RTL Repair | Chisel patch & Verilator regression |
| `docs/evidence/boom-issue-715-assessment-seal-2026-09-16.json` | Upstream Issue #715 Analysis | Clean baseline assessment |
| `docs/evidence/boom-issue-715-attachment-demo-seal-2026-09-20.json` | Issue #715 VCD Waveform | Cycle 3804-3811 signal trace & witness |
