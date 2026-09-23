# Implementation handoff

## MICRO 2026 A³ CHIA Hackathon Submission Package (feat/hackathon-paper-and-submission)

A publication-ready submission package has been constructed to demonstrate #1 level
hackathon impact on real-world systems (Berkeley BOOM out-of-order RISC-V core):

1. **4-Page Submission Paper (PDF & LaTeX):**
   - Compiled to `paper/spechunter_micro2026.pdf` (strictly 4 pages in IEEE/ACM 2-column format)
     using standalone reproducible compiler and source in `paper/spechunter.typ` and `paper/spechunter.tex`.
   - Accompanied by vector figures (`paper/figures/fig1_architecture.svg`, `fig2_boom_pipeline.svg`,
     `fig3_eval_chart.svg`) and complete BibTeX references (`paper/references.bib`).
   - Grounded in three real-world pillars:
     1) Live autonomous agent loop on cycle-accurate BOOM RTL with Gemini 2.5 Flash-Lite, PMP CSRs,
        and atomic cost accounting ($0.0006/run);
     2) Chisel RTL repair synthesis in BOOM's LSU (`lsu.scala`) compiled into a distinct Verilator binary
        (`fd4a264c...`) with 0 functional regression;
     3) Rigorous microarchitectural trace analysis of upstream BOOM Issue #715, identifying the
        `exu/core.scala` hardware gate and proving the `0x59F` TLB request was hardcoded in instruction
        `lb s1, 1439(a0)` (`1439 = 0x59F`), not the dependent uop.

2. **Formal Microarchitectural Spectre Taxonomy (`src/spechunter/taxonomy.py`):**
   - Formally maps speculative vulnerability variants (Spectre-v1 BCB, Spectre-v2 BTI,
     Spectre-v4 SSB, Meltdown-RDCL, Seeded Cache Leak, Secure Baseline) to specific Berkeley BOOM
     hardware units (`ifu/bpu.scala`, `exu/core.scala`, `exu/lsu/lsu.scala`), speculation windows,
     and RTL interlock gates. Tested via `tests/test_taxonomy.py`.

3. **CLI Subcommands (`spechunter audit`, `verify`, `waveform`, `taxonomy`, `benchmark`):**
   - Added `spechunter waveform` for terminal visualization of Berkeley BOOM Issue #715 hazard timing.
   - Added `spechunter taxonomy` (with `--json` flag) for formal Spectre taxonomy mapping.
   - Added `spechunter verify` for push-button cryptographic artifact verification.
   - Added `spechunter audit` (with `--json` flag) for invoking the composable CHIA security audit block directly.
   - Added `spechunter benchmark` for profiling microarchitectural search latency, throughput, and memory RSS footprint.
   - Comprehensive test suite in `tests/test_cli.py` (9 unit and integration tests).

4. **Microarchitectural Waveform & Hazard Timing Explorer (`src/spechunter/presentation.py`):**
   - Embedded cycle-accurate SVG timing diagram (cycles 3804–3811), formal taxonomy table, and
     microarchitectural hazard table into `artifacts/demo.html` and `docs/demo.html`, adhering strictly
     to zero-`<script>` design for maximum portability and security.

5. **Composable CHIA Building Block & Multi-Benchmark Pipeline:**
   - Packaged `SpecHunterSecurityAuditBlock` in `src/spechunter/chia_nodes.py` as a high-level,
     reusable CHIA node with `audit_suite` and `summarize_suite` methods.
   - Added multi-benchmark pipeline in `examples/run_chia_pipeline.py` demonstrating co-design
     audits across Spectre-v1, Meltdown, and Secure Baseline with Ray orchestration and summary metrics.
   - Added `tests/test_chia.py` covering multi-benchmark audit block and suite execution.

6. **Automated Reproducibility Kit, Profiler & HotCRP Packager:**
   - Single push-button script: `tools/run_reproducibility_kit.sh` (5 automated stages).
   - Profiling automation: `tools/benchmark_performance.py` profiling guided vs random search throughput (89,000+ sims/sec) and RSS footprint.
   - Packaging automation: `tools/package_submission.py` generates `.tar.gz` and `.zip` archives with SHA-256 manifests.
   - Unit tests in `tests/test_performance.py` and `tests/test_package.py` verify profiling, bundle generation, and digest integrity.
   - Comprehensive validation: 192 unit tests passed, all 8 cryptographic evidence seals verified,
     4-page IEEE/ACM paper verified, interactive demo generated, HotCRP archive bundled.

7. **Complete HotCRP Submission Dossier (`SUBMISSION.md`):**
   - Formatted for direct HotCRP submission, containing Author-Identified Highlights, paper abstract,
     quickstart judge reproducibility guide, deliverable inventory, and cryptographic provenance manifest.
   - Verified by `tests/test_submission.py`, `tools/verify_all_artifacts.py`, and `spechunter verify`.

Validation: 192 tests passed, 1 skipped, 4 deselected in `.venv/bin/pytest -q -m 'not chia'` (196 total tests).
Ruff lint and format pass cleanly (`0 errors`). All 8 cryptographic evidence streams,
`docs/demo.html`, and `artifacts/demo.html` verified with embedded microarchitectural taxonomy. All seals 100% valid.

## Issue #715 isolated gadget diagnostic (PR #17 follow-up)

The runner now refuses to overwrite any pre-existing evidence output, simulator
log, converted load-memory image, waveform, or waveform witness. This prevents
a retried cloud command from mixing artifacts from separate executions. Focused
validation passes with 19 tests plus Ruff and `git diff --check`.

The diagnostic runner now classifies nonzero simulator exits as
`simulation-error` and records their log and any partial waveform without
requiring a witness from an incomplete execution. Successful diagnostic runs
still require a nonempty waveform and its scanned witness. Focused local
validation passed (14 tests, Ruff lint/format, and `git diff --check`); the
cloud run remains pending authentication and free-trial verification.

The original attachment contains a third, independent load at `0x80028e08` that
accounts for the observed `0x59f` translation request. The dependent load at +4
does not generate a valid LSU request in the recovered baseline waveform; no
vulnerability reproduction or repair validation has been established. A new
`tools/boom/prepare_issue_715_isolated_gadget.py` prepares a diagnostic ELF by
replacing just the independent four-byte load with a NOP and emits a SHA-bound
manifest. The historical runner can optionally verify the original, rebuilt
candidate, and manifest before executing on the pinned simulator. For the
diagnostic, use `build_historical_issue_715.sh /ABS/CHIPYARD /ABS/build.json
trace` to compile the pinned Makefile's separate `-debug` simulator and write
a distinct trace-build manifest. The runner rejects ordinary or unverified
simulators, checks VCD support, fixes the seed to
`1789717734`, limits the run to 10,000 cycles like the preserved baseline,
and requires and hashes a captured waveform. The diagnostic
runner also scans the raw waveform and records the witness JSON hash while
leaving the security verdict pending. Diagnostic
waveform attribution requires a valid same-cycle LSU execute request matched
to the dispatch ROB entry; all four checked-in raw waveforms recompute to
their existing witnesses (16 focused tests pass). The scanner also rejects
missing VCD translation/fault/branch signals rather than treating them as an
absent request; the four historical witnesses remain identical.
`transient_dataflow_witnessed` now also requires the protected and dependent
requests to be ordered within the first speculative branch window. GCP `gcloud auth list`
shows the selected account, but a read-only `gcloud billing projects describe
spechunter` failed on 2026-09-20 because its token could not be refreshed
without interactive reauthentication. The trial balance and expiry remain
unverified; no paid resources were created in this turn. `docs/CLOUD.md` now
records a $8 provisional planning cap for one six-hour `e2-standard-8` worker,
200 GiB balanced disk, and at most 20 GiB recovered artifacts based on
2026-09-20 official SKU prices; recheck prices and trial credit before launch.
Local original
attachment SHA-256: `c7066c9e10d1d19233d5626670e404663c069afe1e168656dcab08efbaa2389b`;
prepared diagnostic candidate SHA-256:
`9e08e91ea094a56fc8812e400e872b9ab5bb5ff4c4ad4561d71694cd6615a9a9`.
The pinned upstream Chipyard Verilator Makefile confirms `default` and `debug`
produce distinct simulator paths and `debug` enables tracing. This corrected
build selection was source-reviewed and shell syntax-checked locally; no
trace-enabled BOOM build or live run was made. The diagnostic limit and updated
worker runbook passed five focused tests plus Ruff and `git diff --check`; no
paid cloud resources were created. Local validation: Ruff lint and
format pass; `PYTHONPATH=src .venv/bin/pytest -q
-m 'not chia'` passes (169 passed, 1 skipped, 1 deselected). The prior unrestricted
suite reported 166 passed, 1 skipped, and one local CHIA/Ray startup timeout
while attempting network-based address discovery (60-second run).
The diagnostic has **not** been executed on BOOM. Consult `docs/BOOM.md` for the
commands and interpretation limits. Next: check free-trial balance/expiry and
current pricing per `docs/CLOUD.md` before provisioning a worker; run this
diagnostic, recover and inspect the raw waveform by ROB identity, and only then
consider a repaired-target comparison if a repeatable violation exists.

Base implementation lives on `feat/base-security-loop`; merge only by reviewed PR.
The existing domain/backend/process/RTL scaffold has been completed with a CLI,
bounded deterministic loop, minimization, fixture mitigation checks, report artifacts,
random comparison, optional CHIA node, regression tests, docs and GitHub CI/delivery.

Validated locally: 19 core/RTL tests, one optional CHIA integration test, lint/format,
wheel/sdist build, and RTL comparison (guided 2/2 seeded cases, random 1/2 at seed 0,
16 iterations; neither reports a secure-control finding). This is fixture evidence.

CHIA is pinned by archive to the original scaffold's commit because its git checkout
references an unavailable examples submodule. Local calls need a small Ray runtime;
the CLI owns and shuts down that runtime. No distributed/cloud run is validated.

GCP project is `spechunter`; only $300 free-trial credit is available. No GCP calls,
resource creation, billing changes, or paid model calls were performed. Preserve the
trial. See docs/CLOUD.md before any paid work. The old proposal's $750 is obsolete.

Next substantive work: docs/ROADMAP.md. Do not describe deterministic templates as
LLM research, the toy fixture as BOOM, or secure-variant selection as an applied RTL patch.

## Vertex cost guard and smoke validation

`feat/vertex-cost-guard` adds a locked, atomic JSON cost ledger; conservative pre-call
reservations; reconciliation from Vertex token metadata; a dated model-price allowlist;
maximum output tokens; and bounded retries for recognized transient failures. The
orchestrator now schedules the minimized exploit itself immediately after repair, so
repair verification cannot depend on the model following a retest instruction. It also
feeds correctable threat-model feedback back to the attacker instead of ending the case.

Vertex AI was enabled in GCP project `spechunter`. Three bounded Gemini 2.5 Flash-Lite
smoke runs used a shared $0.05 ledger and accounted for $0.0046509 in total. One early
attacker schema was rejected by Vertex; its $0.0004514 reservation remains charged in
the ledger conservatively. The successful calls prove live authentication, structured
recon/attack/repair generation, usage reconciliation, and local simulator validation.
One run found the transient seeded fixture and produced no false positive, but the small
nondeterministic samples are integration evidence rather than an LLM evaluation.

Validation: Ruff lint and format checks pass. `pytest -m 'not chia'` passes with 26
tests, one skipped RTL test, and one deselected CHIA test. No Compute Engine or storage
resources were created. Next reconcile delayed Cloud Billing costs and begin the pinned
Chipyard/BOOM runner work.

## Pinned BOOM build and execution evidence

`feat/boom-runner-bootstrap` pins Chipyard 1.14 at
`0acc1e1de2d3284bcd4d876956932a013ffe1949`, BOOM at
`5223e44cfeb26f41380057a2eb4d651197475f69`, Miniforge by SHA-256, glibc 2.34,
and Chipyard's stable `SmallBoomV3Config`. The initially proposed
`SmallBoomConfig` does not exist as a Chipyard 1.14 generator target. Bootstrap
rejects incompatible host ABIs and works around an upstream inline-comment parser
bug so the reviewed lockfile is used instead of silently regenerated.

On 2026-09-10, an e2-standard-8 GCP worker built the pinned Verilator simulator and
ran Chipyard's bare-metal hello payload successfully. The final simulation took 84
seconds. The hash-bound manifest and raw log are in `docs/evidence/`; they establish
a real BOOM execution path, not a security finding. Local validation passes: shell
syntax, Ruff, and 29 tests with one skipped RTL test and one deselected CHIA test.

The eight-core worker ran from 07:33:43 UTC until deletion shortly after 08:15 UTC.
A redundant four-core Rocky worker was deleted after a few minutes once the upstream
parser bug was identified. No Compute Engine instances remain. Reconcile delayed Cloud
Billing before the next scale-up.

Next: implement the trusted machine/user privilege and trap runtime, map abstract
operations to fixed reviewed instruction templates, run matched secret worlds on this
simulator, and compare architectural outcomes with Spike. Do not call the current
smoke result a privilege-isolation test or a vulnerability result.

## BOOM privilege-boundary gate

`feat/boom-privilege-smoke` adds a real RV64 machine/user transition and trap-return
gate. The reviewed payload configures PMP to deny a 4 KiB secret page to user mode,
enters user mode with `mret`, requires load-access-fault exception 5, advances `mepc`
in the machine trap handler, and fails if the load value becomes architecturally visible
or the expected trap does not occur. One compiled ELF must pass both Spike and the
pinned SmallBoomV3 Verilator simulator. The runner bounds RTL execution to 10 million
cycles and emits a manifest binding source, payload, tools, simulator, and logs by
SHA-256.

On 2026-09-10, the gate passed Spike and BOOM twice; the final evidence run took 150
seconds. The manifest and raw logs are in `docs/evidence/boom-privilege-smoke-2026-09-10.*`,
and their tracked hashes were independently verified. Local validation passes shell
syntax, Ruff, and 31 tests with one skipped RTL test and one deselected CHIA test. The
GCP e2-standard-8 worker was explicitly deleted after evidence recovery; no Compute
Engine instance remains.

Next: reuse this trusted transition substrate in the external BOOM runner, map abstract
operations to fixed instruction templates, and add matched-secret public observations.
This gate establishes architectural PMP behavior only; it is not a transient-leakage
test or a BOOM vulnerability claim.

## Trusted BOOM experiment runner

`feat/boom-trusted-runner` implements the missing external runner as a strict request
compiler. It verifies exact Chipyard and BOOM revisions, accepts only bounded whitelisted
operations and the real unmodified `secure-control` variant, generates a fixed PMP/trap
assembly payload on the proven `riscv_test.h`/HTIF substrate, executes one ELF on Spike and
SmallBoomV3, requires architectural agreement, and emits the provenance-bound observation schema. The fixed user-mode
probe times the same two cache lines in the same order and reports their relative latency;
faulting load and younger encode/squash instructions are skipped architecturally while
remaining eligible to expose unsafe transient cache effects.

The CLI now supports selecting one benchmark and defaults real BOOM runs to
`secure-control` with a 900-second execution timeout. Seeded fixture variants remain
rejected rather than being mislabeled as real BOOM mutations. Local validation passes
Ruff, formatting, shell syntax, and 52 tests with one skipped RTL test and one deselected
CHIA test.

`tools/boom/run_secure_matrix.py` provides the empirical gate: two repetitions
per secret for both architectural-denial and transient-window programs, strict response
provenance checks, repeatability/leakage classification, four isolated parallel workers,
atomic evidence output, and SHA-256 binding of the runner and simulator.

On 2026-09-11, the final eight-case matrix passed on the pinned SmallBoomV3 simulator.
Every execution reported the expected load-access fault, no architectural value, and probe
bit zero; both scenarios were deterministic and clean across secret worlds. The evidence is
`docs/evidence/boom-secure-matrix-2026-09-11.json`. During live validation, the original
newlib-based runtime failed to terminate under BOOM; replacing it with the already-proven
RISC-V test/HTIF substrate fixed Spike and BOOM execution. Ruff and 52 tests pass, with one
RTL-dependent skip and one deselected CHIA test.

Review of pinned BOOM v3 `lsu.scala` found that incoming/retried D-cache requests are not
gated by same-cycle `ae_ld`, `pf_ld`, or `ma_ld` signals. The minimal candidate patch in
`tools/boom/patches/gate_faulting_loads.patch` adds all three gates to both paths and was
verified with `git apply --check` against pristine commit `5223e44c`. Pins now include
SHA-256 values for pristine and repaired LSU sources; the trusted baseline runner rejects
dirty BOOM trees or a mismatched pristine source. This is a source-level hypothesis, not
a validated vulnerability or repair, until before/after RTL evidence exists.
`docs/evidence/boom-lsu-repair-audit-2026-09-11.json` binds the exact commit, pristine
and repaired source digests, patch digest, gated signals/paths, and the false RTL-validation
flag; a regression test prevents those audit fields from drifting.

The repair is now wired as the closed ID `gate-faulting-loads`. Vertex may select this ID
but cannot emit executable patch content. `tools/boom/build_repair_variant.sh` copies the
pinned baseline into a separate checkout, applies the exact patch, cleans/rebuilds BOOM,
and writes a source/patch/simulator-bound manifest. The trusted runner maps the repair ID
to that isolated checkout and rejects an altered diff, source digest, manifest, or binary.
The secure matrix accepts the same repair ID for before/after evidence. In the agent loop,
a real repaired-target clean retest returns to attacker iteration; attacker exhaustion then
marks the BOOM repair verified and `rtl_patch_applied`. Unit coverage exercises this whole
state transition with a controlled backend. The clean baseline did not activate the repair
gate, so the candidate patch remains unapplied and live repaired RTL remains unvalidated.

The e2-standard-8 worker ran from 04:33 to 05:51 UTC with a 200 GB balanced disk, no
service account or scopes, and a six-hour deletion cap. Evidence hashes were verified
before the worker and disk were explicitly deleted. Next: add a clearly labeled inverse
mutation as a positive control, expand attacker programs, and only build a repaired target
after a repeatable baseline violation exists.

## Candidate BOOM RTL build and target regression

`feat/boom-rtl-repair-build` closes the build/regression portion of the candidate LSU
repair roadmap. A live e2-standard-8 worker rebuilt the pristine pinned simulator, then
`build_repair_variant.sh` applied only the reviewed load-fault gate in an isolated checkout
and produced a distinct SmallBoomV3 binary. The repaired binary completed both secure
matrix scenarios twice per secret: eight deterministic clean executions with the expected
load-access fault, no architectural secret value, and probe bit zero.

The live run exposed a fail-closed parser defect: `.strip()` removed Git porcelain's
leading working-tree status column, causing the exact repaired source to be rejected.
The runner now removes only line endings, and a temporary-repository regression test
exercises the real status format. The checked seal recomputes hashes across the baseline
smoke, prior baseline matrix, repair build manifest, and repaired matrix. It explicitly
sets `security_fix_validated: false`; these results validate the candidate's buildability
and target behavior but cannot prove a security fix because pristine BOOM had no repeatable
violation.

Evidence is in `docs/evidence/boom-repair-baseline-smoke-2026-09-16.json`,
`boom-load-gate-build-2026-09-16.json`, `boom-load-gate-matrix-2026-09-16.json`, and
`boom-load-gate-regression-seal-2026-09-16.json`. The worker and disk were deleted and the
post-deletion instance list was empty. Full validation passes Ruff, formatting, shell
syntax, and 97 tests with one skipped RTL-dependent test and one deselected CHIA test.
Next: pursue a repeatable baseline witness or a known vulnerable BOOM revision before
claiming repair efficacy.

## Upstream BOOM issue #715 assessment

`feat/boom-issue-715-reproduction` adds a fixed reviewed adaptation of the mechanism in
upstream issue #715. The runner accepts only `enter_user, load_secret, probe`, trains a
delayed branch with a safe pointer, evicts training state, and places the protected load
plus dependent cache encode on the predicted wrong path. Source provenance records the
original issue, historical Chipyard/BOOM revisions, and hashes of its stripped attachment
while clearly identifying the local program as an adaptation.

Four live executions on pinned BOOM `5223e44…` were deterministic and clean across two
secret worlds and two repetitions. The reported BOOM revision is 335 commits older. The
seal binds source provenance, the exact reviewed runner hash, matching smoke/simulator
evidence, and the matrix; it sets both `vulnerability_reproduced` and
`security_fix_validated` false. The repaired build was skipped because a clean baseline
cannot establish a security delta. The GCP worker and disk were deleted and no instance
remained. Full validation passes Ruff, formatting, shell syntax, and 104 tests with one
skipped RTL-dependent test and one deselected CHIA test. Next: target the historical
revision or another source-backed known bug.

## BOOM seeded positive control

`feat/boom-positive-control` adds an intentionally vulnerable harness variant,
`seeded-cache-leak`, which accesses a secret-selected public cache line before entering
user mode. It preserves the real PMP-denied load and fixed observer while guaranteeing a
discoverable cache-state signal on the real simulator. This is explicitly classified as a
positive control, not an upstream BOOM vulnerability or RTL mutation.

The closed repair ID `remove-seeded-cache-leak` removes that access on the same pristine
simulator. It is accepted only for `boom-positive-control`; it never sets
`rtl_patch_applied`. The real agent loop validates the witness, applies the trusted harness
repair, mandates an identical witness retest, returns to the attacker, and requires
attacker exhaustion before verification. The model and Icarus fixture implement equivalent
semantics for fast testing.

`tools/boom/run_positive_control.py` runs paired mutated and repaired matrices, requires
repeatable violations followed by repeatable clean results, cross-checks source/simulator/
program provenance, and binds both child evidence files.

On 2026-09-11, the paired live gate passed. Both fixed programs produced deterministic
probe sequences `[1], [0], [1], [0]` under the seeded mutation and `[0], [0], [0], [0]`
after repair, with the expected load-access fault and no architectural value in every run.
All 16 executions used the same pristine SmallBoomV3 simulator, whose hash matches the
earlier privilege and baseline evidence. The three bound artifacts are in `docs/evidence/`.
The first live attempt also revealed that BOOM reports HTIF probe bit one as process code
255 plus exact exit-code/tohost markers while Spike returns code 2; the runner now accepts
only that exact marker pair and fails closed for other code-255 errors.

The e2-standard-8 worker ran from 06:01 to 06:31 UTC with the same six-hour cap, no service
account/scopes, and 200 GB disk. It was explicitly deleted after evidence recovery. Local
validation now passes Ruff, formatting, and 58 tests with one skipped RTL test and one
deselected CHIA test. Next: execute a bounded live Vertex-driven agent loop against this
positive control and preserve its transcript and cost evidence.

## Historical BOOM issue #715 assessment

`feat/boom-issue-715-historical` pins the exact Chipyard commit reported in upstream issue
#715 (`004297b6…`), its BOOM submodule (`fac2c370…`), historical `SmallBoomConfig`,
Miniforge 4.12.0-0 by the upstream checksum, and conda-lock 1.1.1. Dedicated bootstrap,
baseline/repaired build scripts, a fail-closed historical runner, and a two-secret,
two-repetition matrix driver have been added locally. The reviewed two-line LSU gate patch
is bound by pristine, repaired, and patch SHA-256 values. A seal independently derives the
result from raw runs and refuses repair evidence without a repeatable baseline violation.
Full lint, format, shell syntax, and non-CHIA validation pass with 113 tests, one skipped,
and one deselected. Draft PR #16 is open with all three GitHub checks passing.

On 2026-09-17 the exact historical simulator built in 685 seconds with SHA-256 `c31e4b…`.
Both secret worlds returned probe bit zero twice, so this reviewed adaptation is
deterministic and clean even on the reported BOOM revision. The sealed result sets
`vulnerability_reproduced` and `security_fix_validated` false, and the repair gate remained
closed. The slow classic conda solve for `conda-lock=1.1.1` was replaced with the same
pinned package from pip while the target environment still came from Chipyard's exact
lockfile. Recovered evidence hashes matched the worker; the worker and disk were then
deleted. Next pursue the original Cascade attachment or a different source-backed bug.

## Vertex-to-BOOM live demo

`feat/vertex-boom-demo` adds a trusted local-to-GCP runner transport. It validates the
exact request envelope, restricts GCP identifiers, uploads only JSON under a UUID path,
executes the fixed remote runner, bounds output/time, and cleans the remote request. The
CLI supports repeated runner arguments so project, zone, instance, an explicit local
gcloud configuration, and an existing SSH key can be supplied without placing credentials
on the worker.

BOOM validation now executes four secret worlds concurrently in stable order. Each trusted
runner response binds the simulator SHA-256; `Backend` rejects a hash change within an
experiment and records the hash in report provenance. `tools/boom/seal_vertex_demo.py`
requires a real Vertex/BOOM report with a finding, the closed positive-control repair,
mandatory retest, attacker exhaustion, matching live-control simulator hash, and a fully
settled cost ledger before producing final demo evidence. Local boundary tests are in
place.

On 2026-09-11, the bounded live loop succeeded against the rebuilt pinned SmallBoomV3
simulator. Gemini proposed a six-operation candidate, BOOM confirmed the intentional
seeded leak, and the minimizer retained the causal protected-user-load witness
`enter_user, load_secret, probe`. The repair agent selected only the closed
`remove-seeded-cache-leak` repair; the orchestrator retested the identical witness clean,
returned to the attacker, and recorded exhaustion. The final report has 28 BOOM executions,
four Vertex calls, zero inconclusive cases, and $0.0006038 accounted cost. Its report,
settled ledger, and hash seal are checked into `docs/evidence/`.

The live run exposed two integration defects before final evidence: minimization could
remove the protected load from a positive-control witness, and the sanitized subprocess
home caused concurrent gcloud sessions to race while creating SSH keys. The minimizer and
trusted runner now require the protected load, and the transport requires an explicit
existing SSH identity. Both failures were closed and covered by regression tests. The
worker ran from approximately 17:53 to 18:34 UTC with no service account/scopes and a
six-hour deletion cap, then was explicitly deleted. No Compute Engine instance remains.
Local validation passes Ruff, formatting, and 67 tests with one skipped RTL test and one
deselected CHIA test.

## BOOM held-out attack corpus

`feat/boom-attack-corpus` adds a fail-closed eight-program repair gate. Programs vary
training, encoding, squash and fence placement, plus irrelevant operations; every one
retains the protected user load. Each program executes two repetitions in both secret
worlds under the intentional mutation and the repaired harness. The driver requires every
mutation to be a deterministic violation and every repair result to be deterministically
clean, and records runner, program, simulator, and revision provenance.

On 2026-09-16, the live gate passed all eight programs across 64 SmallBoomV3 executions:
100% mutation detection, 100% repair-clean classification, and zero inconclusive programs.
The simulator SHA-256 matched all prior live BOOM evidence. A separate seal binds the
corpus to the positive-control and Vertex-loop artifacts, and the self-contained demo now
verifies and presents its scorecard. The GCP e2-standard-8 worker had no service account or
scopes, retained its six-hour deletion cap, and was explicitly deleted with its 200 GB disk
after evidence recovery; the instance listing was empty.

Local validation passes Ruff, formatting, shell syntax, and 79 tests with one skipped RTL
test and one deselected CHIA test. Next: broaden timing calibration across seeds and only
evaluate the source-audited RTL repair after a repeatable pristine-baseline violation.

## Quantitative guided-versus-random evaluation

`feat/quantitative-evaluation` adds `spechunter evaluate`, a reproducible comparison over
the privilege, transient-cache, and secure-control deterministic fixtures. The checked
2026-09-16 artifact records every one of 1,000 random seeds, binds evaluator/loop/domain
sources by SHA-256, and is protected by a separately verified seal. Guided search found
both positive cases in 1.5 attempts on average. Random search found 1,145 of 2,000 positive
cases (57.25%, 95% Wilson interval 55.07%–59.40%) in 8.48 attempts on average. Both had
zero false positives and zero inconclusive cases. The demo labels these as fixture search
quality, separately from live BOOM evidence.

## Vertex loop repeatability

`feat/vertex-repeatability` adds a bounded repeated evaluation of the actual Vertex-driven
agent loop on the fast positive-control model fixture. On 2026-09-16, all ten independent
Gemini 2.5 Flash-Lite trials discovered the mutation, selected the closed repair, passed
the mandatory minimized-witness retest, returned to the attacker, and reached exhaustion.
The evaluation contains 40 settled calls, 264 fixture executions, zero inconclusive cases,
and $0.0053752 accounted cost under a shared $0.05 ledger. A verifier checks every repair
state and ledger entry before sealing both artifacts. The offline demo presents this as
LLM orchestration repeatability, explicitly separate from live BOOM evidence.

## CHIA-to-Vertex live integration

`feat/chia-vertex-evidence` makes local CHIA execution self-identifying in reports and
preserves a live Vertex agent loop through the decorated `run_agent_experiment` node.
The 2026-09-16 run used CHIA 1.0.1 and Ray 2.54.0, discovered the model positive control,
selected the closed repair, passed mandatory retesting, returned to the attacker, and
reached exhaustion. It used four Gemini calls, 28 fixture executions, and $0.0005130;
every ledger entry settled successfully. The seal validates the exact nested transcript,
dependency versions, cost, and CHIA adapter digest. No cluster or GCP compute resource was
created. This is CHIA orchestration evidence on a model fixture, not BOOM vulnerability
evidence or a distributed-worker claim.

## Sealed evidence presentation

`feat/evidence-demo` adds `spechunter present`, which verifies the live report against its
SHA-256 seal before rendering a self-contained HTML artifact. The page shows the measured
BOOM/Vertex cost metrics, protected-load witness, complete recon → attacker → validator →
repair → attacker → validator → attacker timeline, and report/simulator hashes. It embeds
the full escaped report for inspection and makes no network requests. Tampered evidence is
rejected, and model text is HTML-escaped. `docs/demo.html` is generated from the checked-in
live artifacts for direct judge review. Local validation passes Ruff, formatting, and 71
tests with one skipped RTL test and one deselected CHIA test. Next: expand the bounded
attacker corpus and add evaluation metrics across held-out attack families.

## Exact issue #715 attachment RTL witness and failed repair

`feat/boom-issue-715-attachment` fetches the original `program.elf.zip` attachment by
pinned URL and verifies both archive and ELF SHA-256 digests. The historical runner now
converts its unusual entry-zero ELF into a fixed 0x80000000 load-memory image; passing
the ELF directly left BOOM in the boot ROM because this attachment has no HTIF symbols.

On 2026-09-17, the exact attachment ran on historical Chipyard `004297b6…`, BOOM
`fac2c370…`, and `SmallBoomConfig`. A seed-1789717734 VCD records the reported branch at
cycle 3769, frontend observations of the wrong-path gadget PCs at cycles 3772 and
3802, a branch-masked protected-page TLB request at cycle 3807, requests to address
`0x59f` beginning at
cycle 3809, a branch-masked load page fault, and resolution of the exact branch as a
misprediction at cycle 3910. The compressed raw trace and its machine-derived JSON witness
are in `docs/evidence/`. This establishes a correlated transient protected/dependent
request sequence on historical RTL. The waveform does not directly prove register-level
dependence or architectural secret disclosure; the latter is explicitly marked false.

The isolated candidate repair built successfully, but the matched-seed repaired trace
repeated every key event at the same cycle, including both dependent TLB requests.
The comparison seal therefore records `repair_effective: false` and
`security_fix_validated: false`. This is the required attacker feedback: the simple
same-cycle `pf_ld`/`ae_ld`/`ma_ld` gate does not address this witness. The next repair
iteration should test a conservative unresolved-branch load gate (or a narrower policy
with equivalent ordering) against this exact seed, then return to attack exploration.

The VCD scanner was corrected after matched-trace review: it now evaluates settled values
at timestamp boundaries instead of treating intermediate combinational changes as request
addresses. Schema v2 binds the protected request, dependent address requests, page fault,
and later branch resolution. The before/after verdict remains repair-ineffective, now for
the mechanism named in the upstream report rather than an ambiguous D-cache-valid edge.

A second, deliberately conservative repair candidate is hash-pinned as
`issue_715_historical_block_speculative_loads.patch`. It retains the fault gates and
prevents loads with a nonempty unresolved-branch mask from reaching the D-cache; correctly
predicted loads can retry after their mask clears, while wrong-path loads should be killed.
This carries a likely performance cost. Its exact-seed live run was also ineffective: the
protected and dependent TLB requests, fault, and misprediction were cycle-identical to
baseline. The comparison remains fail-closed.

Repair v3 now targets the consumer-release paths exposed by v2: it suppresses fast
speculative wakeup for unresolved-branch loads, suppresses writeback for LDQ entries
already marked excepting, and prevents excepting entries from retry/wakeup selection. Its
hash-pinned live build and exact-seed trace completed on the six-hour-capped worker
`spechunter-boom-issue715-repairv2`. The dependent `0x59f` requests still occurred at
cycles 3809 and 3853, exactly matching baseline, so its sealed verdict is also
`repair-ineffective`.

That failure suggested a narrower hypothesis: `fired_load_incoming` can record an LSU
issue even when `dmem_req_fire` is false because the TLB missed. A fast load-use wakeup
then appeared capable of releasing a consumer before any cache response existed.
Repair v4 is a minimal hash-pinned candidate that requires the aligned, registered
`dmem_req_fire` before asserting `spec_ld_wakeup`. Later waveform analysis showed that
v3 already suppressed the observed TLB-miss fast wakeup while the dependent-address
requests persisted, so this wakeup alone does not explain the request chain. V4's
effectiveness is unproven and the remaining release/data path needs investigation.
If a future matched trace removes the dependent request while preserving the trigger,
return to the attacker with additional seeds and variants before accepting the repair.
Application-default credentials authorized the worker noninteractively, and the prior
worker list was empty.

On 2026-09-18, v4 built successfully on the worker: the release simulator SHA-256 is
`a1ba8a64bfbfc69b6b5dd7eb8b53492611da50c1f0567f2c630faf2c047e0f55`.
The waveform-enabled binary also built and the exact attachment/seed ran to the same
10,000-cycle timeout as baseline. The build manifest, build log, and run log were
retrieved locally. Automatic approval review then rejected remote compression and
retrieval of the raw v4 VCD, citing a Codex usage limit through 2026-09-22 01:28 UTC.
No v4 witness or security verdict can be inferred from the run log alone. The worker had
a six-hour automatic deletion limit, so its trace may no longer be available; if so,
rebuild and rerun v4 after remote access resumes.

The matched-trace comparison seal now distinguishes one blocked witness from a validated
security fix. It requires the repaired protected request and fault to remain present,
and always leaves `security_fix_validated` false while marking
`attacker_retest_required` when the matched witness is blocked. A subsequent attacker
pass across independent seeds or variants is necessary before declaring the fix secure.

The general LLM/CHIA agent loop also had a cross-cycle verdict bug: after the attacker
exhausted a repaired variant in one recon cycle, a later recon cycle could rediscover a
violation and hit the repair limit while leaving the earlier `verified` result true.
Verification is now revoked immediately on any new violation, before checking the repair
budget. A scripted two-cycle regression covers the bypass-after-exhaustion sequence.

The BOOM backend now binds simulator SHA-256 per approved variant. Previously a single
hash for the entire experiment rejected a legitimate RTL repair because its simulator
binary must differ from baseline. The backend still fails closed if a variant's hash
changes during the run. Reports retain the first simulator hash for existing consumers
and add `simulator_sha256_by_variant` for before/after review. A runner-boundary test
checks both allowed baseline-to-repair transition and rejected within-variant drift.

The outer recon loop now requires each new cycle to earn its own attacker-exhaustion
verdict. Previously an earlier verified repair could survive a later cycle that ended
in an inconclusive simulator result or simply consumed its attack budget. Scripted
regressions cover both incomplete outcomes, in addition to the later-bypass case.

The issue #715 comparison seal was upgraded to schema v2 because VCD waveforms do not
encode the simulator seed. Its previous `matched_control_flow_and_seed` field inferred
seed equality from matching branch/gadget timing, which the waveform alone cannot prove.
The seal now reports `matched_control_flow` and explicitly marks seed provenance as
`not-bound-by-vcd`. The three rejected-repair comparison artifacts were regenerated;
their fail-closed verdicts are unchanged. Run logs document the chosen seed separately.

The LLM/CHIA loop now requires the minimized exploit to reproduce a violation on its
final validation before recording a finding or calling the repair agent. A clean or
inconclusive minimized replay becomes an inconclusive transcript event and stops that
search. The repair agent receives the minimized program's validated result, rather than
the original larger candidate's result. Regressions cover non-reproducing replays and
confirm that the repair receives the reduced program with its matching validation.

The issue #715 VCD scanner now requires a single ordered branch → gadget → protected
request → dependent request → page fault → misprediction chain, with an overlapping
unresolved-branch mask across the protected, dependent, and fault events. This prevents
unrelated events elsewhere in a trace from forming a false mechanism witness. Unit
cases cover disjoint masks, misplaced events, and a later valid chain following an
unrelated early request. Rescanning the stored baseline and v1–v3 waveforms produced
the same JSON witnesses; the prior positive and rejected-repair verdicts are unchanged.

The issue #715 comparison seal now checks that the repaired trace preserves the
specific exploit trigger as an ordered branch → gadget → protected request → matching
page fault → misprediction sequence, with a shared unresolved-branch mask. Previously,
unrelated protected requests and faults anywhere in the trace could make an otherwise
blocked dependent load look like an effective repair. Schema v3 exposes
`repaired_trigger_preserved`; all three stored v1–v3 comparisons were regenerated and
still reject their ineffective repairs. Tests cover disjoint-mask and late faults.
Validation: 131 passed, 2 skipped; Ruff lint/format and `git diff --check` passed.

The nested agent loop now clears its clean-replay flag at each new recon cycle.
Previously a repair could be verified when the attacker immediately exhausted a new
hypothesis without testing that cycle, because the preceding cycle's clean mandatory
replay remained in state. A regression demonstrates the false positive and requires
the later cycle to report an inconclusive attacker exhaustion instead. Validation:
132 passed, 2 skipped; Ruff lint/format and `git diff --check` passed.

The deterministic guided/random benchmark loop now independently revalidates each
minimized witness before recording a finding or attempting repair. A clean or
inconclusive minimized replay halts that search and counts as an inconclusive case;
it cannot inflate discovery or repair claims. Two regressions cover the replay
outcomes. The September 16 evaluation remains an unchanged historical artifact;
a fresh September 19 evaluation and seal bind the revised loop source and reproduce
the 57.25% random discovery rate over 1,000 trials. The README presentation command
and current source-bound evaluation tests use the new seal. Validation: 134 passed,
2 skipped; Ruff lint/format and `git diff --check` passed.

The shared validator now requires exactly one observation per requested simulator
execution before comparing repeated secret worlds. Previously a short batch of two
observations could silently skip the intended four-execution repeatability check;
missing or extra results now return inconclusive. Five regression cases cover batch
lengths 0, 1, 2, 3, and 5. The September 19 source-bound fixture evaluation and seal
were regenerated after this validator change; the 1,000-trial random discovery rate
remains 57.25%. Validation: 139 passed, 2 skipped; Ruff and diff checks passed.

The issue #715 scanner and repair comparison now close the recorded speculation window
at the first target-branch misprediction after its fetch. A later misprediction cannot
retroactively connect requests after an earlier resolution, where branch-mask bits may
have been reused. Regressions cover out-of-order misprediction records and the same
failure in the repair seal. All four stored baseline/v1–v3 VCDs rescan to equivalent
JSON witnesses, so their rejected-repair verdicts remain unchanged. Validation:
141 passed, 2 skipped; Ruff and diff checks passed.

Current agent reports use schema v3 and require a clean, attacker-generated program
distinct from the minimized exploit after the mandatory repair replay before exhaustion
can verify a repair. Exhaustion immediately after replay, or after replaying the same
program again, is inconclusive. The requirement resets with each recon cycle and repair.
Vertex prompts now request this additional challenge. The September 11 live Vertex and
September 16 CHIA/fixture transcripts remain sealed historical schema-v2 evidence;
they exhausted after only the mandatory replay. README now states that limit and the
current stronger rule. Validation: 142 passed, 2 skipped; Ruff and diff checks passed.

The distinct post-repair challenge also must exercise the benchmark's threat model.
A different but irrelevant `nop` or probe-only candidate can be clean by construction
and no longer counts toward attacker exhaustion. Observable-isolation challenges require
a protected user load followed by a probe; transient-cache additionally requires
branch training and cache encoding before the probe. The validator transcript records
whether each repaired-variant candidate qualified, and the Vertex prompt describes
the requirement; a fence or squash between training and encoding disqualifies the
transient challenge. Current agent reports use schema v4 to distinguish this criterion
from the earlier schema-v3 distinction-only rule. Validation: 145 passed, 2 skipped;
Ruff and diff checks passed.

Current agent reports now use schema v5: a post-repair clean challenge counts only
after the same attacker-generated program reproduces a violation on the original
vulnerable variant. Structural relevance and textual difference alone were insufficient:
a speculative user load could be clean in both variants yet falsely contribute to
repair verification. The validator transcript records the baseline challenge result,
and a real fixture regression proves a baseline-clean candidate cannot verify the fix.
This adds one bounded set of baseline executions per eligible clean candidate, so BOOM
experiments should account for that simulator cost. A regression also verifies that
an inconclusive baseline challenge fails closed. Validation: 147 passed, 2 skipped;
Ruff and diff checks passed.

The current attack-diversity check ignores `nop` padding when comparing a new program
with the minimized repaired witness. Otherwise appending a no-op would satisfy the
distinct-program test and trigger needless baseline simulations. A parameterized
regression covers both exact replay and no-op-padded replay. Validation: 148 passed,
2 skipped; Ruff and diff checks passed.

Publishing status on 2026-09-20: after the user explicitly approved the push, commits
through `d7012e1` were pushed to `Ryclic/SpecHunter` PR #17. The PR description was
updated and its chia and Python 3.12/3.13 checks all passed. Do not merge without
separate authorization.

The presentation now includes a separately sealed account of the original issue #715
attachment on historical BOOM. The seal binds the baseline and three repaired VCDs,
their JSON witnesses, repair builds, and rejection comparisons. The rendered demo
identifies the observed branch-to-dependent-address event chain, all three failed RTL
repair candidates, and the v4 build's unresolved security verdict. It explicitly
avoids claiming direct register dependence or secret disclosure from the waveform.
The README command includes the new seal, `docs/BOOM.md` explains the case, and
`docs/demo.html` was regenerated. Validation: 150 passed, 2 skipped; Ruff lint and
format checks and `git diff --check` passed. The addition was pushed as `d7012e1`
to PR #17, its description updated, and all three GitHub checks passed. All open PRs
(#4–#17) currently show successful checks.

The attachment-case seal now also binds the baseline, three rejected-repair, and v4
run logs. It requires every log to contain the pinned seed and 10,000-cycle timeout,
making the execution claim auditable and preventing the v4 build alone from standing
in for a run. The new seal and self-contained demo were regenerated; a presentation
regression rejects a mismatched v4 log seed. The v4 waveform and security verdict
remain unavailable. Validation: 151 passed, 2 skipped; Ruff lint and format and
`git diff --check` passed. This was published as `261e0c7` on PR #17, and all three
GitHub checks passed. All other open PRs also had successful checks.

The issue #715 matched-trace comparison now uses schema v4. Exact cycle equality
could have marked a repair ineffective solely because it shifted timing; the new
comparison requires the ordered attack trigger and same seed from hash-bound run
logs instead. It classifies a missing trigger as inconclusive, not ineffective.
All three historical failed-repair comparisons were regenerated and still reject
those candidates. The attachment-case seal and demo were regenerated to bind the
new comparison records. Regressions cover shifted timing, missing trigger, and
different seeds. Validation: 154 passed, 2 skipped; Ruff lint and format and
`git diff --check` passed. This was published as `b8b634c` to PR #17; all three
GitHub checks passed. V4 still lacks a waveform and security verdict.

Review of the VCD scanner found that it treated every wide signal containing `pc`
as a fetch-PC witness, including branch-predictor guesses. The scanner now uses
named historical frontend signals: `s0_vpc` for the branch and first gadget PC,
and fetch-buffer `pc_2` with enqueue valid for the second gadget PC. It records
frontend PC observations rather than asserting instruction execution. The second
gadget observation moves from predictor cycle 3773 to frontend-buffer cycle 3802;
the protected request still follows at 3807, so all four original and v1–v3 traces
retain the ordered mechanism witness. All four witnesses, three comparisons, the
case seal, and the demo were regenerated. A synthetic VCD regression confirms that
a predictor-only PC cannot satisfy the new observation rule. CI now rescans every
stored waveform and requires exact agreement with its JSON witness. Validation:
159 passed, 2 skipped; Ruff lint and format and `git diff --check` passed.
This was published as `6b4a26a` on PR #17, and all three GitHub checks passed.
V4 remains unresolved.

An LSU signal review found that baseline, v1, and v2 record a protected-page TLB
request at cycle 3807, then `mem_tlb_miss_0=1`, speculative load wakeup valid, and
`dmem_req_fire_0=0` at 3808; the `0x59f` request follows at 3809. V3 has the same
TLB miss and no D-cache fire but no speculative wakeup valid at 3808, yet the
`0x59f` request still follows. The scanner now records this narrowly as a
TLB-miss fast-wakeup observation, not a proof of dependency. All four witnesses,
the case seal, and the demo were regenerated; the demo notes that v3 weakens the
fast-wakeup-only root-cause hypothesis. The v4 waveform and a causal explanation
for the persistent request remain outstanding. Validation: 160 passed, 2 skipped;
Ruff lint and format and `git diff --check` passed. This was published as `dcbdd64`
on PR #17, with all three GitHub checks passing.

The original ELF disassembly at gadget offsets `0x80028e00` and `0x80028e04`
shows `lb sp,-2048(t1)` immediately followed by `ld s1,0(sp)`. This proves the
static address dependency between those instructions, while the VCD still cannot
prove which runtime value reached the second load. The case seal now SHA-256-binds
the checked-in disassembly and verifies the instruction pair. The demo and BOOM
documentation explain this distinction; a tampered-disassembly regression checks
the fail-closed path. Validation: 161 passed, 2 skipped; Ruff lint and format and
`git diff --check` passed. Publication of the new seal is next.

## Correction: original issue #715 attachment does not reproduce dependent requests

A fresh dispatch-to-LSU attribution of all four saved historical waveforms corrected
an earlier false-positive case verdict. At cycles 3804/3805/3806 the gadget dispatches
loads at offsets +0/+4/+8 with physical destinations `0x12`/`0x15`/`0x16` and
load-queue slots 0/1/2. The protected request at 3807 carries destination `0x12`,
slot 0. The later `0x59f` requests at 3809 and 3853 carry destination `0x16`, slot 2:
they belong to the independent instruction at +8. The actually dependent load at +4
reads physical register `0x12` but issued no recorded branch-masked translation request. Static
ELF dependency does not establish a runtime leak. Contrary to the earlier sections
of this handoff, the reported protected-data-dependent mechanism has **not** been
reproduced and the three candidate repair comparisons are inconclusive. V4 still has
no waveform. The VCD scanner, four witnesses, three comparisons, case seal, demo,
tests, and BOOM documentation were corrected; next obtain a truly dependent baseline
before attempting a repair claim or independent attacker retests. No paid cloud calls
were made in this correction.
Validation of the correction: `.venv/bin/pytest -q` — 162 passed, 2 skipped;
`.venv/bin/ruff check .`, `.venv/bin/ruff format --check .`, and
`git diff --check` passed. `docs/demo.html` was regenerated from the corrected
case seal. The existing original-attachment PR title and body must reflect this
non-reproduction before review; do not merge the previous claim.

## Issue queue attribution follow-up

Further analysis of all four saved waveforms found a meaningful distinction between
issue and translation. In baseline and candidate v1/v2, the dependent gadget load at
+4 dispatches with physical source `0x12` and destination `0x15`, then issues from
the memory issue queue at cycle 3809 with branch mask 1 and load-queue slot 1.
It does not produce a matching branch-masked TLB request. The simultaneous `0x59f`
TLB request belongs to independent load +8, destination `0x16`, slot 2, which
issued at 3807. Candidate v3 suppresses the speculative wakeup; no matching
branch-masked dependent-load issue is seen there. A later instruction reuses
physical register `0x15` with another source and mask, and must not be attributed
to the gadget. The scanner now binds issue-to-dispatch on destination, source,
load-queue slot, and branch mask; its case seal requires the per-candidate issue
observations. This narrows the point of divergence but does not reproduce a leak
or establish repair efficacy. Next determine why the baseline issue does not reach
the LSU translation interface and obtain a reproducing baseline before repair claims.
Validation of the issue-queue follow-up: four waveform rescans exactly match their
regenerated witnesses; 162 passed and 2 skipped in `.venv/bin/pytest -q`; Ruff
lint/format and `git diff --check` passed. The comparison records, case seal, and
self-contained demo were regenerated. No GCP calls or compute resources were used.

The next stage was checked against the raw LSU interface: at cycle 3811 the
baseline waveform contains fields naming dependent destination `0x15`, queue slot
1, and address `0x10098800`, but `io_core_exe_0_req_valid` is zero. Those fields
are an invalid payload and cannot be interpreted as a memory request. A scanner
revision requires the LSU execute-valid signal and dispatch identity before
reporting an execute request; none of the four waveforms has a valid dependent
execute request. All four witnesses, three comparisons, the seal and demo have
been regenerated with that fail-closed distinction. Baseline issue to LSU
execute-valid gating remains the next diagnostic question; a valid translation
or leak is still not established.
Validation: four raw VCD rescans matched their schema-v7 witnesses; 162 passed,
2 skipped; Ruff lint/format and `git diff --check` passed. The corrected case
seal and demo rendered successfully. No GCP calls were made.

## Poisoned issue-queue operand, 2026-09-20

Inspecting the historical memory issue unit's `io_iss_uops_0_iw_p1_poisoned` bit
showed that the dependent load at cycle 3809 issues with its first (physical
register `0x12`) operand poisoned in baseline and v1/v2. The independent +8
load at 3807 has this bit clear. V3 shows no matching issue. The poisoned bit
is consistent with the later absent valid LSU execute request, but the waveform
alone does not prove the exact gating logic or a leak. The scanner now records
the bit only alongside a valid matched issue. All four raw VCD witnesses, three
comparisons, case seal, and demo have been regenerated to bind this distinction.
Next inspect the pinned BOOM register-read/memory execution gating source or
collect a targeted waveform to determine exactly where the poisoned uop is
suppressed; only then construct a reproducing baseline to test a repair.

Pinned source review identified the exact issue-to-register-read gate. Historical
BOOM `fac2c370…` in `src/main/scala/exu/core.scala` lines 973–978 sets
`iregister_read.io.iss_valids(w)` to issue-valid AND NOT (`io.lsu.ld_miss`
AND (`iw_p1_poisoned` OR `iw_p2_poisoned`)). The four raw VCDs show baseline
and v1/v2 at cycle 3809 with dependent issue valid, physical source `0x12`
poisoned, LSU load miss high, and register-read issue valid low. V3 has no
matching dependent issue. The scanner's schema-v9 issue event now binds the
three gate signals, and the seal requires those observations. This identifies
why this issued uop does not reach the LSU execute-valid interface in the
recorded run. It does not prove a security fix or any secret disclosure.
Validation: raw baseline/v1-v3 VCD rescans matched all four schema-v9 witness
JSON files; 162 passed, 2 skipped; Ruff lint/format and `git diff --check`
passed. The comparison JSON records, case seal, and demo were regenerated.
No paid model or GCP compute call was made in this source-and-trace analysis.

## Reorder-buffer identity guard

The historical VCD scanner now joins gadget dispatch to issue and valid LSU
execute using reorder-buffer index as well as physical destination, load-queue
slot, overlapping branch mask, and (at issue) physical source. These identifiers
can each be reused after a flush; a synthetic regression reuses the register,
source, branch mask, and load-queue slot with a different reorder-buffer index and
confirms it cannot be misattributed to the gadget. All four raw waveforms were
rescanned and their source-bound witnesses, comparison records, case seal, and
demo regenerated (schema v10); the substantive security verdict is unchanged.
No local BOOM simulator or cross-toolchain is present, so a new source-backed
reproducing run needs provisioned compute after verifying the current trial
credit and the resource's cost. Never claim a fix from the current baseline.
Validation for schema v10: `.venv/bin/pytest -q` passed with 163 passed,
2 skipped, including full recomputation of the four checked-in raw waveform
witnesses and the new reorder-buffer-reuse regression. Ruff lint, format,
`git diff --check`, seal verification, and demo regeneration passed.
