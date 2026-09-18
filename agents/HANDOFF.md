# Implementation handoff

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
cycle 3769, both wrong-path gadget PCs at cycles 3772–3773, a branch-masked protected-page
TLB request at cycle 3807, dependent requests to the loaded value `0x59f` beginning at
cycle 3809, a branch-masked load page fault, and resolution of the exact branch as a
misprediction at cycle 3910. The compressed raw trace and its machine-derived JSON witness
are in `docs/evidence/`. This proves transient protected-to-dependent address dataflow on
historical RTL; it does not prove an architectural secret disclosure, which the evidence
explicitly marks false.

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
hash-pinned live build is in progress on the six-hour-capped worker
`spechunter-boom-issue715-repairv2`; no v3 security verdict exists yet. Application-default
credentials authorized this worker noninteractively, and the prior worker list was empty.
