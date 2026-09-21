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
