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
