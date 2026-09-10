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
