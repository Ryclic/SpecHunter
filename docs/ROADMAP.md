# Research work beyond the base implementation

1. **Completed 2026-09-11:** Run the LLM provider against the empirically validated BOOM
   positive control and preserve a cost-bound transcript showing discovery, repair
   selection, mandatory retest, and attacker exhaustion. The sealed evidence and
   self-contained demo are checked in under `docs/`.
2. **Completed for the positive control 2026-09-16:** repeat the binary relative-cache
   probe across eight held-out attack programs, two secrets, and two repetitions before
   and after repair. The 64-execution scorecard is sealed to the live Vertex evidence.
   Calibrating more timing seeds and evaluating the candidate RTL repair still require a
   repeatable baseline violation.
3. Reconcile the first Vertex smoke ledger with delayed Cloud Billing data, then improve
   hypothesis quality and evaluate stronger model/configuration choices. Persistent cost
   reservations, dated price verification, output limits, and bounded transport retries
   are implemented.
4. Replace fixture mitigation selection with actual RTL patch generation and target regressions.
5. Validate distributed CHIA execution on local workers before considering GCP workers.
6. **Completed for deterministic fixtures 2026-09-16:** compare guided search with 1,000
   random seeds, record per-seed trials, false positives, attempts and executions, and
   report Wilson intervals. Multi-seed LLM evaluation and additional known BOOM bugs remain.
