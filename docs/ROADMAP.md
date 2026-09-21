# Research work beyond the base implementation

1. Add an explicitly pinned inverse mutation benchmark as a positive control for the live
   runner. The 2026-09-11 repeated-secret baseline was clean, so the source-reviewed load
   gate was correctly left unapplied and unverified.
2. Calibrate and repeat the binary relative-cache probe across more attack programs and
   seeds, then evaluate the candidate repair only if a repeatable baseline violation exists.
3. Reconcile the first Vertex smoke ledger with delayed Cloud Billing data, then improve
   hypothesis quality and evaluate stronger model/configuration choices. Persistent cost
   reservations, dated price verification, output limits, and bounded transport retries
   are implemented.
4. Replace fixture mitigation selection with actual RTL patch generation and target regressions.
5. Validate distributed CHIA execution on local workers before considering GCP workers.
6. Evaluate multiple seeds, known bugs, held-out hypotheses, functional regressions,
   and confidence intervals; the current template baseline is only a pipeline smoke test.
