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
   hypothesis quality and evaluate stronger model/configuration choices. A ten-trial
   Gemini 2.5 Flash-Lite fixture-loop repeatability gate now passes 10/10 with sealed
   transcripts and costs. Persistent reservations, dated prices, output limits, and
   bounded retries are implemented; delayed Cloud Billing reconciliation remains.
4. **Completed for the source-reviewed candidate 2026-09-16:** build the exact LSU patch
   in an isolated checkout and run eight target-regression executions on the distinct
   repaired simulator. Both scenarios were deterministic and clean. The sealed result is
   deliberately classified as build/regression evidence rather than a validated security
   fix because the pristine baseline had no repeatable violation to eliminate. Actual
   synthesis of a new patch from model output and a baseline-to-repaired security delta
   remain future work.
5. **Completed locally 2026-09-16:** execute the real Vertex agent loop through the pinned
   CHIA node on an owned Ray runtime and seal dependency, transcript, repair, and cost
   provenance. Multi-worker CHIA deployment remains future work; no cluster is provisioned.
6. **Completed for deterministic fixtures 2026-09-16:** compare guided search with 1,000
   random seeds, record per-seed trials, false positives, attempts and executions, and
   report Wilson intervals. Multi-seed LLM evaluation and additional known BOOM bugs remain.
7. **Completed current-pin assessment 2026-09-16:** adapt the mechanism from upstream BOOM
   issue #715 into the reviewed PMP/HTIF harness and execute two secrets twice on the pinned
   simulator. The result was deterministic and clean, so no repair was activated and the
   seal explicitly records that neither a vulnerability nor fix was validated. Reproducing
   the exact historical revision or assessing another known bug remains future work.
8. **Completed historical assessment 2026-09-17:** built the exact reported Chipyard/BOOM
   revisions in a hash-pinned environment and ran the fixed issue #715 adaptation twice per
   secret. All four executions returned probe bit zero. The sealed deterministic-clean
   result does not reproduce the upstream report and therefore does not validate a repair.
   Executing the original stripped Cascade attachment or another source-backed bug remains.
