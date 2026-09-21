# Cloud operation policy

Project: `spechunter`. Available credit: **$300 GCP free trial**, superseding the
$750 request in the original proposal. Never upgrade, link/unlink, or otherwise
change billing. The checked-in policy is documentation, not a GCP spending cap.

Vertex AI was enabled on 2026-09-10 for a bounded live integration check. Three smoke
runs used Gemini 2.5 Flash-Lite under one persistent $0.05 application ledger. The
ledger accounted for $0.0046509 across 35 entries, including one conservative $0.0004514
reservation retained after Vertex rejected an early schema before generation. This is
an application estimate; reconcile it with delayed Cloud Billing data before scaling.

The first BOOM build used one e2-standard-8 worker with a 200 GB balanced boot disk
for about 42 minutes on 2026-09-10. A four-core standard-disk worker existed only for
a few minutes during base-image diagnosis. Both were explicitly deleted, and no
Compute Engine instances remained afterward. Billing data is delayed, so these resource
times are operational records rather than a charged-cost claim. The resulting pinned
build and smoke evidence is recorded in `docs/evidence/boom-smoke-2026-09-10.json`.
No Compute Engine or Cloud Storage resources remain. GitHub workflows have no GCP
credentials and deliver Python packages as workflow artifacts.

A later privilege-gate run used another e2-standard-8 worker with the same 200 GB
balanced boot disk from approximately 18:52 to 19:22 UTC on 2026-09-10. It rebuilt the
pinned toolchain and simulator, ran the identical privilege payload on Spike and BOOM,
and was explicitly deleted after the hash-bound evidence was recovered. The instance
had no service account or API scopes and also carried a six-hour automatic deletion
limit. No Compute Engine instance remained after deletion.

The trusted-runner validation used an e2-standard-8 worker with a 200 GB balanced boot
disk from 04:33 to 05:51 UTC on 2026-09-11. It rebuilt the pinned simulator, exposed and
fixed the initial runtime integration, and ran the final eight-case matrix with four
parallel Verilator processes. The final baseline was clean. Evidence was recovered and
hash-verified before the worker and disk were explicitly deleted. No repaired simulator
was built because the baseline produced no repeatable violation. No Compute Engine
instance remained after deletion.

The seeded positive-control gate used another identically constrained e2-standard-8 worker
from 06:01 to 06:31 UTC on 2026-09-11. It rebuilt the same pinned simulator, ran 16 total
SmallBoomV3 executions across the mutated and repaired matrices with four parallel workers,
and produced deterministic violation-to-clean evidence. The recovered simulator hash
matched the prior privilege and secure-control evidence. The worker and 200 GB disk were
explicitly deleted after hash verification; no Compute Engine instance remained.

The live Vertex-agent demonstration used one identically constrained worker from
approximately 17:53 to 18:34 UTC on 2026-09-11. It rebuilt the pinned simulator, passed
the BOOM smoke test, and served the trusted runner for the discovery, minimization, repair
retest, and attacker-exhaustion loop. The successful evidence run made four Gemini 2.5
Flash-Lite calls accounting for $0.0006038 and 28 BOOM executions. Development for this
gate made 17 Vertex calls accounting for $0.0023706 in total, including preflights and one
failed-closed transport attempt. The worker and its 200 GB disk were explicitly deleted
after the evidence was sealed, and no Compute Engine instance remained.

The held-out attack-corpus gate used one identically constrained worker on 2026-09-16.
The pinned build and smoke gate took 575 seconds, then eight programs ran under both the
intentional mutation and repaired harness for 64 SmallBoomV3 executions. The recovered
evidence matched the previously validated simulator hash. The worker and 200 GB disk were
deleted immediately after artifact verification; the subsequent instance listing was empty.

Before a future paid experiment: verify the current free-trial status, remaining
credit and expiry in the console; consult current official SKU/model pricing;
record region, machine/model, maximum duration/tokens, disk/storage costs and a
conservative total estimate. Use a small initial experiment and reconcile actual
usage before expanding. The official Vertex pricing page listed standard Gemini 2.5
Flash-Lite text prices on 2026-09-10 as $0.10 per million input tokens and $0.40 per
million output tokens. Recheck after 30 days. Do not treat ordinary budget alerts as
hard spending limits.
Do not run `chia up` until its complete resource plan and cleanup behavior have
been reviewed. Keep all paid integrations disabled until those checks are complete.

No billing access is necessary to run the local fixtures. CI consumes GitHub Actions
capacity, which is separate from GCP credits; jobs have timeouts and cancel stale runs.
