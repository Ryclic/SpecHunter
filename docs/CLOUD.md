# Cloud operation policy

Project: `spechunter`. Available credit: **$300 GCP free trial**, superseding the
$750 request in the original proposal. Never upgrade, link/unlink, or otherwise
change billing. The checked-in policy is documentation, not a GCP spending cap.

This base implementation makes no paid API calls, enables no GCP services, and
creates no cloud resources. GitHub workflows have no GCP credentials and deliver
Python packages as workflow artifacts. There is no cloud deployment job.

Before a future paid experiment: verify the current free-trial status, remaining
credit and expiry in the console; consult current official SKU/model pricing;
record region, machine/model, maximum duration/tokens, disk/storage costs and a
conservative total estimate. Use a small initial experiment and reconcile actual
usage before expanding. Do not treat budget alerts as hard spending limits.
Do not run `chia up` until its complete resource plan and cleanup behavior have
been reviewed. Keep all paid integrations disabled until those checks are complete.

No billing access is necessary to run the local fixtures. CI consumes GitHub Actions
capacity, which is separate from GCP credits; jobs have timeouts and cancel stale runs.
