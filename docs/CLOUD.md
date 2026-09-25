# Cloud operation policy

Project: `spechunter`. Available credit: **$300 GCP free trial**. Never upgrade,
link/unlink, or otherwise change billing. This document is policy, not a GCP spending cap.

No cloud access is required to run the local fixtures, tests, or the evidence verifier. Only
building and running BOOM on real hardware needs a worker. CI consumes GitHub Actions
capacity, which is separate from GCP credit; it has no GCP credentials and jobs have timeouts.

## Worker constraints

BOOM builds and runs use a single ephemeral Compute Engine worker at a time, provisioned with:

- machine type `e2-standard-8` (fall back to `e2-standard-4` if regional quota blocks it);
- a 200 GB balanced boot disk;
- **no service account and no API scopes**;
- a six-hour automatic deletion cap (`--max-run-duration=6h --instance-termination-action=DELETE`).

Every worker and its disk are explicitly deleted after evidence is recovered and hash-verified,
and the instance and disk listings are confirmed empty. `tools/boom/gcp_worker.sh` provisions a
worker under these constraints.

## Model calls

The Vertex AI agent loop uses Gemini 2.5 Flash-Lite. A locked application ledger reserves a
conservative cost before each call and reconciles it against Vertex usage metadata afterward,
halting at a hard cap. Ledger totals are an application estimate; delayed Cloud Billing data
remains authoritative for actual charges. Reference text pricing is $0.10 per million input
tokens and $0.40 per million output tokens; recheck the official Vertex pricing page before
scaling.

## Cost model

Reference on-demand prices (recheck the official pages before launch):

- `e2-standard-8` in `us-central1-a`:
  [$0.26804568/hour](https://cloud.google.com/products/compute/pricing/general-purpose).
- 200 GiB balanced persistent disk:
  [$0.000136986/GiB-hour](https://cloud.google.com/compute/disks-image-pricing).
- Egress at the [North America Premium Tier rate](https://cloud.google.com/vpc/network-pricing),
  at most $0.12/GiB.

Six hours of one worker plus its disk is about $1.77. Allowing up to 20 GiB of recovered
waveform/artifacts adds at most $2.40 of egress. A single diagnostic worker therefore fits a
provisional **$8 planning cap**; recover less or compress large traces, and if artifacts would
exceed 20 GiB, stop and reassess.

## Before any paid experiment

1. Verify the free-trial status, remaining credit, and expiry in the console.
2. Consult current official SKU and model pricing.
3. Record region, machine/model, maximum duration and tokens, disk/storage cost, and a
   conservative total estimate.
4. Run a small initial experiment and reconcile actual usage before expanding.
5. Do not treat ordinary budget alerts as hard spending limits, and do not upgrade billing.

Do not run `chia up` until its complete resource plan and cleanup behavior have been reviewed;
keep paid integrations disabled until these checks are complete.
