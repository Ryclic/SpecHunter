# External BOOM runner boundary

The bundled RTL is a small state machine, not BOOM. Real BOOM experiments require
an independently built, pinned Chipyard/BOOM checkout, Verilator, RISC-V compiler,
privilege/trap runtime, and public-observer trace instrumentation. These are not
bundled or downloaded automatically.

Invoke `spechunter run --backend boom --runner /absolute/path/to/runner
--target-revision <commit>`. The runner receives one absolute `request.json` path;
its working directory also contains `candidate.S`. Input fields are `schema_version`
(1), `program` (operation strings), `program_sha256`, `secret` (0 or 1), `variant`
(none/privilege/transient), and `target_revision`. Each request must start from a
fresh, otherwise identical machine state. The fixed public probe must not depend
on the secret. A runner must reject unsupported benchmark variants.

Implement the `spechunter_*` harness calls emitted by `Program.assembly()`. These
calls describe experimental actions, not standalone executable attack code.
The validator rejects secret loads before entering user mode: privileged code deliberately
encoding a secret is outside this threat model. Privilege transitions need a runtime that can return from traps; train/load/encode/
squash/probe need explicit timing and microarchitectural instrumentation. Spike can
check architectural outcomes but cannot establish absence of cache leakage.

The runner writes exactly one JSON object to stdout, echoing all provenance fields
and adding `target: "boom"` and an `observation` object:

```json
{"architectural": [], "probes": [10], "events": [], "completed": true}
```

Diagnostic output belongs on stderr. No shell is used, inherited cloud credentials
are stripped, output is bounded, and process groups are killed on timeout. This is
resource containment, not a sandbox for hostile executables. Only use trusted runners.
Schema or provenance mismatch is inconclusive, never a vulnerability finding.

The BOOM label records the runner's assertion, not independent hardware attestation.
Review runner code and trace instrumentation before treating reports as research evidence.
The candidate RTL repair has build and target-regression evidence, but remains unvalidated
as a security fix until a repeatable baseline violation can be removed.

## Reproducible build and smoke test

The reviewed environment pins Chipyard 1.14, its repository commit, Miniforge's
installer digest, glibc 2.34, BOOM's stable `SmallBoomV3Config`, and the tool versions
resolved by Chipyard. `SmallBoomConfig` is not a generator configuration in Chipyard
1.14; the similarly named BOOM CI entry maps to the V3 configuration.

On a glibc 2.34 host with `curl`, `git`, `gcc`, `g++`, `make`, `dtc`, and `wget` installed:

```bash
sudo mkdir -p /opt/spechunter
sudo chown "$USER" /opt/spechunter
tools/boom/bootstrap.sh /opt/spechunter/chipyard
tools/boom/build_and_smoke.sh /opt/spechunter/chipyard /tmp/boom-smoke.json
```

The bootstrap rejects every other host ABI rather than silently regenerating dependency
locks. It removes an inline comment from Chipyard's glibc requirement because the 1.14
setup script otherwise compares the comment with `ldd` and regenerates the lockfiles.
The source revision is checked before that setup-only edit. The smoke command builds
the real Verilator simulator and runs Chipyard's bare-metal hello payload through it.
Success requires the expected payload output. Its JSON evidence records both repository
revisions, config and tool versions, elapsed time, and SHA-256 hashes of the simulator,
payload, and captured output.
Bootstrap refuses to run as root so the later runner can read Git provenance without
adding a global `safe.directory` bypass.
The first successful run is checked in as
[`docs/evidence/boom-smoke-2026-09-10.json`](evidence/boom-smoke-2026-09-10.json)
with its hash-bound raw log. It establishes a real BOOM build and execution path; it is
not a vulnerability result.

## Privilege-boundary gate

Run the reviewed architectural gate after building the pinned simulator:

```bash
tools/boom/run_privilege_smoke.sh \
  /opt/spechunter/chipyard /tmp/boom-privilege-smoke.json
```

The runner compiles one bare-metal ELF and requires it to pass first on Spike and then
on the generated BOOM simulator. Machine mode configures a 4 KiB PMP region with no
user permissions, installs a trap handler, and enters user mode with `mret`. The user
load must raise load-access-fault exception 5; the handler records the trap and advances
`mepc`. The test fails if the protected value reaches the destination register, if the
expected trap is absent, or if either executor fails. The runner imposes a 10-million
cycle limit and records revisions plus SHA-256 hashes for the source, payload, Spike,
simulator, and raw executor logs.

The checked-in
[`docs/evidence/boom-privilege-smoke-2026-09-10.json`](evidence/boom-privilege-smoke-2026-09-10.json)
records a successful Spike and SmallBoomV3 run of this gate. It demonstrates the
architectural PMP denial and trap-return substrate needed by later experiments. It does
not test transient leakage or establish that BOOM is free of speculative attacks.

## Trusted experiment runner

`tools/boom/trusted_runner.py` implements the external backend contract for the pinned
checkout at `/opt/spechunter/chipyard`. It parses the request as data and translates
only the eight supported operations into reviewed instruction snippets; it never
assembles `candidate.S` supplied by an agent. It accepts only the unmodified
`secure-control` target (`variant: "none"`), verifies the top-level Chipyard and BOOM
submodule pins, compiles one ELF, and executes it with both Spike and SmallBoomV3.

The generated assembly uses the pinned `riscv_test.h` reset and HTIF termination
substrate, reserves an aligned 4 KiB protected page, configures PMP, enables user access
to the cycle counter, installs a machine trap handler, and enters user mode.
A denied load and its younger encode/squash window are skipped architecturally after the
fault. The fixed probe always times the same two public cache lines in the same order and
returns whether line zero was faster; neither the probe addresses nor its control flow
depend on the secret. Spike and BOOM must agree on architectural output and trap events
before the BOOM observation is returned. The bounded HTIF exit word carries the binary
probe result; all other nonzero codes are errors. Executor failures, unexpected traps, timeouts,
unsupported variants, and provenance mismatches are inconclusive.

After the pinned simulator is built, invoke the real backend with a per-execution timeout
large enough for Spike plus RTL simulation:

```bash
uv run spechunter run --backend boom \
  --runner "$PWD/tools/boom/trusted_runner.py" \
  --target-revision 0acc1e1de2d3284bcd4d876956932a013ffe1949 \
  --benchmark secure-control --timeout 900 \
  --output artifacts/boom-secure-control.json
```

BOOM defaults to `secure-control` and a 900-second timeout when those flags are omitted.
The seeded `privilege` and `transient` fixture variants are intentionally rejected because
they are not real BOOM configurations or applied RTL mutations.

For the review gate, run the fixed two-scenario matrix. It executes architectural denial
and a load/encode/squash transient window twice in each secret world, rejects
nondeterministic repetitions, verifies every runner response echo, runs four isolated
simulators concurrently in stable input order, and hashes the runner and simulator into one
evidence file:

```bash
tools/boom/run_secure_matrix.py /tmp/boom-secure-matrix.json
```

The command returns zero only when both secure-control scenarios are repeatable and have
identical architectural and binary probe observations across the two secret worlds.
The 2026-09-11 live run passed both scenarios on the pinned SmallBoomV3 simulator; all
eight executions reported the expected load-access fault, no architectural value, and
probe bit zero. The evidence is in
[`docs/evidence/boom-secure-matrix-2026-09-11.json`](evidence/boom-secure-matrix-2026-09-11.json).
This exhausts these two attacker programs but does not prove the absence of other attacks.

## Candidate LSU repair

Source review at the pinned BOOM commit identified that incoming and retried loads can
assert `dmem_req.valid` when translation is complete even when the same DTLB response
reports a load access fault, page fault, or misalignment. Architectural exception handling
still prevents retirement, so this observation alone is not proof of leakage. It does
identify the D-cache request boundary exercised by the transient-window matrix.

[`tools/boom/patches/gate_faulting_loads.patch`](../tools/boom/patches/gate_faulting_loads.patch)
is a minimal candidate repair that adds those three fault predicates to both load request
paths. The patch applies cleanly to the exact pinned BOOM commit. `pins.env` records the
SHA-256 of both the pristine and repaired LSU source. The trusted secure-control runner
requires a pristine BOOM tree and exact pristine source digest so a patched or stale build
cannot be mislabeled as baseline evidence.
The hash-bound source audit is checked in as
[`docs/evidence/boom-lsu-repair-audit-2026-09-11.json`](evidence/boom-lsu-repair-audit-2026-09-11.json).

This patch is source-reviewed and its build and target regression have now been validated.
It must not be described as a BOOM security fix until a baseline violation is repeatable,
the original witness becomes clean on the repaired target, attacker-generated variants are
exhausted, and broader functional regressions pass. The clean baseline matrix could not
establish that security delta.

## Seeded positive control

`boom-positive-control` is an intentional harness mutation for demonstrating the complete
discovery and repair loop on real BOOM. The closed `seeded-cache-leak` variant accesses a
secret-selected public probe line in machine mode before entering the attacker context.
The protected user load must still fault, so the only expected difference is the later
cache observation. This is not an upstream BOOM vulnerability and does not alter BOOM RTL.

The closed repair ID `remove-seeded-cache-leak` removes only that seeded access while
retaining the identical pinned simulator, program, protected-load fault, and observer.
The LLM repair agent may select it only for `boom-positive-control`. The orchestrator then
retests the minimized witness and returns to the attacker until exhaustion, using the same
nested repair loop as real candidate patches.

Run the evidence gate after building the pinned simulator:

```bash
tools/boom/run_positive_control.py /tmp/boom-positive-control.json
```

The driver requires both fixed scenarios to be deterministic violations under the mutated
variant and deterministic clean results under the repaired variant. It cross-checks the
Chipyard revision, BOOM revision, configuration, simulator hash, repeat count, and program
hashes, then binds both child matrices into one manifest.

The live 2026-09-11 gate passed all requirements. In both scenarios, the mutated secret
worlds repeated `[1], [0], [1], [0]`; after repair they repeated `[0], [0], [0], [0]`.
Every execution retained the expected protected-load fault and no architectural secret
value. Both halves used simulator SHA-256 `230de62a46a82fc5f9c92aaf2f6e80893d1379d15952aef927fd0f6c11cfcaa8`,
which is also the independently validated privilege-gate binary. The manifest is
[`docs/evidence/boom-positive-control.json`](evidence/boom-positive-control.json).

## Vertex-to-GCP runner transport

`tools/boom/gcp_runner.py` lets the local Vertex agent loop use an isolated Compute Engine
worker without copying cloud credentials onto it. The wrapper accepts one bounded JSON
request, validates its exact envelope, uploads it under an unguessable name, invokes the
fixed remote trusted runner, bounds all `gcloud` calls and output, and removes the request
in a `finally` path. GCP resource identifiers are restricted before they enter the fixed
remote command. The local `gcloud` configuration is supplied explicitly to this trusted
wrapper; it is not inherited by candidate processes or sent to the worker.

The CLI accepts repeatable `--runner-arg=VALUE` options before the generated request path.
For example:

```bash
uv run --extra vertex spechunter run --backend boom --strategy llm \
  --runner "$PWD/tools/boom/gcp_runner.py" \
  --runner-arg=--project=spechunter \
  --runner-arg=--zone=us-central1-a \
  --runner-arg=--instance=spechunter-boom-agent-1 \
  --runner-arg=--gcloud-config="$HOME/.config/gcloud" \
  --runner-arg=--ssh-key-file="$HOME/.ssh/google_compute_engine" \
  --target-revision 0acc1e1de2d3284bcd4d876956932a013ffe1949 \
  --benchmark boom-positive-control --llm-model gemini-2.5-flash-lite \
  --recon-cycles 1 --attack-limit 4 --repair-limit 1 --timeout 1100
```

Real BOOM validation submits the four repeated-secret executions concurrently and retains
their input order. Each runner response now includes the simulator SHA-256; the backend
requires one stable hash for the entire experiment and records it in report provenance.
`tools/boom/seal_vertex_demo.py` rejects the final artifact unless the Vertex transcript
contains discovery, the closed repair selection, mandatory witness retest, return to the
attacker, exhaustion, matching positive-control simulator provenance, and a fully settled
cost ledger.

The live 2026-09-11 run completed this loop with Gemini 2.5 Flash-Lite and the pinned
SmallBoomV3 simulator. The model proposed a six-operation attack; real BOOM validation
confirmed the seeded leak, and empirical minimization reduced it to
`enter_user, load_secret, probe`. The closed harness repair made that identical witness
clean, after which control returned to the attacker and it reported exhaustion. The run
used 28 BOOM executions and four Vertex calls, accounting for $0.0006038 under the local
ledger. The report, settled ledger, and seal are
[`docs/evidence/vertex-boom-demo-2026-09-11.json`](evidence/vertex-boom-demo-2026-09-11.json),
[`docs/evidence/vertex-boom-demo-cost-2026-09-11.json`](evidence/vertex-boom-demo-cost-2026-09-11.json),
and
[`docs/evidence/vertex-boom-demo-seal-2026-09-11.json`](evidence/vertex-boom-demo-seal-2026-09-11.json).
This demonstrates the complete agent workflow on an intentional harness mutation; it is
not an upstream BOOM vulnerability claim.

## Held-out attack corpus

`tools/boom/run_attack_corpus.py` challenges the closed positive-control repair with eight
distinct protected-load programs that vary training, encode and squash placement, fences,
and irrelevant operations. For each program it executes both secret worlds twice under
the intentional mutation and the repaired harness. The gate succeeds only if all mutated
programs are repeatable violations and all repaired programs are repeatably clean.

```bash
tools/boom/run_attack_corpus.py /tmp/boom-attack-corpus.json
```

The 2026-09-16 run passed all eight programs: 100% mutation detection, 100% repair-clean
classification, zero inconclusive programs, and 64 total SmallBoomV3 executions. The
corpus used the same simulator SHA-256 as the privilege gate, positive control, and live
Vertex loop. `tools/boom/seal_attack_corpus.py` binds the corpus to those earlier artifacts,
and `spechunter present --corpus ... --corpus-seal ...` verifies the binding before showing
the scorecard. This is broader evidence for the intentional harness repair; it remains
neither an upstream BOOM vulnerability nor a proof over unsupported attack programs.

Build the repair in a separate checkout so baseline evidence remains immutable:

```bash
tools/boom/build_repair_variant.sh \
  /opt/spechunter/chipyard \
  /opt/spechunter/chipyard-gate-faulting-loads \
  /tmp/boom-load-gate-build.json
tools/boom/run_secure_matrix.py \
  /tmp/boom-load-gate-matrix.json gate-faulting-loads
```

The builder refuses an existing destination, copies the pinned baseline, applies only the
reviewed patch, cleans and rebuilds the simulator, and emits a manifest binding the source,
patch, and new simulator hashes. The trusted runner accepts the repair ID only from that
separate path and verifies both the exact dirty-source diff and build manifest before use.
An LLM repair response can select this closed repair ID; it cannot provide executable patch
text. After selection, the orchestrator retests the minimized witness on the repaired target
and returns control to the attacker until it reports exhaustion. BOOM repair verification is
true only after those real repaired-target executions succeed.

The 2026-09-16 live gate rebuilt the pristine baseline, reproduced simulator SHA-256
`230de62a46a82fc5f9c92aaf2f6e80893d1379d15952aef927fd0f6c11cfcaa8`, then built the
isolated patch into distinct simulator SHA-256
`fd4a264c1499cb2c3614cf05de4533e3b31ce2d921650452bca59072e55179c3` in 329 seconds.
Both repaired-target scenarios passed two repetitions in both secret worlds: eight total
executions with identical load-access faults, no architectural secret, and probe bit zero.
[`boom-load-gate-regression-seal-2026-09-16.json`](evidence/boom-load-gate-regression-seal-2026-09-16.json)
binds the pristine smoke, prior pristine matrix, repair build, and repaired matrix. Its
classification is `source-reviewed-candidate-regression-not-validated-security-fix` and
`security_fix_validated` is false because the baseline never exhibited the hypothesized
violation.

`tools/boom/gcp_worker.sh create` provisions the corresponding official Rocky Linux 9
image with no service account or API scopes. It has a six-hour maximum runtime and is
deleted automatically at the limit. Install the listed host packages and copy the two
scripts plus `pins.env` onto the worker before invoking the bootstrap. Delete a worker
as soon as its artifacts or failure evidence have been collected.

## Upstream issue #715 current-pin assessment

Upstream BOOM issue #715 reports that a delayed mispredicted branch on BOOM revision
`fac2c370…` allowed a faulting privileged load and dependent access to execute transiently.
The report includes a stripped Cascade ELF. SpecHunter records that attachment's SHA-256
but the current-pin HTIF/Verilator adaptation below is a different program. The original
attachment was later executed on the exact historical revisions; see the separate case
study below.

The trusted runner instead provides the fixed `issue-715-baseline` adaptation. It trains a
delayed conditional branch twelve times with a safe pointer, evicts the training cache
footprint, changes the pointer to the PMP-protected secret, and makes the protected load and
dependent two-line encode the predicted fall-through of an architecturally taken branch.
Only the fixed three-operation request is accepted. Spike establishes the architectural
path while BOOM supplies the cache observation.

On 2026-09-16, four executions on the current pinned BOOM revision `5223e44…` were
deterministic and clean: both secret worlds returned probe bit zero twice, with no
architectural exception. The reported vulnerable revision is 335 BOOM commits older.
[`boom-issue-715-assessment-seal-2026-09-16.json`](evidence/boom-issue-715-assessment-seal-2026-09-16.json)
binds the upstream provenance, reviewed runner, reproduced baseline simulator, and matrix.
It records `vulnerability_reproduced: false` and `security_fix_validated: false`. This
narrows the evidence gap but does not prove the current revision immune to other issue #715
programs or transient attacks.

## Exact historical issue #715 experiment

The next gate targets the revisions named in the upstream report rather than treating the
current-pin negative result as conclusive. `historical_pins.env` binds Chipyard
`004297b6…`, BOOM `fac2c370…`, `SmallBoomConfig`, the pristine and repaired LSU sources,
the reviewed two-line repair diff, and the historical Miniforge installer by SHA-256.
`bootstrap_historical_issue_715.sh` creates this environment from the checked-in Chipyard
lockfile. It refuses an existing destination and verifies both Git revisions and the
pristine source before returning.

The historical runner accepts only the fixed issue #715 program, binary secret values, and
the baseline or reviewed-repair IDs. Before executing it verifies the exact source-tree
state and a build manifest binding the variant, revisions, source, configuration, and
simulator binary. Run the repeatability gate with:

```bash
tools/boom/run_historical_issue_715.py \
  historical-issue-715-baseline \
  /absolute/path/historical-baseline.json
```

Build and test the repair only if that baseline produces a repeatable secret-dependent
observation. A clean or unstable baseline cannot validate the patch.

On 2026-09-17 the exact historical simulator built successfully in 685 seconds. Four live
executions produced probe sequences `[0, 0]` for both secret worlds, so the result is
deterministic and clean for this adaptation. The repair was not built because that would
not establish a security delta. The checked seal independently derives this classification
from the raw observations, cross-checks the source, runner, simulator, and revision
provenance, and records both `vulnerability_reproduced` and `security_fix_validated` as
false. The worker and its disk were deleted after recovered hashes matched the remote
artifacts. See
[`boom-issue-715-historical-seal-2026-09-17.json`](evidence/boom-issue-715-historical-seal-2026-09-17.json).

## Original issue #715 attachment case

The original upstream ELF was loaded into the historical `SmallBoomConfig` simulator.
Its checked-in disassembly shows adjacent instructions `lb sp,-2048(t1)` and
`ld s1,0(sp)`: the second address uses the first instruction's destination register.
The case seal binds this disassembly by SHA-256. This proves a static instruction
dependency, not that the protected load supplied the value observed at runtime.
The baseline waveform records the branch and gadget frontend PCs, a protected-page
translation request, a later `0x59f` translation request, a load page fault, and
branch resolution. Dispatch and load-queue identifiers establish that the `0x59f`
request comes from the independent third instruction at gadget offset `+8`, not the
dependent load at `+4`. No recorded branch-masked translation request came from that dependent
load. Thus this execution does **not** reproduce the protected-data-dependent
mechanism or prove secret disclosure. A shared branch mask alone cannot establish
data dependence.

The baseline and v1/v2 issue the dependent load from the memory queue at cycle
3809, but there is no matching valid LSU execute request or branch-masked TLB
request. At cycle 3811 the LSU carries fields for that load, including an address,
but its execute-request valid signal is low; those fields cannot prove execution
or a data leak. The baseline also
shows a TLB miss and speculative load wakeup without a D-cache request. V3
suppresses that wakeup and no dependent-load issue is observed under the target
branch mask, while the independent third instruction still requests `0x59f`.
This is an issue-stage effect, not evidence of a security fix: the three waveformed
candidate repairs cannot be evaluated as security
fixes because the baseline did not reproduce the target mechanism. A fourth
candidate built and ran, but its waveform was not recovered. The
[case seal](evidence/boom-issue-715-attachment-demo-seal-2026-09-20.json) binds the
four raw waveforms, their corrected witnesses, three inconclusive comparisons,
builds, original disassembly, and pinned-seed simulator logs. A reproducing baseline
and attacker retest are required before any repair can be called effective.

The comparison now binds the baseline and repaired run-log hashes and requires the
same seed in both logs. It compares the ordered branch/gadget/protected-request/fault/
misprediction trigger while allowing cycle timing to shift under a repair. A missing
trigger is inconclusive, even if dependent requests disappear. A blocked matched
witness only starts the attacker retest; it does not validate the security fix.
