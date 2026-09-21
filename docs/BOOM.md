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
BOOM repair is proposal-only until an RTL patch and full target regressions exist.

## Reproducible build and smoke test

The reviewed environment pins Chipyard 1.14, its repository commit, Miniforge's
installer digest, glibc 2.34, BOOM's stable `SmallBoomV3Config`, and the tool versions
resolved by Chipyard. `SmallBoomConfig` is not a generator configuration in Chipyard
1.14; the similarly named BOOM CI entry maps to the V3 configuration.

On a glibc 2.34 host with `curl`, `git`, `gcc`, `g++`, `make`, and `dtc` installed:

```bash
tools/boom/bootstrap.sh /opt/chipyard
tools/boom/build_and_smoke.sh /opt/chipyard /tmp/boom-smoke.json
```

The bootstrap rejects every other host ABI rather than silently regenerating dependency
locks. It removes an inline comment from Chipyard's glibc requirement because the 1.14
setup script otherwise compares the comment with `ldd` and regenerates the lockfiles.
The source revision is checked before that setup-only edit. The smoke command builds
the real Verilator simulator and runs Chipyard's bare-metal hello payload through it.
Success requires the expected payload output. Its JSON evidence records both repository
revisions, config and tool versions, elapsed time, and SHA-256 hashes of the simulator,
payload, and captured output.
The first successful run is checked in as
[`docs/evidence/boom-smoke-2026-09-10.json`](evidence/boom-smoke-2026-09-10.json)
with its hash-bound raw log. It establishes a real BOOM build and execution path; it is
not yet a privilege-isolation experiment or vulnerability result.

`tools/boom/gcp_worker.sh create` provisions the corresponding official Rocky Linux 9
image with no service account or API scopes. It has a six-hour maximum runtime and is
deleted automatically at the limit. Install the listed host packages and copy the two
scripts plus `pins.env` onto the worker before invoking the bootstrap. Delete a worker
as soon as its artifacts or failure evidence have been collected.
