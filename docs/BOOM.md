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

The generated runtime reserves an aligned 4 KiB protected page, configures PMP, enables
user access to the cycle counter, installs a machine trap handler, and enters user mode.
A denied load and its younger encode/squash window are skipped architecturally after the
fault. The fixed probe always times the same two public cache lines in the same order and
returns whether line zero was faster; neither the probe addresses nor its control flow
depend on the secret. Spike and BOOM must agree on architectural output and trap events
before the BOOM observation is returned. Probe results are restricted to the binary
relative-latency contract. Executor failures, unexpected traps, malformed output, timeouts,
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

`tools/boom/gcp_worker.sh create` provisions the corresponding official Rocky Linux 9
image with no service account or API scopes. It has a six-hour maximum runtime and is
deleted automatically at the limit. Install the listed host packages and copy the two
scripts plus `pins.env` onto the worker before invoking the bootstrap. Delete a worker
as soon as its artifacts or failure evidence have been collected.
