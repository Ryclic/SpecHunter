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
