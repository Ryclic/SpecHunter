"""Source-bound summary of the original historical BOOM issue #715 attachment."""

import hashlib
import json
from pathlib import Path


class AttachmentEvidenceError(ValueError):
    pass


PREFIX = "boom-issue-715-attachment-"
BASELINE = (
    "baseline-2026-09-17.json",
    "baseline-seed-1789717734-2026-09-17.vcd.gz",
    "baseline-seed-1789717734-2026-09-17.log",
)
REPAIRS = (
    (
        "repaired-2026-09-17.json",
        "repaired-seed-1789717734-2026-09-17.vcd.gz",
        "repair-build-2026-09-17.json",
        "comparison-2026-09-17.json",
        "repaired-seed-1789717734-2026-09-17.log",
    ),
    (
        "repair-v2-2026-09-18.json",
        "repair-v2-seed-1789717734-2026-09-18.vcd.gz",
        "repair-v2-build-2026-09-18.json",
        "repair-v2-comparison-2026-09-18.json",
        "repair-v2-seed-1789717734-2026-09-18.log",
    ),
    (
        "repair-v3-witness-2026-09-18.json",
        "repair-v3-seed-1789717734-2026-09-18.vcd.gz",
        "repair-v3-build-2026-09-18.json",
        "repair-v3-comparison-2026-09-18.json",
        "repair-v3-run-2026-09-18.log",
    ),
)
V4_BUILD = "repair-v4-build-2026-09-18.json"
V4_RUN = "repair-v4-run-2026-09-18.log"
DISASSEMBLY = "disassembly-2026-09-17.txt"
SEED = 1789717734
TIMEOUT = f"*** FAILED *** via trace_count (timeout, seed {SEED}) after 10000 cycles"
FRONTEND_SOURCES = {
    "0xd0100287d0": "frontend.s0_vpc",
    "0xd010028e00": "frontend.s0_vpc",
    "0xd010028e04": "frontend.fb.pc_2 with io_enq_valid",
}
CLASSIFICATION = "original-attachment-dependent-request-not-reproduced-v4-unresolved"


def _digest(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _read(root: Path, suffix: str) -> tuple[dict, str, str]:
    name = PREFIX + suffix
    path = root / name
    return json.loads(path.read_text()), name, _digest(path)


def _run_log(root: Path, suffix: str) -> tuple[str, str]:
    name = PREFIX + suffix
    path = root / name
    if TIMEOUT not in path.read_text(errors="replace").splitlines():
        raise AttachmentEvidenceError(f"run log lacks the pinned seed and timeout: {name}")
    return name, _digest(path)


def build_seal(root: Path) -> dict:
    root = root.resolve()
    disassembly_name = PREFIX + DISASSEMBLY
    disassembly = root / disassembly_name
    lines = disassembly.read_text().splitlines()
    if not any("80028e00:" in line and "lb\tsp,-2048(t1)" in line for line in lines) or not any(
        "80028e04:" in line and "ld\ts1,0(sp)" in line for line in lines
    ):
        raise AttachmentEvidenceError("original ELF gadget disassembly differs")
    baseline, baseline_name, baseline_hash = _read(root, BASELINE[0])
    baseline_trace_name = PREFIX + BASELINE[1]
    baseline_trace_hash = _digest(root / baseline_trace_name)
    baseline_run_name, baseline_run_hash = _run_log(root, BASELINE[2])
    if (
        baseline.get("schema_version") != 9
        or baseline.get("experiment") != "boom-upstream-issue-715-vcd-witness"
        or baseline.get("frontend_pc_signal_sources") != FRONTEND_SOURCES
        or baseline.get("gadget_frontend_pc_cycles", {}).get("0xd010028e04") is None
        or baseline.get("mechanism_witnessed") is not False
        or baseline.get("dependent_load_requests") != []
        or baseline.get("dependent_load_exe_requests") != []
        or not baseline.get("dependent_load_issues")
        or not all(
            event.get("prs1_poisoned") is True
            and event.get("load_miss") is True
            and event.get("register_read_valid") is False
            for event in baseline["dependent_load_issues"]
        )
        or not baseline.get("observed_address_requests")
        or any(
            request.get("dispatch_pc_lob") != "0x8"
            for request in baseline["observed_address_requests"]
        )
        or baseline.get("architectural_secret_disclosure_proven") is not False
        or baseline.get("trace_sha256") != baseline_trace_hash
        or not baseline.get("tlb_miss_fast_wakeup_observations")
    ):
        raise AttachmentEvidenceError("baseline witness or raw trace differs")
    repairs = []
    revisions = set()
    for index, (
        witness_suffix,
        trace_suffix,
        build_suffix,
        comparison_suffix,
        run_suffix,
    ) in enumerate(REPAIRS):
        witness, witness_name, witness_hash = _read(root, witness_suffix)
        build, build_name, build_hash = _read(root, build_suffix)
        comparison, comparison_name, comparison_hash = _read(root, comparison_suffix)
        trace_name = PREFIX + trace_suffix
        trace_hash = _digest(root / trace_name)
        run_name, run_hash = _run_log(root, run_suffix)
        revisions.add((build.get("chipyard_revision"), build.get("boom_revision")))
        if (
            witness.get("schema_version") != 9
            or witness.get("frontend_pc_signal_sources") != FRONTEND_SOURCES
            or witness.get("experiment") != "boom-upstream-issue-715-vcd-witness"
            or witness.get("gadget_frontend_pc_cycles", {}).get("0xd010028e04") is None
            or witness.get("trace_sha256") != trace_hash
            or witness.get("mechanism_witnessed") is not False
            or witness.get("architectural_secret_disclosure_proven") is not False
            or comparison.get("schema_version") != 9
            or comparison.get("baseline_dependent_issues") != baseline["dependent_load_issues"]
            or comparison.get("repaired_dependent_issues") != witness["dependent_load_issues"]
            or comparison.get("baseline_dependent_exe_requests")
            != baseline["dependent_load_exe_requests"]
            or comparison.get("repaired_dependent_exe_requests")
            != witness["dependent_load_exe_requests"]
            or comparison.get("repair_variant") != build.get("variant")
            or comparison.get("repaired_simulator_sha256") != build.get("simulator_sha256")
            or comparison.get("baseline_trace_sha256") != baseline_trace_hash
            or comparison.get("repaired_trace_sha256") != trace_hash
            or comparison.get("seed_provenance") != "bound-by-run-logs"
            or comparison.get("seed") != SEED
            or comparison.get("baseline_run_log_sha256") != baseline_run_hash
            or comparison.get("repaired_run_log_sha256") != run_hash
            or comparison.get("baseline_mechanism_witnessed") is not False
            or comparison.get("repaired_mechanism_witnessed") is not False
            or comparison.get("repair_effective") is not False
            or comparison.get("security_fix_validated") is not False
            or comparison.get("verdict") != "inconclusive-baseline-not-reproduced"
            or bool(witness.get("tlb_miss_fast_wakeup_observations")) != (index < 2)
            or witness.get("dependent_load_requests") != []
            or witness.get("dependent_load_exe_requests") != []
            or bool(witness.get("dependent_load_issues")) != (index < 2)
            or not all(
                event.get("prs1_poisoned") is True
                and event.get("load_miss") is True
                and event.get("register_read_valid") is False
                for event in witness.get("dependent_load_issues", [])
            )
            or not witness.get("observed_address_requests")
            or any(
                request.get("dispatch_pc_lob") != "0x8"
                for request in witness["observed_address_requests"]
            )
        ):
            raise AttachmentEvidenceError(f"candidate repair evidence differs: {build_name}")
        repairs.append(
            {
                "variant": build["variant"],
                "witness": witness_name,
                "witness_sha256": witness_hash,
                "waveform": trace_name,
                "waveform_sha256": trace_hash,
                "build": build_name,
                "build_sha256": build_hash,
                "comparison": comparison_name,
                "comparison_sha256": comparison_hash,
                "run_log": run_name,
                "run_log_sha256": run_hash,
                "tlb_miss_fast_wakeup_count": len(witness["tlb_miss_fast_wakeup_observations"]),
            }
        )
    v4, v4_name, v4_hash = _read(root, V4_BUILD)
    v4_run_name, v4_run_hash = _run_log(root, V4_RUN)
    revisions.add((v4.get("chipyard_revision"), v4.get("boom_revision")))
    if len(revisions) != 1 or v4.get("variant") != "historical-issue-715-dcache-fired-wakeup":
        raise AttachmentEvidenceError("repair builds do not share the historical revisions")
    if list(root.glob(PREFIX + "*v4*.vcd*")):
        raise AttachmentEvidenceError("v4 waveform exists; update its unresolved verdict")
    return {
        "schema_version": 1,
        "classification": CLASSIFICATION,
        "disassembly": disassembly_name,
        "disassembly_sha256": _digest(disassembly),
        "static_gadget_register_dependency": True,
        "baseline": {
            "witness": baseline_name,
            "witness_sha256": baseline_hash,
            "waveform": baseline_trace_name,
            "waveform_sha256": baseline_trace_hash,
            "run_log": baseline_run_name,
            "run_log_sha256": baseline_run_hash,
            "tlb_miss_fast_wakeup_count": len(baseline["tlb_miss_fast_wakeup_observations"]),
        },
        "repairs": repairs,
        "historical_revisions": {
            "chipyard": v4["chipyard_revision"],
            "boom": v4["boom_revision"],
        },
        "v4_build": v4_name,
        "v4_build_sha256": v4_hash,
        "v4_run_log": v4_run_name,
        "v4_run_log_sha256": v4_run_hash,
        "v4_security_verdict": "unresolved-no-waveform",
        "v3_fast_wakeup_suppressed_but_request_chain_remained": True,
        "security_fix_validated": False,
    }


def verify_seal(path: Path) -> dict:
    saved = json.loads(path.read_text())
    expected = build_seal(path.parent)
    if saved != expected:
        raise AttachmentEvidenceError("attachment case seal differs from checked-in evidence")
    return saved
