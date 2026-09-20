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
)
REPAIRS = (
    (
        "repaired-2026-09-17.json",
        "repaired-seed-1789717734-2026-09-17.vcd.gz",
        "repair-build-2026-09-17.json",
        "comparison-2026-09-17.json",
    ),
    (
        "repair-v2-2026-09-18.json",
        "repair-v2-seed-1789717734-2026-09-18.vcd.gz",
        "repair-v2-build-2026-09-18.json",
        "repair-v2-comparison-2026-09-18.json",
    ),
    (
        "repair-v3-witness-2026-09-18.json",
        "repair-v3-seed-1789717734-2026-09-18.vcd.gz",
        "repair-v3-build-2026-09-18.json",
        "repair-v3-comparison-2026-09-18.json",
    ),
)
V4_BUILD = "repair-v4-build-2026-09-18.json"
CLASSIFICATION = "original-attachment-event-chain-three-failed-repairs-v4-unresolved"


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


def build_seal(root: Path) -> dict:
    root = root.resolve()
    baseline, baseline_name, baseline_hash = _read(root, BASELINE[0])
    baseline_trace_name = PREFIX + BASELINE[1]
    baseline_trace_hash = _digest(root / baseline_trace_name)
    if (
        baseline.get("experiment") != "boom-upstream-issue-715-vcd-witness"
        or baseline.get("mechanism_witnessed") is not True
        or baseline.get("architectural_secret_disclosure_proven") is not False
        or baseline.get("trace_sha256") != baseline_trace_hash
    ):
        raise AttachmentEvidenceError("baseline witness or raw trace differs")
    repairs = []
    revisions = set()
    for witness_suffix, trace_suffix, build_suffix, comparison_suffix in REPAIRS:
        witness, witness_name, witness_hash = _read(root, witness_suffix)
        build, build_name, build_hash = _read(root, build_suffix)
        comparison, comparison_name, comparison_hash = _read(root, comparison_suffix)
        trace_name = PREFIX + trace_suffix
        trace_hash = _digest(root / trace_name)
        revisions.add((build.get("chipyard_revision"), build.get("boom_revision")))
        if (
            witness.get("trace_sha256") != trace_hash
            or witness.get("mechanism_witnessed") is not True
            or witness.get("architectural_secret_disclosure_proven") is not False
            or comparison.get("schema_version") != 3
            or comparison.get("repair_variant") != build.get("variant")
            or comparison.get("repaired_simulator_sha256") != build.get("simulator_sha256")
            or comparison.get("baseline_trace_sha256") != baseline_trace_hash
            or comparison.get("repaired_trace_sha256") != trace_hash
            or comparison.get("baseline_mechanism_witnessed") is not True
            or comparison.get("repaired_mechanism_witnessed") is not True
            or comparison.get("repair_effective") is not False
            or comparison.get("security_fix_validated") is not False
            or comparison.get("verdict") != "repair-ineffective"
        ):
            raise AttachmentEvidenceError(f"rejected repair evidence differs: {build_name}")
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
            }
        )
    v4, v4_name, v4_hash = _read(root, V4_BUILD)
    revisions.add((v4.get("chipyard_revision"), v4.get("boom_revision")))
    if len(revisions) != 1 or v4.get("variant") != "historical-issue-715-dcache-fired-wakeup":
        raise AttachmentEvidenceError("repair builds do not share the historical revisions")
    if list(root.glob(PREFIX + "*v4*.vcd*")):
        raise AttachmentEvidenceError("v4 waveform exists; update its unresolved verdict")
    return {
        "schema_version": 1,
        "classification": CLASSIFICATION,
        "baseline": {
            "witness": baseline_name,
            "witness_sha256": baseline_hash,
            "waveform": baseline_trace_name,
            "waveform_sha256": baseline_trace_hash,
        },
        "repairs": repairs,
        "historical_revisions": {
            "chipyard": v4["chipyard_revision"],
            "boom": v4["boom_revision"],
        },
        "v4_build": v4_name,
        "v4_build_sha256": v4_hash,
        "v4_security_verdict": "unresolved-no-waveform",
        "security_fix_validated": False,
    }


def verify_seal(path: Path) -> dict:
    saved = json.loads(path.read_text())
    expected = build_seal(path.parent)
    if saved != expected:
        raise AttachmentEvidenceError("attachment case seal differs from checked-in evidence")
    return saved
