#!/usr/bin/env python3
"""Bind the BOOM attack-corpus scorecard to its prior live control evidence."""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

CLASSIFICATION = "intentional-harness-mutation-not-upstream-boom-vulnerability"
EXPECTED_SCORECARD = {
    "attack_programs": 8,
    "mutation_detection_rate": 1.0,
    "repair_clean_rate": 1.0,
    "inconclusive_programs": 0,
    "simulator_executions": 64,
}


class SealError(RuntimeError):
    pass


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def read(path: Path) -> dict:
    value = json.loads(path.read_text())
    if not isinstance(value, dict):
        raise SealError(f"{path} must contain a JSON object")
    return value


def create_seal(corpus_path: Path, control_path: Path, report_path: Path) -> dict:
    corpus = read(corpus_path)
    control = read(control_path)
    report = read(report_path)
    if corpus.get("experiment") != "boom-held-out-attack-corpus-repair-evaluation":
        raise SealError("unsupported corpus experiment")
    if corpus.get("classification") != CLASSIFICATION:
        raise SealError("corpus classification differs")
    if corpus.get("scorecard") != EXPECTED_SCORECARD:
        raise SealError("corpus scorecard is incomplete")
    results = corpus.get("results")
    if not isinstance(results, list) or len(results) != EXPECTED_SCORECARD["attack_programs"]:
        raise SealError("corpus program count differs")
    simulator_hash = corpus.get("simulator_sha256")
    if simulator_hash != control.get("simulator_sha256"):
        raise SealError("corpus and positive control used different simulators")
    if simulator_hash != report.get("provenance", {}).get("simulator_sha256"):
        raise SealError("corpus and Vertex loop used different simulators")
    return {
        "schema_version": 1,
        "experiment": corpus["experiment"],
        "classification": CLASSIFICATION,
        "attack_corpus": corpus_path.name,
        "attack_corpus_sha256": digest(corpus_path),
        "positive_control": control_path.name,
        "positive_control_sha256": digest(control_path),
        "vertex_report": report_path.name,
        "vertex_report_sha256": digest(report_path),
        "simulator_sha256": simulator_hash,
        "scorecard": corpus["scorecard"],
    }


def main() -> int:
    try:
        if len(sys.argv) != 5 or any(not Path(arg).is_absolute() for arg in sys.argv[1:]):
            raise SealError(
                "usage: seal_attack_corpus.py /ABSOLUTE/corpus.json "
                "/ABSOLUTE/control.json /ABSOLUTE/report.json /ABSOLUTE/seal.json"
            )
        corpus, control, report, output = map(Path, sys.argv[1:])
        seal = create_seal(corpus, control, report)
        output.parent.mkdir(parents=True, exist_ok=True)
        temporary = output.with_suffix(output.suffix + ".tmp")
        temporary.write_text(json.dumps(seal, indent=2) + "\n")
        temporary.replace(output)
        print(json.dumps({"sealed": True, "scorecard": seal["scorecard"]}, indent=2))
        return 0
    except (KeyError, OSError, json.JSONDecodeError, SealError) as exc:
        print(f"BOOM attack corpus seal: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
