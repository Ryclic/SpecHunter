#!/usr/bin/env python3
"""Evaluate a held-out attack corpus before and after the BOOM positive-control repair."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import sys
import tempfile
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path

REPEATS = 2
WORKERS = 4
MUTATED = "seeded-cache-leak"
REPAIRED = "remove-seeded-cache-leak"
CORPUS = {
    "minimal-denied-load": ["enter_user", "load_secret", "probe"],
    "trained-denied-load": ["train", "enter_user", "load_secret", "probe"],
    "encode-window": ["train", "enter_user", "load_secret", "encode", "probe"],
    "squashed-window": [
        "train",
        "enter_user",
        "load_secret",
        "encode",
        "squash",
        "probe",
    ],
    "fence-before-load": ["train", "enter_user", "fence", "load_secret", "probe"],
    "fence-before-probe": [
        "train",
        "enter_user",
        "load_secret",
        "encode",
        "fence",
        "probe",
    ],
    "squash-then-encode": [
        "train",
        "enter_user",
        "load_secret",
        "squash",
        "encode",
        "probe",
    ],
    "noise-padded-window": [
        "nop",
        "train",
        "enter_user",
        "nop",
        "load_secret",
        "encode",
        "squash",
        "fence",
        "nop",
        "probe",
    ],
}


class CorpusError(RuntimeError):
    pass


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def program_digest(program: list[str]) -> str:
    return hashlib.sha256(json.dumps(program).encode()).hexdigest()


def load_matrix_module(script_dir: Path):
    path = script_dir / "run_secure_matrix.py"
    spec = importlib.util.spec_from_file_location("spechunter_secure_matrix", path)
    if not spec or not spec.loader:
        raise CorpusError("cannot load secure matrix implementation")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def validate_results(results: list[dict]) -> dict:
    if len(results) != len(CORPUS):
        raise CorpusError("corpus result count differs")
    expected_names = set(CORPUS)
    if {item.get("name") for item in results} != expected_names:
        raise CorpusError("corpus scenario names differ")
    mutation_detected = 0
    repair_clean = 0
    for item in results:
        name = item["name"]
        if item.get("program") != CORPUS[name]:
            raise CorpusError(f"program provenance differs: {name}")
        before = item.get("mutated", {})
        after = item.get("repaired", {})
        if before.get("deterministic") is not True or before.get("status") != "violation":
            raise CorpusError(f"mutation was not repeatably detected: {name}")
        if after.get("deterministic") is not True or after.get("status") != "clean":
            raise CorpusError(f"repair did not remain clean: {name}")
        mutation_detected += 1
        repair_clean += 1
    total = len(results)
    return {
        "attack_programs": total,
        "mutation_detection_rate": mutation_detected / total,
        "repair_clean_rate": repair_clean / total,
        "inconclusive_programs": 0,
        "simulator_executions": total * REPEATS * 2 * 2,
    }


def make_requests(work: Path, name: str, program: list[str], variant: str) -> list[Path]:
    requests = []
    for repeat in range(REPEATS):
        for secret in (0, 1):
            request = {
                "schema_version": 1,
                "program": program,
                "program_sha256": program_digest(program),
                "secret": secret,
                "variant": variant,
                "target_revision": PINS["CHIPYARD_REVISION"],
            }
            path = work / f"{name}-{variant}-{repeat}-{secret}.json"
            path.write_text(json.dumps(request) + "\n")
            requests.append(path)
    return requests


def observe(matrix, runner: Path, requests: list[Path]) -> tuple[list[dict], str]:
    with ThreadPoolExecutor(max_workers=WORKERS) as executor:
        responses = list(executor.map(lambda path: matrix.run_request(runner, path), requests))
    hashes = {response["simulator_sha256"] for response in responses}
    if len(hashes) != 1:
        raise CorpusError("simulator provenance changed within a corpus batch")
    return [response["observation"] for response in responses], hashes.pop()


PINS: dict[str, str] = {}


def main() -> int:
    try:
        if len(sys.argv) != 2 or not Path(sys.argv[1]).is_absolute():
            raise CorpusError("usage: run_attack_corpus.py /ABSOLUTE/evidence.json")
        output = Path(sys.argv[1])
        output.parent.mkdir(parents=True, exist_ok=True)
        script_dir = Path(__file__).resolve().parent
        runner = script_dir / "trusted_runner.py"
        matrix = load_matrix_module(script_dir)
        for line in (script_dir / "pins.env").read_text().splitlines():
            if line and not line.startswith("#"):
                key, separator, value = line.partition("=")
                if not separator:
                    raise CorpusError("invalid pins.env")
                PINS[key] = value
        results = []
        simulator_hashes = set()
        with tempfile.TemporaryDirectory(prefix="spechunter-corpus-") as temporary:
            work = Path(temporary)
            for name, program in CORPUS.items():
                variants = {}
                for variant, label in ((MUTATED, "mutated"), (REPAIRED, "repaired")):
                    observations, simulator_hash = observe(
                        matrix, runner, make_requests(work, name, program, variant)
                    )
                    simulator_hashes.add(simulator_hash)
                    variants[label] = {
                        "variant": variant,
                        "observations": observations,
                        **matrix.classify(observations),
                    }
                results.append(
                    {
                        "name": name,
                        "program": program,
                        "program_sha256": program_digest(program),
                        **variants,
                    }
                )
        if len(simulator_hashes) != 1:
            raise CorpusError("simulator provenance changed across corpus")
        simulator_hash = simulator_hashes.pop()
        simulators = list(
            Path("/opt/spechunter/chipyard/sims/verilator").glob(
                f"simulator-*-{PINS['BOOM_CONFIG']}"
            )
        )
        if len(simulators) != 1 or digest(simulators[0]) != simulator_hash:
            raise CorpusError("corpus simulator does not match the installed pinned binary")
        scorecard = validate_results(results)
        evidence = {
            "schema_version": 1,
            "experiment": "boom-held-out-attack-corpus-repair-evaluation",
            "classification": "intentional-harness-mutation-not-upstream-boom-vulnerability",
            "chipyard_revision": PINS["CHIPYARD_REVISION"],
            "boom_revision": PINS["BOOM_REVISION"],
            "config": PINS["BOOM_CONFIG"],
            "simulator_sha256": simulator_hash,
            "runner_sha256": digest(runner),
            "corpus_runner_sha256": digest(Path(__file__)),
            "repeats": REPEATS,
            "parallel_workers": WORKERS,
            "scorecard": scorecard,
            "results": results,
            "completed_at": datetime.now(timezone.utc).isoformat(),  # noqa: UP017
        }
        temporary_output = output.with_suffix(output.suffix + ".tmp")
        temporary_output.write_text(json.dumps(evidence, indent=2) + "\n")
        temporary_output.replace(output)
        print(json.dumps(scorecard, indent=2))
        return 0
    except (KeyError, OSError, CorpusError) as exc:
        print(f"BOOM attack corpus: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
