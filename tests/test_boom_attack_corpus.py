import importlib.util
import json
from copy import deepcopy
from hashlib import sha256
from pathlib import Path

import pytest

ROOT = Path(__file__).parents[1]
SCRIPT = ROOT / "tools/boom/run_attack_corpus.py"
SPEC = importlib.util.spec_from_file_location("run_attack_corpus", SCRIPT)
assert SPEC and SPEC.loader
CORPUS = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CORPUS)


def passing_results():
    return [
        {
            "name": name,
            "program": program,
            "mutated": {"deterministic": True, "status": "violation"},
            "repaired": {"deterministic": True, "status": "clean"},
        }
        for name, program in CORPUS.CORPUS.items()
    ]


def test_corpus_has_materially_different_protected_load_programs():
    programs = list(CORPUS.CORPUS.values())
    assert len(programs) == 8
    assert len({tuple(program) for program in programs}) == len(programs)
    for program in programs:
        assert program.index("enter_user") < program.index("load_secret") < program.index("probe")


def test_scorecard_requires_every_mutation_detected_and_repair_clean():
    scorecard = CORPUS.validate_results(passing_results())
    assert scorecard == {
        "attack_programs": 8,
        "mutation_detection_rate": 1.0,
        "repair_clean_rate": 1.0,
        "inconclusive_programs": 0,
        "simulator_executions": 64,
    }
    broken = deepcopy(passing_results())
    broken[0]["repaired"]["status"] = "violation"
    with pytest.raises(CORPUS.CorpusError, match="repair did not remain clean"):
        CORPUS.validate_results(broken)


def test_checked_in_live_corpus_has_stable_provenance_and_complete_scorecard():
    evidence = json.loads((ROOT / "docs/evidence/boom-attack-corpus-2026-09-16.json").read_text())
    control = json.loads((ROOT / "docs/evidence/boom-positive-control.json").read_text())
    assert evidence["classification"] == (
        "intentional-harness-mutation-not-upstream-boom-vulnerability"
    )
    assert evidence["simulator_sha256"] == control["simulator_sha256"]
    assert evidence["corpus_runner_sha256"] == sha256(SCRIPT.read_bytes()).hexdigest()
    assert evidence["scorecard"] == CORPUS.validate_results(evidence["results"])
