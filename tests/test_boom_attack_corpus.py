import importlib.util
from copy import deepcopy
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
