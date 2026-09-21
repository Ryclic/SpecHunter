import importlib.util
from copy import deepcopy
from pathlib import Path

ROOT = Path(__file__).parents[1]
SCRIPT = ROOT / "tools/evaluate_vertex_repeatability.py"
SPEC = importlib.util.spec_from_file_location("evaluate_vertex_repeatability", SCRIPT)
assert SPEC and SPEC.loader
EVALUATION = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(EVALUATION)


def report():
    return {
        "metrics": {
            "discovered": 1,
            "positive_cases": 1,
            "false_positives": 0,
            "inconclusive_cases": 0,
            "repairs_attacker_exhausted": 1,
            "llm_calls": 4,
            "executions": 28,
        },
        "results": [{"repair": {"verified": True}}],
    }


def test_summary_requires_complete_repair_red_team_loop():
    good = report()
    assert EVALUATION.trial_success(good)
    summary = EVALUATION.summarize([good, good])
    assert summary == {
        "trials": 2,
        "successful_full_loops": 2,
        "full_loop_success_rate": 1.0,
        "discoveries": 2,
        "repairs_attacker_exhausted": 2,
        "inconclusive_cases": 0,
        "llm_calls": 8,
        "fixture_executions": 56,
    }
    incomplete = deepcopy(good)
    incomplete["metrics"]["repairs_attacker_exhausted"] = 0
    assert not EVALUATION.trial_success(incomplete)
