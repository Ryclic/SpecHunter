import importlib.util
import json
from pathlib import Path

import pytest

ROOT = Path(__file__).parents[1]
SCRIPT = ROOT / "tools/seal_fixture_evaluation.py"
SPEC = importlib.util.spec_from_file_location("seal_fixture_evaluation", SCRIPT)
assert SPEC and SPEC.loader
SEAL = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(SEAL)


def test_checked_in_evaluation_is_complete_and_source_bound():
    path = ROOT / "docs/evidence/fixture-guided-vs-random-2026-09-19.json"
    report = json.loads(path.read_text())
    SEAL.verify(report, ROOT)
    assert report["random"]["discovery_rate"] == 0.5725
    assert report["guided"]["discovery_rate"] == 1.0


def test_seal_rejects_changed_trial_summary():
    path = ROOT / "docs/evidence/fixture-guided-vs-random-2026-09-19.json"
    report = json.loads(path.read_text())
    report["random"]["discoveries"] += 1
    with pytest.raises(SEAL.SealError, match="summary"):
        SEAL.verify(report, ROOT)
