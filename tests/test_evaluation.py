import json
import sys
from hashlib import sha256
from pathlib import Path

import pytest

from spechunter.cli import main
from spechunter.evaluation import _wilson, evaluate

ROOT = Path(__file__).parents[1]


def test_wilson_interval_contains_observed_rate():
    low, high = _wilson(7, 10)
    assert low < 0.7 < high
    with pytest.raises(ValueError):
        _wilson(1, 0)


def test_evaluation_is_reproducible_except_timestamp():
    first = evaluate(trials=5, iterations=8)
    second = evaluate(trials=5, iterations=8)
    first.pop("completed_at")
    second.pop("completed_at")
    assert first == second
    assert first["classification"] == ("deterministic-fixture-evaluation-not-real-boom-evidence")
    assert first["guided"]["discovery_rate"] == 1.0
    assert first["guided"]["false_positives"] == 0
    assert len(first["random_trials"]) == 5
    assert (
        first["provenance"]["evaluator_sha256"]
        == sha256((ROOT / "src/spechunter/evaluation.py").read_bytes()).hexdigest()
    )


def test_cli_writes_evaluation_atomically(tmp_path, monkeypatch):
    output = tmp_path / "evaluation.json"
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "spechunter",
            "evaluate",
            "--trials",
            "3",
            "--iterations",
            "4",
            "--output",
            str(output),
        ],
    )
    assert main() == 0
    report = json.loads(output.read_text())
    assert report["random_seeds"] == {"first": 0, "last": 2, "count": 3}
