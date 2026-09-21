import importlib.util
import json
from pathlib import Path

import pytest

ROOT = Path(__file__).parents[1]
SCRIPT = ROOT / "tools/boom/seal_attack_corpus.py"
SPEC = importlib.util.spec_from_file_location("seal_attack_corpus", SCRIPT)
assert SPEC and SPEC.loader
SEAL = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(SEAL)


def write(path, value):
    path.write_text(json.dumps(value))
    return path


def fixtures(tmp_path):
    simulator = "a" * 64
    corpus = write(
        tmp_path / "corpus.json",
        {
            "experiment": "boom-held-out-attack-corpus-repair-evaluation",
            "classification": SEAL.CLASSIFICATION,
            "scorecard": SEAL.EXPECTED_SCORECARD,
            "results": [{} for _ in range(8)],
            "simulator_sha256": simulator,
        },
    )
    control = write(tmp_path / "control.json", {"simulator_sha256": simulator})
    report = write(tmp_path / "report.json", {"provenance": {"simulator_sha256": simulator}})
    return corpus, control, report


def test_seal_binds_complete_corpus_to_prior_evidence(tmp_path):
    corpus, control, report = fixtures(tmp_path)
    seal = SEAL.create_seal(corpus, control, report)
    assert seal["scorecard"] == SEAL.EXPECTED_SCORECARD
    assert seal["simulator_sha256"] == "a" * 64
    assert seal["attack_corpus_sha256"] == SEAL.digest(corpus)


def test_seal_rejects_scorecard_or_simulator_drift(tmp_path):
    corpus, control, report = fixtures(tmp_path)
    value = json.loads(corpus.read_text())
    value["scorecard"]["repair_clean_rate"] = 0.875
    write(corpus, value)
    with pytest.raises(SEAL.SealError, match="scorecard"):
        SEAL.create_seal(corpus, control, report)
    corpus, control, report = fixtures(tmp_path)
    write(control, {"simulator_sha256": "b" * 64})
    with pytest.raises(SEAL.SealError, match="different simulators"):
        SEAL.create_seal(corpus, control, report)


def test_checked_in_seal_binds_live_artifacts():
    evidence = ROOT / "docs/evidence"
    seal = json.loads((evidence / "boom-attack-corpus-seal-2026-09-16.json").read_text())
    for name, hash_field in (
        (seal["attack_corpus"], "attack_corpus_sha256"),
        (seal["positive_control"], "positive_control_sha256"),
        (seal["vertex_report"], "vertex_report_sha256"),
    ):
        assert SEAL.digest(evidence / name) == seal[hash_field]
    recreated = SEAL.create_seal(
        evidence / seal["attack_corpus"],
        evidence / seal["positive_control"],
        evidence / seal["vertex_report"],
    )
    assert recreated == seal
