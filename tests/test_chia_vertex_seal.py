import importlib.util
import json
from copy import deepcopy
from pathlib import Path

import pytest

ROOT = Path(__file__).parents[1]
EVIDENCE = ROOT / "docs/evidence"
SCRIPT = ROOT / "tools/seal_chia_vertex_loop.py"
SPEC = importlib.util.spec_from_file_location("seal_chia_vertex_loop", SCRIPT)
assert SPEC and SPEC.loader
SEAL = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(SEAL)


def artifacts():
    report = json.loads((EVIDENCE / "chia-vertex-loop-2026-09-16.json").read_text())
    ledger = json.loads((EVIDENCE / "chia-vertex-loop-cost-2026-09-16.json").read_text())
    return report, ledger


def test_live_chia_vertex_evidence_has_complete_nested_loop_and_settled_cost():
    report, ledger = artifacts()
    SEAL.verify(report, ledger)
    assert report["orchestration"] == {
        "engine": "chia",
        "execution": "local-ray",
        "node": "run_agent_experiment",
        "chialoops_version": "1.0.1",
        "ray_version": "2.54.0",
    }


def test_chia_seal_rejects_missing_provenance_or_repair():
    report, ledger = artifacts()
    broken = deepcopy(report)
    broken["orchestration"].pop("ray_version")
    with pytest.raises(SEAL.SealError, match="provenance"):
        SEAL.verify(broken, ledger)
    broken = deepcopy(report)
    broken["results"][0]["repair"]["verified"] = False
    with pytest.raises(SEAL.SealError, match="verified repair"):
        SEAL.verify(broken, ledger)
