import importlib.util
import json
from copy import deepcopy
from pathlib import Path

import pytest

ROOT = Path(__file__).parents[1]
EVIDENCE = ROOT / "docs/evidence"
SCRIPT = ROOT / "tools/seal_vertex_repeatability.py"
SPEC = importlib.util.spec_from_file_location("seal_vertex_repeatability", SCRIPT)
assert SPEC and SPEC.loader
SEAL = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(SEAL)


def artifacts():
    evidence = json.loads((EVIDENCE / "vertex-fixture-repeatability-2026-09-16.json").read_text())
    ledger = json.loads(
        (EVIDENCE / "vertex-fixture-repeatability-cost-2026-09-16.json").read_text()
    )
    return evidence, ledger


def test_live_repeatability_evidence_has_ten_settled_full_loops():
    evidence, ledger = artifacts()
    SEAL.verify(evidence, ledger)
    assert evidence["summary"]["full_loop_success_rate"] == 1.0
    assert evidence["cost"]["accounted_usd"] == "0.0053752"


def test_seal_rejects_unverified_repair_or_unsettled_cost():
    evidence, ledger = artifacts()
    broken = deepcopy(evidence)
    broken["trials"][0]["report"]["results"][0]["repair"]["verified"] = False
    with pytest.raises(SEAL.SealError, match="unverified"):
        SEAL.verify(broken, ledger)
    broken_ledger = deepcopy(ledger)
    broken_ledger["entries"][0]["state"] = "reserved"
    with pytest.raises(SEAL.SealError, match="unsettled"):
        SEAL.verify(evidence, broken_ledger)
