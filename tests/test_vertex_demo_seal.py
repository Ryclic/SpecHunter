import importlib.util
from copy import deepcopy
from pathlib import Path

import pytest

ROOT = Path(__file__).parents[1]
SCRIPT = ROOT / "tools/boom/seal_vertex_demo.py"
SPEC = importlib.util.spec_from_file_location("seal_vertex_demo", SCRIPT)
assert SPEC and SPEC.loader
SEAL = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(SEAL)


def fixtures():
    transcript = [
        {"stage": "recon"},
        {"stage": "attacker"},
        {"stage": "validator"},
        {"stage": "repair", "repair_id": "remove-seeded-cache-leak"},
        {"stage": "attacker"},
        {"stage": "validator"},
        {"stage": "attacker"},
    ]
    report = {
        "schema_version": 2,
        "strategy": "llm",
        "provider": "vertex",
        "provenance": {
            "kind": "boom",
            "is_boom_evidence": True,
            "simulator_sha256": "simulator",
        },
        "results": [
            {
                "benchmark": {"id": "boom-positive-control"},
                "findings": [{"sha256": "witness"}],
                "transcript": transcript,
                "repair": {
                    "attempted": True,
                    "attacker_exhausted": True,
                    "verified": True,
                    "final_variant": "remove-seeded-cache-leak",
                    "rtl_patch_applied": False,
                },
            }
        ],
        "metrics": {"repairs_attacker_exhausted": 1},
    }
    ledger = {
        "schema_version": 1,
        "entries": [{"state": "settled", "outcome": "success"}],
    }
    control = {
        "classification": "intentional-harness-mutation-not-upstream-boom-vulnerability",
        "simulator_sha256": "simulator",
    }
    return report, ledger, control


def test_seal_requires_complete_vertex_boom_repair_red_team_loop():
    SEAL.validate(*fixtures())
    report, ledger, control = fixtures()
    report["results"][0]["repair"]["attacker_exhausted"] = False
    with pytest.raises(SEAL.SealError, match="attacker exhaustion"):
        SEAL.validate(report, ledger, control)


def test_seal_rejects_unsettled_cost_or_simulator_drift():
    report, ledger, control = fixtures()
    unsettled = deepcopy(ledger)
    unsettled["entries"][0]["state"] = "reserved"
    with pytest.raises(SEAL.SealError, match="unsettled"):
        SEAL.validate(report, unsettled, control)
    drifted = deepcopy(control)
    drifted["simulator_sha256"] = "other"
    with pytest.raises(SEAL.SealError, match="simulator provenance"):
        SEAL.validate(report, ledger, drifted)
