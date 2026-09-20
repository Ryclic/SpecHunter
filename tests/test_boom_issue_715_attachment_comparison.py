import importlib.util
import json
from pathlib import Path

import pytest

ROOT = Path(__file__).parents[1]
SCRIPT = ROOT / "tools/boom/seal_issue_715_attachment_comparison.py"
SPEC = importlib.util.spec_from_file_location("issue_715_comparison", SCRIPT)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader
SPEC.loader.exec_module(MODULE)


def _seal(tmp_path, monkeypatch, repaired):
    baseline = json.loads(
        (ROOT / "docs/evidence/boom-issue-715-attachment-baseline-2026-09-17.json").read_text()
    )
    build = json.loads(
        (
            ROOT / "docs/evidence/boom-issue-715-attachment-repair-v3-build-2026-09-18.json"
        ).read_text()
    )
    paths = [tmp_path / name for name in ("baseline.json", "repaired.json", "build.json")]
    for path, value in zip(paths, (baseline, repaired, build), strict=True):
        path.write_text(json.dumps(value))
    baseline_run = (
        ROOT / "docs/evidence/boom-issue-715-attachment-baseline-seed-1789717734-2026-09-17.log"
    )
    repaired_run = ROOT / "docs/evidence/boom-issue-715-attachment-repair-v3-run-2026-09-18.log"
    output = tmp_path / "comparison.json"
    monkeypatch.setattr(
        "sys.argv",
        [
            str(SCRIPT),
            *(str(path) for path in paths),
            str(baseline_run),
            str(repaired_run),
            str(output),
        ],
    )
    assert MODULE.main() == 0
    return json.loads(output.read_text())


def test_matched_replay_requires_attacker_return(tmp_path, monkeypatch):
    repaired = json.loads(
        (ROOT / "docs/evidence/boom-issue-715-attachment-baseline-2026-09-17.json").read_text()
    )
    repaired["dependent_load_requests"] = []
    repaired["mechanism_witnessed"] = False
    result = _seal(tmp_path, monkeypatch, repaired)
    assert result["repair_effective"] is True
    assert result["repaired_trigger_preserved"] is True
    assert result["schema_version"] == 4
    assert result["matched_control_flow"] is True
    assert result["seed_provenance"] == "bound-by-run-logs"
    assert result["seed"] == 1789717734
    assert result["security_fix_validated"] is False
    assert result["attacker_retest_required"] is True
    assert result["verdict"] == "repair-blocked-witness"


def test_missing_protected_load_is_not_a_valid_repair(tmp_path, monkeypatch):
    repaired = json.loads(
        (ROOT / "docs/evidence/boom-issue-715-attachment-baseline-2026-09-17.json").read_text()
    )
    repaired["dependent_load_requests"] = []
    repaired["protected_load_requests"] = []
    repaired["mechanism_witnessed"] = False
    result = _seal(tmp_path, monkeypatch, repaired)
    assert result["repair_effective"] is False
    assert result["security_fix_validated"] is False


def test_unrelated_fault_is_not_a_valid_repair(tmp_path, monkeypatch):
    repaired = json.loads(
        (ROOT / "docs/evidence/boom-issue-715-attachment-baseline-2026-09-17.json").read_text()
    )
    repaired["dependent_load_requests"] = []
    repaired["mechanism_witnessed"] = False
    repaired["load_page_faults"][0]["branch_mask"] = "0x2"
    result = _seal(tmp_path, monkeypatch, repaired)
    assert result["repaired_trigger_preserved"] is False
    assert result["repair_effective"] is False


def test_late_fault_is_not_a_valid_repair(tmp_path, monkeypatch):
    repaired = json.loads(
        (ROOT / "docs/evidence/boom-issue-715-attachment-baseline-2026-09-17.json").read_text()
    )
    repaired["dependent_load_requests"] = []
    repaired["mechanism_witnessed"] = False
    repaired["load_page_faults"][0]["cycle"] = 3911
    result = _seal(tmp_path, monkeypatch, repaired)
    assert result["repaired_trigger_preserved"] is False
    assert result["repair_effective"] is False


def test_earlier_resolution_closes_repair_trigger_window(tmp_path, monkeypatch):
    repaired = json.loads(
        (ROOT / "docs/evidence/boom-issue-715-attachment-baseline-2026-09-17.json").read_text()
    )
    repaired["dependent_load_requests"] = []
    repaired["mechanism_witnessed"] = False
    repaired["target_mispredicts"].append({"cycle": 3800, "pc": repaired["branch_pc"]})
    assert MODULE._trigger_preserved(repaired) is False
    result = _seal(tmp_path, monkeypatch, repaired)
    assert result["repair_effective"] is False


def test_timing_shift_still_counts_as_matched_trigger(tmp_path, monkeypatch):
    repaired = json.loads(
        (ROOT / "docs/evidence/boom-issue-715-attachment-baseline-2026-09-17.json").read_text()
    )
    repaired["branch_fetch_cycle"] += 5
    repaired["gadget_fetch_cycles"] = {
        pc: cycle + 5 for pc, cycle in repaired["gadget_fetch_cycles"].items()
    }
    for key in ("protected_load_requests", "load_page_faults", "target_mispredicts"):
        for event in repaired[key]:
            event["cycle"] += 5
    repaired["dependent_load_requests"] = []
    repaired["mechanism_witnessed"] = False
    result = _seal(tmp_path, monkeypatch, repaired)
    assert result["matched_control_flow"] is True
    assert result["repaired_trigger_preserved"] is True
    assert result["repair_effective"] is True


def test_unmatched_trigger_is_inconclusive(tmp_path, monkeypatch):
    repaired = json.loads(
        (ROOT / "docs/evidence/boom-issue-715-attachment-baseline-2026-09-17.json").read_text()
    )
    repaired["dependent_load_requests"] = []
    repaired["protected_load_requests"] = []
    repaired["mechanism_witnessed"] = False
    result = _seal(tmp_path, monkeypatch, repaired)
    assert result["verdict"] == "inconclusive-unmatched-trigger"


def test_comparison_rejects_different_run_seed(tmp_path, monkeypatch):
    witness = ROOT / "docs/evidence/boom-issue-715-attachment-baseline-2026-09-17.json"
    build = ROOT / "docs/evidence/boom-issue-715-attachment-repair-v3-build-2026-09-18.json"
    baseline_run = (
        ROOT / "docs/evidence/boom-issue-715-attachment-baseline-seed-1789717734-2026-09-17.log"
    )
    repaired_run = tmp_path / "repaired.log"
    source = ROOT / "docs/evidence/boom-issue-715-attachment-repair-v3-run-2026-09-18.log"
    repaired_run.write_text(source.read_text().replace("seed 1789717734", "seed 9"))
    monkeypatch.setattr(
        "sys.argv",
        [
            str(SCRIPT),
            str(witness),
            str(witness),
            str(build),
            str(baseline_run),
            str(repaired_run),
            str(tmp_path / "comparison.json"),
        ],
    )
    with pytest.raises(RuntimeError, match="different seeds"):
        MODULE.main()
