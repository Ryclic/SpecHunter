import importlib.util
import json
from pathlib import Path

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
    output = tmp_path / "comparison.json"
    monkeypatch.setattr("sys.argv", [str(SCRIPT), *(str(path) for path in paths), str(output)])
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
    assert result["matched_control_flow"] is True
    assert result["seed_provenance"] == "not-bound-by-vcd"
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
