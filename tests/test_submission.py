from pathlib import Path

ROOT = Path(__file__).parents[1]

# Claims that must never appear in the public docs.
UNSEALED_CLAIMS = ("1091", "1095", "HSA-CERT", "HSA-2026", "CVSS", "89,200", "0.05%")


def test_submission_points_to_sealed_evidence_and_limitations():
    content = (ROOT / "SUBMISSION.md").read_text(encoding="utf-8")
    assert "paper/spechunter_a3_2026.pdf" in content
    assert "tools/verify_evidence.py" in content
    assert "## Limitations" in content
    assert "No new BOOM vulnerability was found" in content
    for seal in sorted((ROOT / "docs/evidence").glob("*seal*.json")):
        if "2026-09-16" in seal.name and "fixture-guided" in seal.name:
            continue  # superseded by the 2026-09-19 evaluation seal
        if "issue-715" in seal.name:
            continue  # indexed by the issue #715 wildcard row
        assert seal.name in content, seal.name
    for claim in UNSEALED_CLAIMS:
        assert claim not in content, claim


def test_readme_does_not_repeat_unsealed_claims():
    content = (ROOT / "README.md").read_text(encoding="utf-8")
    for claim in UNSEALED_CLAIMS:
        assert claim not in content, claim


def test_demo_does_not_repeat_unsealed_claims():
    content = (ROOT / "docs/demo.html").read_text(encoding="utf-8")
    for claim in UNSEALED_CLAIMS:
        assert claim not in content, claim
