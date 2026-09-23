from pathlib import Path


def test_submission_dossier_complete():
    submission_path = Path(__file__).parents[1] / "SUBMISSION.md"
    assert submission_path.is_file(), f"Expected submission dossier at {submission_path}"
    content = submission_path.read_text(encoding="utf-8")

    assert "MICRO 2026 A³ CHIA Hackathon Submission Dossier" in content
    assert "Discovery and resolution of architectural and microarchitectural bugs" in content
    assert "1. Author-Identified Highlights" in content
    assert "2. Abstract" in content
    assert "3. Quickstart Reproducibility" in content
    assert "4. Interactive Command Line Tools" in content
    assert "5. Deliverable Inventory" in content
    assert "6. Cryptographic Provenance Manifest" in content
    assert "tools/run_reproducibility_kit.sh" in content
    assert "paper/spechunter_micro2026.pdf" in content
    assert "docs/demo.html" in content
    assert "spechunter taxonomy" in content
    assert "spechunter ablation" in content
