import importlib.util
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
_spec = importlib.util.spec_from_file_location(
    "package_submission", REPO_ROOT / "tools/package_submission.py"
)
_mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_mod)
package = _mod.package
sha256_file = _mod.sha256_file


def test_package_submission_builds_archives():
    res = package()
    assert res == 0

    tar_path = REPO_ROOT / "artifacts/spechunter_micro2026_submission.tar.gz"
    zip_path = REPO_ROOT / "artifacts/spechunter_micro2026_submission.zip"
    manifest_path = REPO_ROOT / "artifacts/submission_dist/MANIFEST.sha256"

    assert tar_path.is_file()
    assert tar_path.stat().st_size > 100_000

    assert zip_path.is_file()
    assert zip_path.stat().st_size > 100_000

    assert manifest_path.is_file()
    manifest_text = manifest_path.read_text(encoding="utf-8")
    assert "spechunter_micro2026.pdf" in manifest_text
    assert "SUBMISSION.md" in manifest_text
    assert "demo.html" in manifest_text
    assert "spechunter.tex" in manifest_text
    assert "spechunter.typ" in manifest_text


def test_sha256_file_consistency(tmp_path):
    p = tmp_path / "test.txt"
    p.write_bytes(b"SpecHunter MICRO 2026")
    digest = sha256_file(p)
    assert len(digest) == 64
    assert digest.isalnum()
