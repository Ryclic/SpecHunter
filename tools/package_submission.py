#!/usr/bin/env python3
"""Automated packaging script for MICRO 2026 A³ Workshop — CHIA Hackathon submission."""

from __future__ import annotations

import hashlib
import tarfile
import zipfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
ARTIFACTS_DIR = REPO_ROOT / "artifacts"
DIST_DIR = ARTIFACTS_DIR / "submission_dist"

DELIVERABLES = [
    ("paper/spechunter_a3_2026.pdf", "spechunter_a3_2026.pdf"),
    ("paper/main.tex", "main.tex"),
    ("paper/main.bib", "main.bib"),
    ("docs/demo.html", "demo.html"),
    ("SUBMISSION.md", "SUBMISSION.md"),
    ("README.md", "README.md"),
]


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    return h.hexdigest()


def package() -> int:
    DIST_DIR.mkdir(parents=True, exist_ok=True)
    manifest_lines = []

    print("=== SpecHunter HotCRP Submission Packager ===")
    print("Collecting primary deliverables:")

    files_to_pack: list[tuple[Path, str]] = []

    for rel_path, arcname in DELIVERABLES:
        src = REPO_ROOT / rel_path
        if not src.is_file():
            print(f"[-] ERROR: Missing deliverable: {src}")
            return 1
        digest = sha256_file(src)
        manifest_lines.append(f"{digest}  {arcname}")
        files_to_pack.append((src, arcname))
        print(f"  ✓ {arcname:<28} (SHA-256: {digest[:16]}...)")

    print("\nCollecting cryptographic evidence seals:")
    evidence_dir = REPO_ROOT / "docs/evidence"
    for ev in sorted(evidence_dir.glob("*")):
        if ev.is_file():
            digest = sha256_file(ev)
            arcname = f"evidence/{ev.name}"
            manifest_lines.append(f"{digest}  {arcname}")
            files_to_pack.append((ev, arcname))
            print(f"  ✓ {arcname:<28} (SHA-256: {digest[:16]}...)")

    # Write manifest
    manifest_path = DIST_DIR / "MANIFEST.sha256"
    manifest_path.write_text("\n".join(manifest_lines) + "\n", encoding="utf-8")
    files_to_pack.append((manifest_path, "MANIFEST.sha256"))

    # Create tar.gz archive
    tar_path = ARTIFACTS_DIR / "spechunter_micro2026_submission.tar.gz"
    with tarfile.open(tar_path, "w:gz") as tar:
        for src, arcname in files_to_pack:
            tar.add(src, arcname=f"spechunter_submission/{arcname}")
    tar_digest = sha256_file(tar_path)
    tar_size = tar_path.stat().st_size

    # Create zip archive
    zip_path = ARTIFACTS_DIR / "spechunter_micro2026_submission.zip"
    with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for src, arcname in files_to_pack:
            zf.write(src, arcname=f"spechunter_submission/{arcname}")
    zip_digest = sha256_file(zip_path)
    zip_size = zip_path.stat().st_size

    print("\nSubmission Packages Built Successfully:")
    print(f"  • TAR.GZ: {tar_path}")
    print(f"    Size:   {tar_size:,} bytes")
    print(f"    SHA256: {tar_digest}")
    print(f"  • ZIP:    {zip_path}")
    print(f"    Size:   {zip_size:,} bytes")
    print(f"    SHA256: {zip_digest}")
    print(f"  • Files:  {len(files_to_pack)} items bundled")
    print("\nReady for HotCRP upload at https://a3-chia-hackathon-26.hotcrp.com/")
    return 0


if __name__ == "__main__":
    raise SystemExit(package())
