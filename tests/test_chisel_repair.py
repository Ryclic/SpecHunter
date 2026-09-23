"""Unit tests for ChiselRepairSynthesizer and ChiselPatch generation."""

import tempfile
from pathlib import Path

import pytest

from spechunter.chisel_repair import ChiselRepairSynthesizer


def test_list_patches():
    synthesizer = ChiselRepairSynthesizer()
    patches = synthesizer.list_patches()
    assert "gate-faulting-loads" in patches
    assert "issue-715-translation-gate" in patches
    assert "bpu-barrier-flush" in patches
    assert "remove-seeded-cache-leak" in patches


def test_synthesize_gate_faulting_loads():
    synthesizer = ChiselRepairSynthesizer()
    patch = synthesizer.synthesize("gate-faulting-loads")

    assert patch.patch_id == "gate-faulting-loads"
    assert "lsu.scala" in patch.target_file
    assert patch.cwe_id == "CWE-1272"
    assert "pmp_check_passed" in patch.patched_code
    assert "--- a/generators/boom" in patch.unified_diff
    assert len(patch.sha256_digest) == 64
    assert synthesizer.verify_syntax(patch) is True


def test_synthesize_issue_715():
    synthesizer = ChiselRepairSynthesizer()
    patch = synthesizer.synthesize("issue-715-translation-gate")

    assert patch.patch_id == "issue-715-translation-gate"
    assert "dtlb_translation_resolved" in patch.patched_code
    assert patch.cwe_id == "CWE-1037"
    assert synthesizer.verify_syntax(patch) is True


def test_synthesize_bpu_flush():
    synthesizer = ChiselRepairSynthesizer()
    patch = synthesizer.synthesize("bpu-barrier-flush")

    assert patch.patch_id == "bpu-barrier-flush"
    assert "bpu.scala" in patch.target_file
    assert "bht.io.flush := priv_transition" in patch.patched_code
    assert synthesizer.verify_syntax(patch) is True


def test_export_patch_file():
    synthesizer = ChiselRepairSynthesizer()
    patch = synthesizer.synthesize("gate-faulting-loads")

    with tempfile.TemporaryDirectory() as tmpdir:
        dest = Path(tmpdir) / "gate.patch"
        out = synthesizer.export_patch_file(patch, dest)
        assert out.is_file()
        content = out.read_text(encoding="utf-8")
        assert "diff" in content or "---" in content
        assert "pmp_check_passed" in content


def test_unknown_patch():
    synthesizer = ChiselRepairSynthesizer()
    with pytest.raises(KeyError, match="Unknown patch"):
        synthesizer.synthesize("non-existent-patch")
