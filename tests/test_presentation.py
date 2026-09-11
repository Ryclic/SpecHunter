import json
from copy import deepcopy
from pathlib import Path

import pytest

from spechunter.presentation import PresentationError, render

ROOT = Path(__file__).parents[1]
EVIDENCE = ROOT / "docs/evidence"


def test_live_evidence_renders_self_contained_demo(tmp_path):
    output = tmp_path / "demo.html"
    result = render(
        EVIDENCE / "vertex-boom-demo-2026-09-11.json",
        EVIDENCE / "vertex-boom-demo-seal-2026-09-11.json",
        output,
    )
    page = output.read_text()
    assert result["report_sha256"] in page
    assert result["simulator_sha256"] in page
    assert "enter_user → load_secret → probe" in page
    assert "Find. Repair." in page
    assert "No network requests or external assets" in page
    assert "<script" not in page


def test_renderer_rejects_tampered_report(tmp_path):
    report = json.loads((EVIDENCE / "vertex-boom-demo-2026-09-11.json").read_text())
    report["metrics"]["executions"] = 0
    tampered = tmp_path / "vertex-boom-demo-2026-09-11.json"
    tampered.write_text(json.dumps(report))
    with pytest.raises(PresentationError, match="does not match"):
        render(tampered, EVIDENCE / "vertex-boom-demo-seal-2026-09-11.json", tmp_path / "x")


def test_renderer_escapes_untrusted_transcript_text(tmp_path):
    report_path = EVIDENCE / "vertex-boom-demo-2026-09-11.json"
    report = json.loads(report_path.read_text())
    changed = deepcopy(report)
    changed["results"][0]["transcript"][0]["output"]["hypothesis"] = "<img src=x onerror=alert(1)>"
    candidate = tmp_path / "report.json"
    candidate.write_text(json.dumps(changed))
    seal = json.loads((EVIDENCE / "vertex-boom-demo-seal-2026-09-11.json").read_text())
    from hashlib import sha256

    seal["report"] = candidate.name
    seal["report_sha256"] = sha256(candidate.read_bytes()).hexdigest()
    seal_path = tmp_path / "seal.json"
    seal_path.write_text(json.dumps(seal))
    output = tmp_path / "demo.html"
    render(candidate, seal_path, output)
    page = output.read_text()
    assert "<img src=x" not in page
    assert "&lt;img src=x" in page
