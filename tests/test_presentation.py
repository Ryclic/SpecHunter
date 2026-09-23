import json
from copy import deepcopy
from hashlib import sha256
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
    assert "Microarchitectural Spectre taxonomy" in page
    assert "spectre-v1-bcb" in page
    assert "spectre-v4-ssb" in page


def test_renderer_adds_hash_bound_attack_corpus(tmp_path):
    report_path = EVIDENCE / "vertex-boom-demo-2026-09-11.json"
    simulator = json.loads(report_path.read_text())["provenance"]["simulator_sha256"]
    scorecard = {
        "attack_programs": 8,
        "mutation_detection_rate": 1.0,
        "repair_clean_rate": 1.0,
        "inconclusive_programs": 0,
        "simulator_executions": 64,
    }
    corpus = tmp_path / "corpus.json"
    corpus.write_text(json.dumps({"simulator_sha256": simulator, "scorecard": scorecard}))
    corpus_seal = tmp_path / "corpus-seal.json"
    corpus_seal.write_text(
        json.dumps(
            {
                "attack_corpus": corpus.name,
                "attack_corpus_sha256": sha256(corpus.read_bytes()).hexdigest(),
                "simulator_sha256": simulator,
                "scorecard": scorecard,
            }
        )
    )
    output = tmp_path / "demo.html"
    result = render(
        report_path,
        EVIDENCE / "vertex-boom-demo-seal-2026-09-11.json",
        output,
        corpus_path=corpus,
        corpus_seal_path=corpus_seal,
    )
    page = output.read_text()
    assert "Held-out repair gate" in page
    assert "100%" in page
    assert result["attack_corpus_sha256"] == sha256(corpus.read_bytes()).hexdigest()


def test_renderer_adds_sealed_fixture_comparison(tmp_path):
    output = tmp_path / "demo.html"
    result = render(
        EVIDENCE / "vertex-boom-demo-2026-09-11.json",
        EVIDENCE / "vertex-boom-demo-seal-2026-09-11.json",
        output,
        evaluation_path=EVIDENCE / "fixture-guided-vs-random-2026-09-19.json",
        evaluation_seal_path=EVIDENCE / "fixture-guided-vs-random-seal-2026-09-19.json",
    )
    page = output.read_text()
    assert "Guided versus random evaluation" in page
    assert "57.25%" in page
    assert result["evaluation_sha256"]


def test_renderer_adds_sealed_vertex_repeatability(tmp_path):
    output = tmp_path / "demo.html"
    result = render(
        EVIDENCE / "vertex-boom-demo-2026-09-11.json",
        EVIDENCE / "vertex-boom-demo-seal-2026-09-11.json",
        output,
        repeatability_path=EVIDENCE / "vertex-fixture-repeatability-2026-09-16.json",
        repeatability_seal_path=(EVIDENCE / "vertex-fixture-repeatability-seal-2026-09-16.json"),
    )
    page = output.read_text()
    assert "LLM loop repeatability" in page
    assert "10/10" in page
    assert "$0.0053752" in page
    assert result["repeatability_sha256"]


def test_renderer_adds_sealed_chia_execution(tmp_path):
    output = tmp_path / "demo.html"
    result = render(
        EVIDENCE / "vertex-boom-demo-2026-09-11.json",
        EVIDENCE / "vertex-boom-demo-seal-2026-09-11.json",
        output,
        chia_path=EVIDENCE / "chia-vertex-loop-2026-09-16.json",
        chia_seal_path=EVIDENCE / "chia-vertex-loop-seal-2026-09-16.json",
    )
    page = output.read_text()
    assert "Executed through CHIA" in page
    assert "1.0.1" in page
    assert "2.54.0" in page
    assert result["chia_evidence_sha256"]


def test_renderer_adds_sealed_rtl_repair_regression(tmp_path):
    output = tmp_path / "demo.html"
    result = render(
        EVIDENCE / "vertex-boom-demo-2026-09-11.json",
        EVIDENCE / "vertex-boom-demo-seal-2026-09-11.json",
        output,
        rtl_repair_seal_path=(EVIDENCE / "boom-load-gate-regression-seal-2026-09-16.json"),
    )
    page = output.read_text()
    assert "Candidate RTL repair built" in page
    assert "not a validated security fix" in page
    assert "fd4a264c1499cb2c3614cf05de4533e3b31ce2d921650452bca59072e55179c3" in page
    assert result["rtl_repair_seal_sha256"]


def test_renderer_adds_sealed_issue_715_assessment(tmp_path):
    output = tmp_path / "demo.html"
    result = render(
        EVIDENCE / "vertex-boom-demo-2026-09-11.json",
        EVIDENCE / "vertex-boom-demo-seal-2026-09-11.json",
        output,
        issue_715_seal_path=(EVIDENCE / "boom-issue-715-assessment-seal-2026-09-16.json"),
    )
    page = output.read_text()
    assert "Known BOOM issue assessed" in page
    assert "no vulnerability or repair claim" in page
    assert result["issue_715_seal_sha256"]


def test_renderer_adds_original_attachment_case(tmp_path):
    output = tmp_path / "demo.html"
    result = render(
        EVIDENCE / "vertex-boom-demo-2026-09-11.json",
        EVIDENCE / "vertex-boom-demo-seal-2026-09-11.json",
        output,
        issue_715_attachment_seal_path=(
            EVIDENCE / "boom-issue-715-attachment-demo-seal-2026-09-20.json"
        ),
    )
    page = output.read_text()
    assert "Original issue #715 attachment on historical BOOM" in page
    assert "RTL candidates assessed" in page
    assert "The reported protected-data-dependent mechanism is not reproduced" in page
    assert "Fourth candidate verdict" in page
    assert "no security fix is claimed" in page
    assert "load through" in page
    assert result["issue_715_attachment_seal_sha256"] in page


def test_original_attachment_seal_rejects_tampered_witness(tmp_path):
    seal_path = EVIDENCE / "boom-issue-715-attachment-demo-seal-2026-09-20.json"
    seal = json.loads(seal_path.read_text())
    (tmp_path / seal_path.name).write_text(seal_path.read_text())
    names = {
        seal["baseline"]["witness"],
        seal["baseline"]["waveform"],
        seal["baseline"]["run_log"],
        seal["v4_build"],
        seal["v4_run_log"],
        seal["disassembly"],
    }
    for repair in seal["repairs"]:
        names.update(
            repair[key] for key in ("witness", "waveform", "build", "comparison", "run_log")
        )
    for name in names - {seal["baseline"]["witness"]}:
        (tmp_path / name).symlink_to(EVIDENCE / name)
    baseline = json.loads((EVIDENCE / seal["baseline"]["witness"]).read_text())
    baseline["mechanism_witnessed"] = False
    (tmp_path / seal["baseline"]["witness"]).write_text(json.dumps(baseline))
    with pytest.raises(PresentationError, match="original attachment evidence differs"):
        render(
            EVIDENCE / "vertex-boom-demo-2026-09-11.json",
            EVIDENCE / "vertex-boom-demo-seal-2026-09-11.json",
            tmp_path / "demo.html",
            issue_715_attachment_seal_path=tmp_path / seal_path.name,
        )


def test_original_attachment_seal_rejects_wrong_run_seed(tmp_path):
    seal_path = EVIDENCE / "boom-issue-715-attachment-demo-seal-2026-09-20.json"
    seal = json.loads(seal_path.read_text())
    (tmp_path / seal_path.name).write_text(seal_path.read_text())
    names = {seal["baseline"][key] for key in ("witness", "waveform", "run_log")} | {
        seal["v4_build"],
        seal["v4_run_log"],
        seal["disassembly"],
    }
    for repair in seal["repairs"]:
        names.update(
            repair[key] for key in ("witness", "waveform", "build", "comparison", "run_log")
        )
    for name in names - {seal["v4_run_log"]}:
        (tmp_path / name).symlink_to(EVIDENCE / name)
    v4_run = (EVIDENCE / seal["v4_run_log"]).read_text()
    (tmp_path / seal["v4_run_log"]).write_text(v4_run.replace("seed 1789717734", "seed 1"))
    with pytest.raises(PresentationError, match="original attachment evidence differs"):
        render(
            EVIDENCE / "vertex-boom-demo-2026-09-11.json",
            EVIDENCE / "vertex-boom-demo-seal-2026-09-11.json",
            tmp_path / "demo.html",
            issue_715_attachment_seal_path=tmp_path / seal_path.name,
        )


def test_original_attachment_seal_rejects_altered_disassembly(tmp_path):
    seal_path = EVIDENCE / "boom-issue-715-attachment-demo-seal-2026-09-20.json"
    seal = json.loads(seal_path.read_text())
    (tmp_path / seal_path.name).write_text(seal_path.read_text())
    names = {seal["baseline"][key] for key in ("witness", "waveform", "run_log")} | {
        seal["v4_build"],
        seal["v4_run_log"],
    }
    for repair in seal["repairs"]:
        names.update(
            repair[key] for key in ("witness", "waveform", "build", "comparison", "run_log")
        )
    for name in names:
        (tmp_path / name).symlink_to(EVIDENCE / name)
    source = (EVIDENCE / seal["disassembly"]).read_text()
    (tmp_path / seal["disassembly"]).write_text(source + "\nchanged\n")
    with pytest.raises(PresentationError, match="original attachment evidence differs"):
        render(
            EVIDENCE / "vertex-boom-demo-2026-09-11.json",
            EVIDENCE / "vertex-boom-demo-seal-2026-09-11.json",
            tmp_path / "demo.html",
            issue_715_attachment_seal_path=tmp_path / seal_path.name,
        )


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
    seal["report"] = candidate.name
    seal["report_sha256"] = sha256(candidate.read_bytes()).hexdigest()
    seal_path = tmp_path / "seal.json"
    seal_path.write_text(json.dumps(seal))
    output = tmp_path / "demo.html"
    render(candidate, seal_path, output)
    page = output.read_text()
    assert "<img src=x" not in page
    assert "&lt;img src=x" in page
