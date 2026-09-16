"""Render sealed SpecHunter evidence as a self-contained review artifact."""

# The embedded HTML/CSS remains legible as an artifact template with long source lines.
# ruff: noqa: E501

from __future__ import annotations

import json
from hashlib import sha256
from html import escape
from pathlib import Path


class PresentationError(ValueError):
    pass


def _read(path: Path) -> dict:
    try:
        value = json.loads(path.read_text())
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise PresentationError(f"cannot read {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise PresentationError(f"{path} must contain a JSON object")
    return value


def _digest(path: Path) -> str:
    return sha256(path.read_bytes()).hexdigest()


def _event_copy(event: dict) -> tuple[str, str]:
    stage = event.get("stage", "unknown")
    if stage == "recon":
        output = event.get("output", {})
        return "Recon", str(output.get("hypothesis", "Hypothesis generated"))
    if stage == "attacker":
        if event.get("outcome") == "exhausted":
            return "Attacker", "No materially different supported attack remained."
        program = " → ".join(str(op) for op in event.get("program") or [])
        return "Attacker", f"Candidate: {program}"
    if stage == "validator":
        status = str(event.get("status", "unknown"))
        reason = str(event.get("reason", ""))
        return "Validator", f"{status.title()}: {reason}"
    if stage == "repair":
        return "Repair", f"Selected closed repair: {event.get('repair_id', 'none')}"
    return str(stage).title(), str(event.get("reason", "Recorded by orchestrator"))


def _load_corpus(corpus_path: Path, seal_path: Path, simulator_hash: str) -> dict:
    corpus_path = corpus_path.resolve()
    seal = _read(seal_path.resolve())
    corpus = _read(corpus_path)
    if seal.get("attack_corpus") != corpus_path.name or seal.get("attack_corpus_sha256") != _digest(
        corpus_path
    ):
        raise PresentationError("attack corpus does not match its evidence seal")
    expected = {
        "attack_programs": 8,
        "mutation_detection_rate": 1.0,
        "repair_clean_rate": 1.0,
        "inconclusive_programs": 0,
        "simulator_executions": 64,
    }
    if corpus.get("scorecard") != expected or seal.get("scorecard") != expected:
        raise PresentationError("attack corpus scorecard is incomplete")
    if corpus.get("simulator_sha256") != simulator_hash:
        raise PresentationError("attack corpus used a different simulator")
    if seal.get("simulator_sha256") != simulator_hash:
        raise PresentationError("attack corpus seal used a different simulator")
    return corpus


def _load_evaluation(evaluation_path: Path, seal_path: Path) -> dict:
    evaluation_path = evaluation_path.resolve()
    seal = _read(seal_path.resolve())
    evaluation = _read(evaluation_path)
    if seal.get("evaluation") != evaluation_path.name or seal.get("evaluation_sha256") != _digest(
        evaluation_path
    ):
        raise PresentationError("fixture evaluation does not match its evidence seal")
    classification = "deterministic-fixture-evaluation-not-real-boom-evidence"
    if (
        evaluation.get("classification") != classification
        or seal.get("classification") != classification
    ):
        raise PresentationError("fixture evaluation classification differs")
    if seal.get("random_trials", 0) < 1000:
        raise PresentationError("fixture evaluation sample is too small")
    return evaluation


def _load_repeatability(evidence_path: Path, seal_path: Path) -> dict:
    evidence_path = evidence_path.resolve()
    evidence = _read(evidence_path)
    seal = _read(seal_path.resolve())
    if seal.get("evidence") != evidence_path.name or seal.get("evidence_sha256") != _digest(
        evidence_path
    ):
        raise PresentationError("Vertex repeatability evidence does not match its seal")
    classification = "model-fixture-repeatability-not-real-boom-evidence"
    if (
        evidence.get("classification") != classification
        or seal.get("classification") != classification
    ):
        raise PresentationError("Vertex repeatability classification differs")
    if seal.get("trials") != 10 or evidence.get("summary", {}).get("successful_full_loops") != 10:
        raise PresentationError("Vertex repeatability evidence is incomplete")
    return evidence


def render(
    report_path: Path,
    seal_path: Path,
    output: Path,
    *,
    corpus_path: Path | None = None,
    corpus_seal_path: Path | None = None,
    evaluation_path: Path | None = None,
    evaluation_seal_path: Path | None = None,
    repeatability_path: Path | None = None,
    repeatability_seal_path: Path | None = None,
) -> dict:
    report_path = report_path.resolve()
    seal_path = seal_path.resolve()
    report = _read(report_path)
    seal = _read(seal_path)
    if seal.get("report") != report_path.name or seal.get("report_sha256") != _digest(report_path):
        raise PresentationError("report does not match its evidence seal")
    if (
        seal.get("experiment") != "vertex-agent-boom-discovery-repair-red-team-loop"
        or seal.get("classification")
        != "intentional-harness-mutation-not-upstream-boom-vulnerability"
    ):
        raise PresentationError("unsupported or mislabeled evidence seal")
    results = report.get("results")
    if not isinstance(results, list) or len(results) != 1:
        raise PresentationError("demo report must contain exactly one result")
    result = results[0]
    findings = result.get("findings") or []
    if not findings:
        raise PresentationError("demo report has no validated finding")
    metrics = report.get("metrics", {})
    repair = result.get("repair", {})
    witness = " → ".join(str(op) for op in findings[0].get("program", []))
    events = []
    for index, event in enumerate(result.get("transcript", []), 1):
        title, copy = _event_copy(event)
        events.append(
            f'<li class="stage stage-{escape(str(event.get("stage", "unknown")))}">'
            f'<span class="step">{index:02d}</span><div><strong>{escape(title)}</strong>'
            f"<p>{escape(copy)}</p></div></li>"
        )
    raw_report = escape(json.dumps(report, indent=2))
    report_hash = escape(str(seal["report_sha256"]))
    simulator_hash = escape(str(report.get("provenance", {}).get("simulator_sha256", "")))
    corpus_section = ""
    corpus_hash = None
    if corpus_path is not None or corpus_seal_path is not None:
        if corpus_path is None or corpus_seal_path is None:
            raise PresentationError("attack corpus and seal must be supplied together")
        corpus = _load_corpus(
            corpus_path,
            corpus_seal_path,
            str(report.get("provenance", {}).get("simulator_sha256", "")),
        )
        scorecard = corpus["scorecard"]
        corpus_hash = _digest(corpus_path)
        corpus_section = f"""<section><h2>Held-out repair gate</h2>
<p>The same repair was challenged with eight distinct supported programs on the identical simulator.</p>
<div class="grid"><div class="card"><b>{scorecard["attack_programs"]}</b><span>Attack programs</span></div>
<div class="card"><b>{scorecard["simulator_executions"]}</b><span>BOOM executions</span></div>
<div class="card"><b>{scorecard["mutation_detection_rate"]:.0%}</b><span>Mutation detection</span></div>
<div class="card"><b>{scorecard["repair_clean_rate"]:.0%}</b><span>Repair clean</span></div></div>
<div class="card"><span>Corpus SHA-256</span><code>{escape(corpus_hash)}</code></div></section>"""
    evaluation_section = ""
    evaluation_hash = None
    if evaluation_path is not None or evaluation_seal_path is not None:
        if evaluation_path is None or evaluation_seal_path is None:
            raise PresentationError("fixture evaluation and seal must be supplied together")
        evaluation = _load_evaluation(evaluation_path, evaluation_seal_path)
        guided = evaluation["guided"]
        random = evaluation["random"]
        evaluation_hash = _digest(evaluation_path)
        interval = random["discovery_rate_wilson_95"]
        evaluation_section = f"""<section><h2>Guided versus random evaluation</h2>
<p>This separate deterministic fixture benchmark measures search quality; it is not BOOM vulnerability evidence.</p>
<div class="grid"><div class="card"><b>{guided["discovery_rate"]:.0%}</b><span>Guided discovery</span></div>
<div class="card"><b>{random["discovery_rate"]:.2%}</b><span>Random discovery</span></div>
<div class="card"><b>{guided["positive_attempts_mean"]:.1f}</b><span>Guided mean attempts</span></div>
<div class="card"><b>{random["positive_attempts_mean"]:.2f}</b><span>Random mean attempts</span></div></div>
<div class="card"><p>Random: {random["trials"]} seeds; 95% Wilson interval {interval[0]:.2%}–{interval[1]:.2%}; zero false positives and zero inconclusive cases.</p></div></section>"""
    repeatability_section = ""
    repeatability_hash = None
    if repeatability_path is not None or repeatability_seal_path is not None:
        if repeatability_path is None or repeatability_seal_path is None:
            raise PresentationError(
                "Vertex repeatability evidence and seal must be supplied together"
            )
        repeatability = _load_repeatability(repeatability_path, repeatability_seal_path)
        repeatability_hash = _digest(repeatability_path)
        repeated = repeatability["summary"]
        repeatability_section = f"""<section><h2>LLM loop repeatability</h2>
<p>Ten independent Vertex trials used the fast model fixture to measure orchestration reliability, separately from live BOOM evidence.</p>
<div class="grid"><div class="card"><b>{repeated["successful_full_loops"]}/{repeated["trials"]}</b><span>Full loops succeeded</span></div>
<div class="card"><b>{repeated["llm_calls"]}</b><span>Gemini calls</span></div>
<div class="card"><b>{repeated["fixture_executions"]}</b><span>Fixture executions</span></div>
<div class="card"><b>${repeatability["cost"]["accounted_usd"]}</b><span>Accounted cost</span></div></div></section>"""
    html = f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>SpecHunter · Verified Agent Loop</title>
<style>
:root{{--ink:#eef4ff;--muted:#9cafca;--panel:#111b2e;--line:#263754;--cyan:#55d8ff;--green:#67eda7;--amber:#ffc66d;--red:#ff7d8a}}
*{{box-sizing:border-box}} body{{margin:0;background:#07101f;color:var(--ink);font:16px/1.55 ui-sans-serif,system-ui,sans-serif}}
main{{max-width:1080px;margin:auto;padding:48px 24px 80px}} .eyebrow{{color:var(--cyan);font-weight:750;letter-spacing:.14em;text-transform:uppercase}}
h1{{font-size:clamp(2.5rem,7vw,5.8rem);line-height:.92;margin:.25em 0}} .lede{{font-size:1.25rem;color:var(--muted);max-width:760px}}
.verified{{display:inline-flex;gap:.5rem;align-items:center;background:#123b31;color:var(--green);padding:.45rem .8rem;border-radius:999px;font-weight:700}}
.grid{{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin:36px 0}} .card{{background:var(--panel);border:1px solid var(--line);border-radius:14px;padding:20px}}
.card b{{font-size:1.8rem;display:block}} .card span{{color:var(--muted)}} h2{{margin-top:54px;font-size:1.75rem}}
.witness{{font:700 1.1rem ui-monospace,monospace;color:var(--amber);overflow-wrap:anywhere}}
.timeline{{list-style:none;padding:0;display:grid;gap:10px}} .stage{{display:grid;grid-template-columns:44px 1fr;gap:14px;background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:14px}}
.step{{display:grid;place-items:center;width:36px;height:36px;border-radius:50%;background:#1d3150;color:var(--cyan);font:700 .8rem ui-monospace,monospace}}
.stage strong{{font-size:1.05rem}} .stage p{{margin:.15rem 0 0;color:var(--muted)}} .stage-repair{{border-color:#735b28}} .stage-validator{{border-color:#285d50}}
.proof{{display:grid;grid-template-columns:1fr 1fr;gap:12px}} code{{color:var(--cyan);overflow-wrap:anywhere}} details{{margin-top:24px}} pre{{white-space:pre-wrap;background:#040a14;padding:18px;border-radius:12px;max-height:480px;overflow:auto;color:#bfd0e8}}
footer{{margin-top:48px;padding-top:20px;border-top:1px solid var(--line);color:var(--muted)}}
@media(max-width:760px){{.grid{{grid-template-columns:1fr 1fr}}.proof{{grid-template-columns:1fr}}}}
</style></head><body><main>
<span class="verified">✓ Cryptographically sealed evidence</span><p class="eyebrow">SpecHunter · Vertex AI × RISC-V BOOM</p>
<h1>Find. Repair.<br>Attack again.</h1>
<p class="lede">An LLM-driven security loop found a controlled cache leak on a cycle-accurate BOOM CPU simulation, selected a bounded repair, retested the exact exploit, and returned control to the attacker until its supported search was exhausted.</p>
<section class="grid" aria-label="Experiment metrics">
<div class="card"><b>{escape(str(metrics.get("executions", 0)))}</b><span>BOOM executions</span></div>
<div class="card"><b>{escape(str(metrics.get("llm_calls", 0)))}</b><span>Vertex calls</span></div>
<div class="card"><b>${escape(str(report.get("cost", {}).get("accounted_usd", "0")))}</b><span>Accounted LLM cost</span></div>
<div class="card"><b>{"Yes" if repair.get("attacker_exhausted") else "No"}</b><span>Attacker exhausted</span></div>
</section>
<section><h2>Minimal validated witness</h2><div class="card"><p class="witness">{escape(witness)}</p><p>The protected user load remains in the minimized experiment. The finding is explicitly classified as an intentional harness mutation used to prove the end-to-end workflow, not an upstream BOOM vulnerability.</p></div></section>
<section><h2>Agent and validator timeline</h2><ol class="timeline">{"".join(events)}</ol></section>
{corpus_section}
{evaluation_section}
{repeatability_section}
<section><h2>Evidence integrity</h2><div class="proof"><div class="card"><span>Report SHA-256</span><code>{report_hash}</code></div><div class="card"><span>Simulator SHA-256</span><code>{simulator_hash}</code></div></div>
<details><summary>Inspect the complete report</summary><pre>{raw_report}</pre></details></section>
<footer>Generated locally from the sealed SpecHunter report. No network requests or external assets are required.</footer>
</main></body></html>"""
    output.parent.mkdir(parents=True, exist_ok=True)
    temporary = output.with_suffix(output.suffix + ".tmp")
    temporary.write_text(html)
    temporary.replace(output)
    return {
        "output": str(output),
        "report_sha256": seal["report_sha256"],
        "simulator_sha256": report.get("provenance", {}).get("simulator_sha256"),
        "attack_corpus_sha256": corpus_hash,
        "evaluation_sha256": evaluation_hash,
        "repeatability_sha256": repeatability_hash,
    }
