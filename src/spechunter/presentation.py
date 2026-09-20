"""Render sealed SpecHunter evidence as a self-contained review artifact."""

# The embedded HTML/CSS remains legible as an artifact template with long source lines.
# ruff: noqa: E501

from __future__ import annotations

import json
from hashlib import sha256
from html import escape
from pathlib import Path

from spechunter.attachment_case import AttachmentEvidenceError, verify_seal


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


def _load_chia(evidence_path: Path, seal_path: Path) -> dict:
    evidence_path = evidence_path.resolve()
    evidence = _read(evidence_path)
    seal = _read(seal_path.resolve())
    if seal.get("report") != evidence_path.name or seal.get("report_sha256") != _digest(
        evidence_path
    ):
        raise PresentationError("CHIA evidence does not match its seal")
    expected = evidence.get("orchestration", {})
    if seal.get("orchestration") != expected or expected.get("engine") != "chia":
        raise PresentationError("CHIA orchestration provenance differs")
    if evidence.get("metrics", {}).get("repairs_attacker_exhausted") != 1:
        raise PresentationError("CHIA agent loop is incomplete")
    return evidence


def _load_rtl_repair(seal_path: Path) -> dict:
    seal_path = seal_path.resolve()
    seal = _read(seal_path)
    classification = "source-reviewed-candidate-regression-not-validated-security-fix"
    if (
        seal.get("classification") != classification
        or seal.get("candidate_build_validated") is not True
        or seal.get("target_regression_validated") is not True
        or seal.get("security_fix_validated") is not False
    ):
        raise PresentationError("RTL repair evidence classification differs")
    for name_key, hash_key in (
        ("baseline_smoke", "baseline_smoke_sha256"),
        ("prior_baseline_matrix", "prior_baseline_matrix_sha256"),
        ("repair_build", "repair_build_sha256"),
        ("repair_matrix", "repair_matrix_sha256"),
    ):
        artifact = seal_path.parent / str(seal.get(name_key, ""))
        if not artifact.is_file() or seal.get(hash_key) != _digest(artifact):
            raise PresentationError("RTL repair artifact does not match its seal")
    matrix = _read(seal_path.parent / seal["repair_matrix"])
    scenarios = matrix.get("scenarios")
    if (
        not isinstance(scenarios, list)
        or len(scenarios) != 2
        or any(item.get("status") != "clean" for item in scenarios)
    ):
        raise PresentationError("RTL repair target regression is incomplete")
    return seal


def _load_issue_715_assessment(seal_path: Path) -> dict:
    seal_path = seal_path.resolve()
    seal = _read(seal_path)
    if (
        seal.get("classification") != "upstream-issue-715-not-reproduced-on-current-pin"
        or seal.get("vulnerability_reproduced") is not False
        or seal.get("security_fix_validated") is not False
        or seal.get("executions") != 4
    ):
        raise PresentationError("issue #715 assessment classification differs")
    for name_key, hash_key in (
        ("source_provenance", "source_provenance_sha256"),
        ("smoke_evidence", "smoke_evidence_sha256"),
        ("assessment_matrix", "assessment_matrix_sha256"),
    ):
        artifact = seal_path.parent / str(seal.get(name_key, ""))
        if not artifact.is_file() or seal.get(hash_key) != _digest(artifact):
            raise PresentationError("issue #715 artifact does not match its seal")
    return seal


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
    chia_path: Path | None = None,
    chia_seal_path: Path | None = None,
    rtl_repair_seal_path: Path | None = None,
    issue_715_seal_path: Path | None = None,
    issue_715_attachment_seal_path: Path | None = None,
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
    chia_section = ""
    chia_hash = None
    if chia_path is not None or chia_seal_path is not None:
        if chia_path is None or chia_seal_path is None:
            raise PresentationError("CHIA evidence and seal must be supplied together")
        chia = _load_chia(chia_path, chia_seal_path)
        chia_hash = _digest(chia_path)
        orchestration = chia["orchestration"]
        chia_section = f"""<section><h2>Executed through CHIA</h2>
<p>The same nested Vertex workflow ran through the decorated CHIA node on an owned local Ray runtime.</p>
<div class="grid"><div class="card"><b>{escape(orchestration["chialoops_version"])}</b><span>CHIA version</span></div>
<div class="card"><b>{escape(orchestration["ray_version"])}</b><span>Ray version</span></div>
<div class="card"><b>{chia["metrics"]["llm_calls"]}</b><span>Gemini calls</span></div>
<div class="card"><b>Yes</b><span>Attacker exhausted</span></div></div></section>"""
    rtl_repair_section = ""
    rtl_repair_hash = None
    if rtl_repair_seal_path is not None:
        rtl_repair = _load_rtl_repair(rtl_repair_seal_path)
        rtl_repair_hash = _digest(rtl_repair_seal_path)
        rtl_repair_section = f"""<section><h2>Candidate RTL repair built</h2>
<p>The source-reviewed LSU patch compiled into a distinct BOOM simulator and passed eight target-regression executions. The baseline was already clean, so this is build and regression evidence, not a validated security fix.</p>
<div class="grid"><div class="card"><b>8</b><span>Repaired BOOM executions</span></div>
<div class="card"><b>2/2</b><span>Scenarios clean</span></div>
<div class="card"><b>Yes</b><span>Distinct binary</span></div>
<div class="card"><b>No</b><span>Security fix validated</span></div></div>
<div class="card"><span>Repaired simulator SHA-256</span><code>{escape(str(rtl_repair["repaired_simulator_sha256"]))}</code></div></section>"""
    issue_715_section = ""
    issue_715_hash = None
    if issue_715_seal_path is not None:
        issue_715 = _load_issue_715_assessment(issue_715_seal_path)
        issue_715_hash = _digest(issue_715_seal_path)
        issue_715_section = f"""<section><h2>Known BOOM issue assessed</h2>
<p>A reviewed branch-misprediction adaptation of upstream BOOM issue #715 ran against the current pinned simulator. All matched-secret executions were deterministic and clean, so no vulnerability or repair claim is made for this revision.</p>
<div class="grid"><div class="card"><b>#715</b><span>Upstream issue</span></div>
<div class="card"><b>{issue_715["executions"]}</b><span>BOOM executions</span></div>
<div class="card"><b>Clean</b><span>Current pin result</span></div>
<div class="card"><b>No</b><span>Fix claimed</span></div></div></section>"""
    attachment_section = ""
    attachment_hash = None
    if issue_715_attachment_seal_path is not None:
        try:
            attachment = verify_seal(issue_715_attachment_seal_path.resolve())
        except (AttachmentEvidenceError, OSError, ValueError) as exc:
            raise PresentationError(f"original attachment evidence differs: {exc}") from exc
        attachment_hash = _digest(issue_715_attachment_seal_path)
        baseline_witness = _read(
            issue_715_attachment_seal_path.parent / attachment["baseline"]["witness"]
        )
        attachment_section = f"""<section><h2>Original issue #715 attachment on historical BOOM</h2>
<p>The original upstream ELF ran on the reported Chipyard/BOOM revisions. Its waveform records a wrong-path protected-page request and later dependent-address requests before the branch resolved. This is a correlated event chain, not direct proof of register-level dependence or secret disclosure.</p>
<div class="grid"><div class="card"><b>{baseline_witness["branch_fetch_cycle"]}</b><span>Branch fetch cycle</span></div>
<div class="card"><b>{len(baseline_witness["dependent_load_requests"])}</b><span>Dependent-address requests</span></div>
<div class="card"><b>{len(attachment["repairs"])}</b><span>RTL candidates rejected</span></div>
<div class="card"><b>Unresolved</b><span>Fourth candidate verdict</span></div></div>
<p>The first three candidate repairs reproduced the dependent requests and failed the matched-trace gate. The fourth built and ran, but its waveform was not recovered; no security fix is claimed.</p>
<div class="card"><span>Original waveform SHA-256</span><code>{escape(attachment["baseline"]["waveform_sha256"])}</code></div>
<div class="card"><span>Case seal SHA-256</span><code>{escape(attachment_hash)}</code></div></section>"""
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
{chia_section}
{rtl_repair_section}
{issue_715_section}
{attachment_section}
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
        "chia_evidence_sha256": chia_hash,
        "rtl_repair_seal_sha256": rtl_repair_hash,
        "issue_715_seal_sha256": issue_715_hash,
        "issue_715_attachment_seal_sha256": attachment_hash,
    }
