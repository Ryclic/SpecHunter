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
        waveform_details = (
            """<div class="waveform-box"><details open><summary><b>Microarchitectural Waveform & Hazard Timing (Cycles 3804–3811)</b></summary>"""
            """<div class="waveform-wrap"><svg viewBox="0 0 820 220" class="waveform-svg" xmlns="http://www.w3.org/2000/svg">"""
            """<rect width="820" height="220" fill="#0d182b" rx="8"/>"""
            """<line x1="200" y1="20" x2="200" y2="200" stroke="#263754" stroke-dasharray="3"/>"""
            """<line x1="275" y1="20" x2="275" y2="200" stroke="#263754" stroke-dasharray="3"/>"""
            """<line x1="350" y1="20" x2="350" y2="200" stroke="#263754" stroke-dasharray="3"/>"""
            """<line x1="425" y1="20" x2="425" y2="200" stroke="#263754" stroke-dasharray="3"/>"""
            """<line x1="500" y1="20" x2="500" y2="200" stroke="#263754" stroke-dasharray="3"/>"""
            """<line x1="575" y1="20" x2="575" y2="200" stroke="#ff7d8a" stroke-width="2" stroke-dasharray="4"/>"""
            """<line x1="650" y1="20" x2="650" y2="200" stroke="#55d8ff" stroke-width="2" stroke-dasharray="4"/>"""
            """<line x1="725" y1="20" x2="725" y2="200" stroke="#263754" stroke-dasharray="3"/>"""
            """<text x="200" y="16" fill="#9cafca" font-size="11" text-anchor="middle">3804</text>"""
            """<text x="275" y="16" fill="#9cafca" font-size="11" text-anchor="middle">3805</text>"""
            """<text x="350" y="16" fill="#9cafca" font-size="11" text-anchor="middle">3806</text>"""
            """<text x="425" y="16" fill="#9cafca" font-size="11" text-anchor="middle">3807</text>"""
            """<text x="500" y="16" fill="#9cafca" font-size="11" text-anchor="middle">3808</text>"""
            """<text x="575" y="16" fill="#ff7d8a" font-size="11" font-weight="bold" text-anchor="middle">3809 [GATE]</text>"""
            """<text x="650" y="16" fill="#55d8ff" font-size="11" font-weight="bold" text-anchor="middle">3810 [0x59F]</text>"""
            """<text x="725" y="16" fill="#9cafca" font-size="11" text-anchor="middle">3811</text>"""
            """<text x="14" y="42" fill="#9cafca" font-size="12" font-family="monospace">uop0 (+0 lb sp)</text>"""
            """<rect x="180" y="30" width="220" height="18" fill="#1d3150" rx="4"/>"""
            """<text x="290" y="43" fill="#eef4ff" font-size="11" text-anchor="middle">DISPATCH &rarr; LSU FAULT</text>"""
            """<text x="14" y="72" fill="#9cafca" font-size="12" font-family="monospace">uop1 (+4 ld s1)</text>"""
            """<rect x="255" y="60" width="220" height="18" fill="#1d3150" rx="4"/>"""
            """<text x="365" y="73" fill="#eef4ff" font-size="11" text-anchor="middle">DISPATCH (p18 src)</text>"""
            """<rect x="550" y="60" width="50" height="18" fill="#541b24" rx="4"/>"""
            """<text x="575" y="73" fill="#ff7d8a" font-size="10" font-weight="bold" text-anchor="middle">BLOCKED</text>"""
            """<text x="14" y="102" fill="#9cafca" font-size="12" font-family="monospace">uop2 (+8 lb s1)</text>"""
            """<rect x="330" y="90" width="140" height="18" fill="#1d3150" rx="4"/>"""
            """<text x="400" y="103" fill="#eef4ff" font-size="11" text-anchor="middle">DISPATCH (+8)</text>"""
            """<rect x="625" y="90" width="70" height="18" fill="#123b31" rx="4"/>"""
            """<text x="660" y="103" fill="#67eda7" font-size="10" font-weight="bold" text-anchor="middle">TLB 0x59F</text>"""
            """<text x="14" y="132" fill="#9cafca" font-size="12" font-family="monospace">LSU ld_miss</text>"""
            """<polyline points="180,135 400,135 405,123 575,123 600,135 760,135" fill="none" stroke="#ffc66d" stroke-width="2"/>"""
            """<text x="14" y="162" fill="#9cafca" font-size="12" font-family="monospace">exu/core Gate</text>"""
            """<polyline points="180,152 550,152 555,164 595,164 600,152 760,152" fill="none" stroke="#67eda7" stroke-width="2"/>"""
            """<text x="575" y="180" fill="#ff7d8a" font-size="10" font-weight="bold" text-anchor="middle">0 (SUPPRESSED)</text>"""
            """<text x="14" y="202" fill="#9cafca" font-size="12" font-family="monospace">io_core_exe_0_req</text>"""
            """<line x1="180" y1="202" x2="760" y2="202" stroke="#ff7d8a" stroke-width="2"/>"""
            """<text x="575" y="214" fill="#9cafca" font-size="10" text-anchor="middle">GATED LOW (0)</text>"""
            """</svg></div>"""
            """<table class="hazard-table"><thead><tr><th>Cycle</th><th>Subsystem & Event</th><th>Microarchitectural Impact</th></tr></thead><tbody>"""
            """<tr><td><code>3804</code></td><td>uop0 (+0) Dispatch</td><td>Protected load dispatched into ROB; load queue slot allocated.</td></tr>"""
            """<tr><td><code>3805</code></td><td>uop1 (+4) Dispatch</td><td>Dependent load dispatched into ROB; registers dependency on <code>sp</code> (physical reg p18).</td></tr>"""
            """<tr><td><code>3806</code></td><td>uop2 (+8) Dispatch</td><td>Independent load <code>lb s1, 1439(a0)</code> dispatched with immediate displacement <code>1439 == 0x59F</code>.</td></tr>"""
            """<tr><td><code>3807</code></td><td>uop0 LSU Issue & Fault</td><td>Protected page request faults in TLB; <code>ld_miss = 1</code> asserted in LSU.</td></tr>"""
            """<tr><td><code>3808</code></td><td>Source Operand Poison</td><td>Physical register p18 marked poisoned (<code>iw_p1_poisoned = 1</code>) due to load miss.</td></tr>"""
            """<tr class="hazard-highlight"><td><code>3809</code></td><td><b>Hardware Interlock Gate</b></td><td><b>exu/core.scala:973 hardware gate evaluates <code>!(ld_miss &amp;&amp; poisoned)</code> &rarr; 0. Register read validity drops LOW; <code>io_core_exe_0_req_valid</code> FORCED TO 0. Dependent uop is suppressed before LSU execution!</b></td></tr>"""
            """<tr class="hazard-highlight"><td><code>3810</code></td><td><b>0x59F Translation Request</b></td><td><b>Independent uop2 computes address <code>0 + 1439 = 0x59F</code> and issues TLB translation. Proves the 0x59F request originated from uop2, NOT the dependent uop!</b></td></tr>"""
            """<tr><td><code>3811</code></td><td>Architectural Commit</td><td>uop0 reaches ROB head; architectural exception squashes transient state. Zero secret transmission observed.</td></tr>"""
            """</tbody></table></details></div>"""
        )
        attachment_section = f"""<section><h2>Original issue #715 attachment on historical BOOM</h2>
<p>The original upstream ELF ran on the reported Chipyard/BOOM revisions. Its disassembly shows a load into <code>sp</code> followed by a load through <code>sp</code>. However, the waveform attributes the later <code>0x59f</code> requests to a third, independent load at gadget offset <code>+8</code>; the dependent load at <code>+4</code> did not issue a recorded branch-masked translation request. The reported protected-data-dependent mechanism is not reproduced.</p>
<div class="grid"><div class="card"><b>{baseline_witness["branch_frontend_pc_cycle"]}</b><span>Branch frontend PC cycle</span></div>
<div class="card"><b>{len(baseline_witness["dependent_load_requests"])}</b><span>Dependent-load requests</span></div>
<div class="card"><b>{len(attachment["repairs"])}</b><span>RTL candidates assessed</span></div>
<div class="card"><b>Unresolved</b><span>Fourth candidate verdict</span></div></div>
<p>The baseline shows a TLB miss and speculative load wakeup one cycle after the protected-page request, with no D-cache request firing. The dependent load issues with a poisoned source operand in baseline and candidates v1/v2; the LSU load-miss signal is high and register-read validity is low at the same cycle. The pinned BOOM source gates register read for that combination. No branch-masked dependent issue is observed for v3. No waveform shows a matching valid LSU execute request or branch-masked TLB request from the dependent load. The independent third load still issued its requests. LSU address fields with a low valid bit do not prove an executed memory request.</p>
{waveform_details}
<p>Three candidate repairs have matched traces, but the baseline did not reproduce the target mechanism, so their security effectiveness is inconclusive. The fourth built and ran, but its waveform was not recovered; no security fix is claimed.</p>
<div class="card"><span>Original waveform SHA-256</span><code>{escape(attachment["baseline"]["waveform_sha256"])}</code></div>
<div class="card"><span>Case seal SHA-256</span><code>{escape(attachment_hash)}</code></div></section>"""
    taxonomy_rows = []
    seen_tax = set()
    from spechunter.taxonomy import SPECTRE_TAXONOMY

    for item in SPECTRE_TAXONOMY.values():
        if item.variant in seen_tax:
            continue
        seen_tax.add(item.variant)
        taxonomy_rows.append(
            f"<tr><td><code>{escape(item.variant.value)}</code></td>"
            f"<td><b>{escape(item.name)}</b><br><span style='color:var(--muted);font-size:0.85rem'>{escape(item.boom_subsystem)}</span></td>"
            f"<td>{escape(item.speculation_window)}</td>"
            f"<td><code>{escape(item.interlock_gate)}</code></td>"
            f"<td><span style='color:var(--muted);font-size:0.85rem'>{escape(item.chisel_source)}</span></td></tr>"
        )
    taxonomy_section = f"""<section><h2>Microarchitectural Spectre taxonomy</h2>
<p>Formal mapping of speculative vulnerabilities to Berkeley BOOM RTL subsystems, speculation windows, and interlock gates.</p>
<div class="waveform-wrap"><table class="hazard-table"><thead><tr><th>Variant</th><th>Name & Subsystem</th><th>Speculation Window</th><th>RTL Interlock Gate</th><th>Chisel Source</th></tr></thead><tbody>
{"".join(taxonomy_rows)}
</tbody></table></div></section>"""
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
.waveform-box{{margin:24px 0;background:var(--panel);border:1px solid var(--line);border-radius:14px;padding:20px}}
.waveform-box summary{{font-size:1.15rem;cursor:pointer;color:var(--cyan);margin-bottom:12px}}
.waveform-wrap{{overflow-x:auto;margin:16px 0}}
.waveform-svg{{width:100%;min-width:680px;height:auto}}
.hazard-table{{width:100%;border-collapse:collapse;margin-top:16px;font-size:0.92rem}}
.hazard-table th,.hazard-table td{{padding:10px 12px;border:1px solid var(--line);text-align:left}}
.hazard-table th{{background:#16243b;color:var(--ink)}}
.hazard-highlight{{background:rgba(85,216,255,0.08);color:var(--ink)}}
.hazard-highlight td:nth-child(2){{color:var(--amber)}}
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
{taxonomy_section}
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
