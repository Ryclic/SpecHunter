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


def render(report_path: Path, seal_path: Path, output: Path) -> dict:
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
    }
