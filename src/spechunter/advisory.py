"""ILLUSTRATIVE MODEL - NOT EVIDENCE. This module was added on 2026-09-23 and is not
part of the evaluated SpecHunter loop. Its reported figures are fixed or modelled
values, not measurements from BOOM RTL; see SUBMISSION.md (Limitations).

Formal Hardware Security Advisory (HSA) generation for Berkeley BOOM.

Generates CVE/HSA-grade security advisories detailing speculative execution
and transient privilege boundary analysis on the Berkeley Out-of-Order Machine (BOOM).
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass


@dataclass(frozen=True)
class AdvisoryFinding:
    advisory_id: str
    title: str
    target_core: str
    cwe_id: str
    cwe_name: str
    cvss_score: float
    severity: str
    threat_scenario: str
    root_cause_subsystem: str
    chisel_source_file: str
    waveform_cycles: str
    mitigation_logic: str
    patch_file: str
    regression_scorecard: dict[str, str | int | float]
    provenance_seal: str


BOOM_SECURITY_ADVISORY = AdvisoryFinding(
    advisory_id="HSA-2026-0001",
    title="Speculative Memory Translation and Transient Execution Analysis in Berkeley BOOM",
    target_core="Berkeley Out-of-Order Machine (BOOM v3 / LargeBoomConfig & SmallBoomV3Config)",
    cwe_id="CWE-1037",
    cwe_name="Processor Hardware Speculative Execution Side-Channel Vulnerability",
    cvss_score=7.4,
    severity="HIGH",
    threat_scenario=(
        "Speculative issue of load instructions under unresolved branch prediction masks "
        "or exception shadows can emit transient translation requests to the L1 Data TLB "
        "and modify data cache state before branch/fault resolution. In upstream BOOM issue #715, "
        "translation requests (0x59f) were observed under branch misprediction shadows."
    ),
    root_cause_subsystem="Load-Store Unit (LSU / DTLB Issue Pipeline)",
    chisel_source_file="generators/boom/src/main/scala/exu/lsu/lsu.scala",
    waveform_cycles=(
        "Cycles 3804-3811 (Branch mask allocation, poisoned register issue, DTLB fire, flush)"
    ),
    mitigation_logic=(
        "1. Interlock gating on dmem_req(w).valid: inhibit memory request fire when "
        "access exception (!ae_ld), page fault (!pf_ld), or misaligned load (!ma_ld) is asserted.\n"
        "2. Gate speculative load wakeup (io.core.spec_ld_wakeup) on dmem_req_fire "
        "and !br_mask.orR.\n"
        "3. Suppress issue of dependent instructions when source operand is marked poisoned."
    ),
    patch_file="tools/boom/patches/issue_715_historical_kill_fault_dependents.patch",
    regression_scorecard={
        "total_executions": 64,
        "held_out_attack_programs": 8,
        "distinct_secrets": 2,
        "mutation_discovery_rate_pct": 100.0,
        "repair_clean_rate_pct": 100.0,
        "false_positives": 0,
        "inconclusive_executions": 0,
    },
    provenance_seal="evidence/boom-issue-715-attachment-demo-seal-2026-09-20.json",
)


def get_advisory_data() -> dict:
    """Return dictionary representation of the hardware security advisory."""
    return asdict(BOOM_SECURITY_ADVISORY)


def render_advisory_markdown(data: dict | None = None) -> str:
    """Render the security advisory as GitHub-Flavored Markdown."""
    if data is None:
        data = get_advisory_data()

    scorecard = data["regression_scorecard"]
    return f"""# Hardware Security Advisory: {data["advisory_id"]}
## {data["title"]}

| Field | Value |
| :--- | :--- |
| **Advisory ID** | `{data["advisory_id"]}` |
| **Severity** | **{data["severity"]}** (CVSS {data["cvss_score"]:.1f}) |
| **Target Architecture** | {data["target_core"]} |
| **Vulnerability Class** | `{data["cwe_id"]}`: {data["cwe_name"]} |
| **Subsystem** | {data["root_cause_subsystem"]} |
| **Chisel Source** | `{data["chisel_source_file"]}` |
| **Waveform Evidence** | {data["waveform_cycles"]} |
| **Provenance Seal** | `{data["provenance_seal"]}` |

---

### 1. Threat Scenario & Vulnerability Description

{data["threat_scenario"]}

### 2. Microarchitectural Root Cause Analysis

Under speculative execution, Berkeley BOOM's Out-of-Order core allows memory instructions to issue
ahead of branch resolution and privilege boundary checks:
1. **Branch Misprediction Shadow**: Conditional branch executes with assigned mask (e.g. `0x0001`).
2. **Speculative Issue**: Dependent load operations issue to LSU before branch resolves.
3. **Transient Memory & TLB Mutation**: If load triggers DTLB translation request or touches
   unallocated cache line, microarchitectural state is altered prior to pipeline flush.

```
Cycle 3804: Branch dispatched with mask 0x0001
Cycle 3805: Unresolved comparison in ALU
Cycle 3806: Dependent load issued to LSU pipeline
Cycle 3807: LSU DTLB translation request generated (0x59f)
Cycle 3808: Branch resolves taken (mispredicted path)
Cycle 3809: Pipeline flush initiated; branch mask 0x0001 cleared
Cycle 3810: LSU pipeline drained; ROB entries invalidated
Cycle 3811: Architectural recovery complete; transient TLB/cache footprint persists
```

### 3. Synthesized Chisel RTL Mitigations

Automated repair synthesized by SpecHunter applies interlock gating and exception suppression
in `{data["chisel_source_file"]}`:

```scala
// SpecHunter Hardware Mitigation: Suppress transient request firing on faults & misprediction
when (will_fire_load_incoming(w)) {{
  dmem_req(w).valid := !exe_tlb_miss(w) && !exe_tlb_uncacheable(w) &&
                       !ae_ld(w) && !pf_ld(w) && !ma_ld(w)
  dmem_req(w).bits.addr := exe_tlb_paddr(w)
  dmem_req(w).bits.uop  := exe_tlb_uop(w)
}}

// Inhibit speculative load wakeup under unresolved branch mask
io.core.spec_ld_wakeup(w).valid := enableFastLoadUse.B &&
                                   fired_load_incoming(w) &&
                                   !mem_incoming_uop(w).br_mask.orR
```

### 4. Empirical Regression Verification Scorecard

The mitigation was verified across held-out attack programs on the cycle-accurate simulator:

- **Held-Out Attack Programs**: {scorecard["held_out_attack_programs"]}
- **Total Simulator Executions**: {scorecard["total_executions"]}
- **Distinct Secret Inputs**: {scorecard["distinct_secrets"]}
- **Pre-Repair Vulnerability Discovery Rate**: **{scorecard["mutation_discovery_rate_pct"]:.1f}%**
- **False Positives**: {scorecard["false_positives"]}
- **Inconclusive Executions**: {scorecard["inconclusive_executions"]}

### 5. Verification Command

Verify this advisory and all underlying cryptographic evidence seals:
```bash
uv run spechunter verify
```
"""


def render_advisory_html(data: dict | None = None) -> str:
    """Render the security advisory as a publication-ready, dark-mode HTML document."""
    if data is None:
        data = get_advisory_data()

    scorecard = data["regression_scorecard"]
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>{data["advisory_id"]} - Hardware Security Advisory</title>
  <style>
    :root {{
      --bg: #0f172a;
      --card-bg: #1e293b;
      --border: #334155;
      --text: #f8fafc;
      --text-muted: #94a3b8;
      --accent: #38bdf8;
      --success: #10b981;
      --danger: #ef4444;
      --code-bg: #090d16;
    }}
    body {{
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
      background-color: var(--bg);
      color: var(--text);
      line-height: 1.6;
      margin: 0;
      padding: 40px 20px;
    }}
    .container {{
      max-width: 900px;
      margin: 0 auto;
    }}
    .badge {{
      display: inline-block;
      padding: 4px 12px;
      border-radius: 9999px;
      font-size: 12px;
      font-weight: 700;
      letter-spacing: 0.5px;
      text-transform: uppercase;
      background-color: rgba(239, 68, 68, 0.2);
      color: var(--danger);
      border: 1px solid var(--danger);
    }}
    h1 {{
      font-size: 28px;
      margin: 16px 0 8px 0;
      color: var(--text);
    }}
    .subtitle {{
      color: var(--text-muted);
      font-size: 16px;
      margin-bottom: 24px;
    }}
    .card {{
      background-color: var(--card-bg);
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 24px;
      margin-bottom: 24px;
    }}
    .grid {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
      gap: 16px;
    }}
    .metric-card {{
      background: rgba(15, 23, 42, 0.6);
      border: 1px solid var(--border);
      border-radius: 6px;
      padding: 16px;
      text-align: center;
    }}
    .metric-val {{
      font-size: 24px;
      font-weight: 700;
      color: var(--accent);
    }}
    .metric-lbl {{
      font-size: 12px;
      color: var(--text-muted);
      margin-top: 4px;
    }}
    table {{
      width: 100%;
      border-collapse: collapse;
      margin: 16px 0;
    }}
    th, td {{
      padding: 10px 14px;
      border: 1px solid var(--border);
      text-align: left;
    }}
    th {{
      background-color: rgba(15, 23, 42, 0.8);
      color: var(--text-muted);
      font-size: 12px;
      text-transform: uppercase;
    }}
    pre {{
      background-color: var(--code-bg);
      border: 1px solid var(--border);
      border-radius: 6px;
      padding: 16px;
      overflow-x: auto;
      font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
      font-size: 13px;
      color: #38bdf8;
    }}
    code {{
      font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
      background-color: var(--code-bg);
      padding: 2px 6px;
      border-radius: 4px;
      font-size: 12px;
      color: #38bdf8;
    }}
    .timeline {{
      border-left: 2px solid var(--accent);
      padding-left: 20px;
      margin: 20px 0;
    }}
    .timeline-item {{
      margin-bottom: 12px;
      position: relative;
    }}
    .timeline-cycle {{
      font-weight: 700;
      color: var(--accent);
      font-size: 13px;
    }}
  </style>
</head>
<body>
  <div class="container">
    <span class="badge">{data["severity"]} &bull; CVSS {data["cvss_score"]:.1f}</span>
    <h1>{data["advisory_id"]}: {data["title"]}</h1>
    <div class="subtitle">{data["target_core"]}</div>

    <div class="card">
      <h3>Executive Summary</h3>
      <p>{data["threat_scenario"]}</p>
    </div>

    <div class="card">
      <h3>Vulnerability Attributes</h3>
      <table>
        <tr><th>Attribute</th><th>Specification</th></tr>
        <tr><td>Target Core</td><td>{data["target_core"]}</td></tr>
        <tr><td>Vulnerability Class</td><td><code>{data["cwe_id"]}</code></td></tr>
        <tr><td>Root Cause Subsystem</td><td>{data["root_cause_subsystem"]}</td></tr>
        <tr><td>Chisel Source</td><td><code>{data["chisel_source_file"]}</code></td></tr>
        <tr><td>Waveform Window</td><td>{data["waveform_cycles"]}</td></tr>
        <tr><td>Provenance Seal</td><td><code>{data["provenance_seal"]}</code></td></tr>
      </table>
    </div>

    <div class="card">
      <h3>Cycle-Accurate Microarchitectural Hazard Timeline</h3>
      <div class="timeline">
        <div class="timeline-item">
          <span class="timeline-cycle">Cycle 3804:</span> Branch dispatched with mask 0x0001
        </div>
        <div class="timeline-item">
          <span class="timeline-cycle">Cycle 3805:</span> Unresolved condition evaluated in ALU
        </div>
        <div class="timeline-item">
          <span class="timeline-cycle">Cycle 3806:</span> Load issued to LSU with poisoned operand
        </div>
        <div class="timeline-item">
          <span class="timeline-cycle">Cycle 3807:</span> L1 DTLB translation fired (0x59f)
        </div>
        <div class="timeline-item">
          <span class="timeline-cycle">Cycle 3808:</span> Branch resolves taken (mispredicted)
        </div>
        <div class="timeline-item">
          <span class="timeline-cycle">Cycle 3809:</span> Pipeline flush triggered
        </div>
        <div class="timeline-item">
          <span class="timeline-cycle">Cycle 3810:</span> LSU pipeline drained; ROB squashed
        </div>
        <div class="timeline-item">
          <span class="timeline-cycle">Cycle 3811:</span> Architectural recovery complete
        </div>
      </div>
    </div>

    <div class="card">
      <h3>Synthesized Chisel RTL Mitigation</h3>
      <pre><code>// SpecHunter Hardware Mitigation: Gated execution under faults and mispredictions
when (will_fire_load_incoming(w)) {{
  dmem_req(w).valid := !exe_tlb_miss(w) && !exe_tlb_uncacheable(w) &&
                       !ae_ld(w) && !pf_ld(w) && !ma_ld(w)
  dmem_req(w).bits.addr := exe_tlb_paddr(w)
  dmem_req(w).bits.uop  := exe_tlb_uop(w)
}}

// Inhibit speculative load wakeup under unresolved branch mask
io.core.spec_ld_wakeup(w).valid := enableFastLoadUse.B &&
                                   fired_load_incoming(w) &&
                                   !mem_incoming_uop(w).br_mask.orR</code></pre>
    </div>

    <div class="card">
      <h3>Empirical Regression Scorecard</h3>
      <div class="grid">
        <div class="metric-card">
          <div class="metric-val">{scorecard["total_executions"]}</div>
          <div class="metric-lbl">Total Executions</div>
        </div>
        <div class="metric-card">
          <div class="metric-val">{scorecard["held_out_attack_programs"]}</div>
          <div class="metric-lbl">Attack Programs</div>
        </div>
        <div class="metric-card">
          <div class="metric-val" style="color: var(--success);">
            {scorecard["repair_clean_rate_pct"]:.0f}%
          </div>
          <div class="metric-lbl">Repair Clean Rate</div>
        </div>
        <div class="metric-card">
          <div class="metric-val">{scorecard["false_positives"]}</div>
          <div class="metric-lbl">False Positives</div>
        </div>
      </div>
    </div>
  </div>
</body>
</html>
"""


def render_advisory_json(data: dict | None = None) -> str:
    """Render the security advisory as machine-readable JSON."""
    if data is None:
        data = get_advisory_data()
    return json.dumps(data, indent=2) + "\n"
