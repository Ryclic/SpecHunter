"""Generate vector SVG figures for the SpecHunter MICRO 2026 paper."""

# ruff: noqa: E501

from pathlib import Path

FIG_DIR = Path("paper/figures")
FIG_DIR.mkdir(parents=True, exist_ok=True)


def generate_arch_diagram():
    svg = """<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 800 360" width="100%" height="100%" style="background:#ffffff; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif;">
  <defs>
    <marker id="arrow" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
      <path d="M 0 1 L 10 5 L 0 9 z" fill="#1e293b"/>
    </marker>
    <marker id="arrow-blue" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
      <path d="M 0 1 L 10 5 L 0 9 z" fill="#2563eb"/>
    </marker>
    <marker id="arrow-green" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
      <path d="M 0 1 L 10 5 L 0 9 z" fill="#16a34a"/>
    </marker>
    <marker id="arrow-red" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
      <path d="M 0 1 L 10 5 L 0 9 z" fill="#dc2626"/>
    </marker>
    <filter id="shadow" x="-5%" y="-5%" width="110%" height="115%" filterUnits="userSpaceOnUse">
      <feDropShadow dx="1" dy="2" stdDeviation="2" flood-color="#0f172a" flood-opacity="0.08"/>
    </filter>
  </defs>

  <!-- Title / Outer Border -->
  <rect x="10" y="10" width="780" height="340" rx="8" fill="#f8fafc" stroke="#cbd5e1" stroke-width="1.5"/>
  <text x="25" y="32" font-size="12" font-weight="700" fill="#475569" letter-spacing="0.05em">SPECHUNTER CLOSED-LOOP CHIA ARCHITECTURE</text>

  <!-- CHIA Ray Runtime Container -->
  <rect x="25" y="45" width="750" height="175" rx="6" fill="#f1f5f9" stroke="#94a3b8" stroke-dasharray="4 4"/>
  <text x="35" y="62" font-size="11" font-weight="600" fill="#64748b">CHIA Orchestration Layer (Ray Runtime / DAG Execution)</text>

  <!-- Recon Node -->
  <g transform="translate(45, 80)" filter="url(#shadow)">
    <rect width="130" height="110" rx="6" fill="#eff6ff" stroke="#3b82f6" stroke-width="1.5"/>
    <rect width="130" height="24" rx="6" fill="#3b82f6"/>
    <text x="65" y="16" font-size="11" font-weight="700" fill="#ffffff" text-anchor="middle">1. Recon Agent</text>
    <text x="65" y="45" font-size="10" fill="#1e3a8a" text-anchor="middle">Hypothesis Gen</text>
    <text x="65" y="62" font-size="9" fill="#475569" text-anchor="middle">• Privilege boundary</text>
    <text x="65" y="76" font-size="9" fill="#475569" text-anchor="middle">• Speculative branch</text>
    <text x="65" y="90" font-size="9" fill="#475569" text-anchor="middle">• Cache side channel</text>
  </g>

  <!-- Attacker Node -->
  <g transform="translate(225, 80)" filter="url(#shadow)">
    <rect width="130" height="110" rx="6" fill="#fef2f2" stroke="#ef4444" stroke-width="1.5"/>
    <rect width="130" height="24" rx="6" fill="#ef4444"/>
    <text x="65" y="16" font-size="11" font-weight="700" fill="#ffffff" text-anchor="middle">2. Attacker Agent</text>
    <text x="65" y="45" font-size="10" fill="#991b1b" text-anchor="middle">Adversarial Prog Gen</text>
    <text x="65" y="62" font-size="9" fill="#475569" text-anchor="middle">• Instruction synthesis</text>
    <text x="65" y="76" font-size="9" fill="#475569" text-anchor="middle">• Register mapping</text>
    <text x="65" y="90" font-size="9" fill="#475569" text-anchor="middle">• PMP/HTIF harness</text>
  </g>

  <!-- Validator Node -->
  <g transform="translate(435, 80)" filter="url(#shadow)">
    <rect width="130" height="110" rx="6" fill="#f0fdf4" stroke="#22c55e" stroke-width="1.5"/>
    <rect width="130" height="24" rx="6" fill="#22c55e"/>
    <text x="65" y="16" font-size="11" font-weight="700" fill="#ffffff" text-anchor="middle">3. Validator Agent</text>
    <text x="65" y="45" font-size="10" fill="#166534" text-anchor="middle">Trace Analysis</text>
    <text x="65" y="62" font-size="9" fill="#475569" text-anchor="middle">• Secret-world diff</text>
    <text x="65" y="76" font-size="9" fill="#475569" text-anchor="middle">• Delta minimization</text>
    <text x="65" y="90" font-size="9" fill="#475569" text-anchor="middle">• ROB/LSU VCD check</text>
  </g>

  <!-- Repair Node -->
  <g transform="translate(625, 80)" filter="url(#shadow)">
    <rect width="130" height="110" rx="6" fill="#faf5ff" stroke="#a855f7" stroke-width="1.5"/>
    <rect width="130" height="24" rx="6" fill="#a855f7"/>
    <text x="65" y="16" font-size="11" font-weight="700" fill="#ffffff" text-anchor="middle">4. Repair Agent</text>
    <text x="65" y="45" font-size="10" fill="#581c87" text-anchor="middle">Diagnosis &amp; Patch</text>
    <text x="65" y="62" font-size="9" fill="#475569" text-anchor="middle">• Root-cause localize</text>
    <text x="65" y="76" font-size="9" fill="#475569" text-anchor="middle">• Chisel RTL patch</text>
    <text x="65" y="90" font-size="9" fill="#475569" text-anchor="middle">• Isolated re-build</text>
  </g>

  <!-- Connecting Arrows in Loop -->
  <line x1="175" y1="135" x2="223" y2="135" stroke="#1e293b" stroke-width="1.5" marker-end="url(#arrow)"/>
  <line x1="355" y1="135" x2="433" y2="135" stroke="#1e293b" stroke-width="1.5" marker-end="url(#arrow)"/>
  <line x1="565" y1="135" x2="623" y2="135" stroke="#1e293b" stroke-width="1.5" marker-end="url(#arrow)"/>

  <!-- Mandatory Retest Feedback Loop (Repair -> Attacker) -->
  <path d="M 690 80 Q 690 55 490 55 Q 290 55 290 78" fill="none" stroke="#dc2626" stroke-width="1.5" stroke-dasharray="3 3" marker-end="url(#arrow-red)"/>
  <rect x="420" y="48" width="140" height="15" rx="3" fill="#ffffff" stroke="#dc2626" stroke-width="0.8"/>
  <text x="490" y="59" font-size="8.5" font-weight="700" fill="#dc2626" text-anchor="middle">Mandatory Retest &amp; Exhaustion</text>

  <!-- Lower Container: Hardware Execution & Verification Layer -->
  <rect x="25" y="235" width="750" height="100" rx="6" fill="#ffffff" stroke="#cbd5e1" stroke-width="1.5"/>
  <text x="35" y="252" font-size="11" font-weight="700" fill="#334155">Execution &amp; Hardware Verification Authority (RISC-V BOOM &amp; Spike)</text>

  <!-- BOOM Sim Box -->
  <g transform="translate(230, 260)">
    <rect width="260" height="65" rx="5" fill="#f8fafc" stroke="#475569" stroke-width="1.2"/>
    <text x="130" y="20" font-size="11" font-weight="700" fill="#0f172a" text-anchor="middle">SmallBoomV3 (Verilator Target)</text>
    <text x="130" y="38" font-size="9" fill="#475569" text-anchor="middle">Cycle-accurate simulation • LSU/ROB trace</text>
    <text x="130" y="52" font-size="9" fill="#475569" text-anchor="middle">Signal inspection: ld_miss, iw_poisoned, tlb_req</text>
  </g>

  <!-- Spike Reference Box -->
  <g transform="translate(45, 260)">
    <rect width="165" height="65" rx="5" fill="#f8fafc" stroke="#64748b" stroke-width="1.2"/>
    <text x="82" y="20" font-size="11" font-weight="700" fill="#0f172a" text-anchor="middle">Spike Golden Model</text>
    <text x="82" y="38" font-size="9" fill="#475569" text-anchor="middle">Architectural reference</text>
    <text x="82" y="52" font-size="9" fill="#475569" text-anchor="middle">PMP / Privilege checks</text>
  </g>

  <!-- Cost Ledger Box -->
  <g transform="translate(510, 260)">
    <rect width="245" height="65" rx="5" fill="#f8fafc" stroke="#0284c7" stroke-width="1.2"/>
    <text x="122" y="20" font-size="11" font-weight="700" fill="#0369a1" text-anchor="middle">Locked Cost Ledger &amp; Seals</text>
    <text x="122" y="38" font-size="9" fill="#0369a1" text-anchor="middle">Pre-call reservation • Delayed billing reconcile</text>
    <text x="122" y="52" font-size="9" fill="#0369a1" text-anchor="middle">SHA-256 bound artifacts &amp; cryptographic seals</text>
  </g>

  <!-- Connection to hardware -->
  <line x1="290" y1="190" x2="290" y2="258" stroke="#ef4444" stroke-width="1.5" marker-end="url(#arrow-red)"/>
  <line x1="435" y1="260" x2="435" y2="192" stroke="#16a34a" stroke-width="1.5" marker-end="url(#arrow-green)"/>
</svg>"""
    (FIG_DIR / "fig1_architecture.svg").write_text(svg)
    print("Generated fig1_architecture.svg")


def generate_pipeline_diagram():
    svg = """<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 760 260" width="100%" height="100%" style="background:#ffffff; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif;">
  <defs>
    <marker id="arr" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
      <path d="M 0 1 L 10 5 L 0 9 z" fill="#334155"/>
    </marker>
    <marker id="arr-red" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
      <path d="M 0 1 L 10 5 L 0 9 z" fill="#dc2626"/>
    </marker>
  </defs>

  <rect x="5" y="5" width="750" height="250" rx="8" fill="#f8fafc" stroke="#cbd5e1" stroke-width="1.5"/>
  <text x="20" y="26" font-size="12" font-weight="700" fill="#334155">BOOM ISSUE &amp; LSU TRANSIENT DATAFLOW HAZARDS (ISSUE #715 REPRODUCTION)</text>

  <!-- Stage 1: Fetch & Decode -->
  <g transform="translate(25, 45)">
    <rect width="110" height="120" rx="5" fill="#f1f5f9" stroke="#94a3b8" stroke-width="1.2"/>
    <text x="55" y="22" font-size="10" font-weight="700" fill="#1e293b" text-anchor="middle">1. Fetch/Decode</text>
    <text x="55" y="45" font-size="8.5" fill="#475569" text-anchor="middle">Branch Prediction</text>
    <rect x="10" y="60" width="90" height="45" rx="3" fill="#fee2e2" stroke="#ef4444" stroke-width="0.8"/>
    <text x="55" y="77" font-size="8" font-weight="600" fill="#991b1b" text-anchor="middle">Speculative Path</text>
    <text x="55" y="92" font-size="7.5" fill="#7f1d1d" text-anchor="middle">Branch Mask 0x1</text>
  </g>

  <!-- Stage 2: Rename & Dispatch -->
  <g transform="translate(160, 45)">
    <rect width="125" height="120" rx="5" fill="#f1f5f9" stroke="#94a3b8" stroke-width="1.2"/>
    <text x="62" y="22" font-size="10" font-weight="700" fill="#1e293b" text-anchor="middle">2. Dispatch &amp; ROB</text>
    <text x="62" y="45" font-size="8.5" fill="#475569" text-anchor="middle">Phys Reg Allocation</text>
    <text x="10" y="68" font-size="8" fill="#334155">+0: ld p18 &lt;- (p12) [LQ0]</text>
    <text x="10" y="85" font-size="8" fill="#334155">+4: ld p21 &lt;- (p18) [LQ1]</text>
    <text x="10" y="102" font-size="8" fill="#334155">+8: ld p22 &lt;- (p14) [LQ2]</text>
  </g>

  <!-- Stage 3: Issue Queue & Register Read Gate -->
  <g transform="translate(310, 45)">
    <rect width="165" height="120" rx="5" fill="#fef3c7" stroke="#d97706" stroke-width="1.2"/>
    <text x="82" y="22" font-size="10" font-weight="700" fill="#92400e" text-anchor="middle">3. Mem Issue Unit &amp; Gate</text>
    <text x="82" y="42" font-size="8.5" fill="#78350f" text-anchor="middle">core.scala lines 973-978</text>
    <rect x="8" y="55" width="149" height="50" rx="4" fill="#ffffff" stroke="#b45309" stroke-width="0.8"/>
    <text x="82" y="70" font-size="7.5" font-weight="700" fill="#b45309" text-anchor="middle">iss_valid &amp;&amp; !(ld_miss &amp;&amp;</text>
    <text x="82" y="82" font-size="7.5" font-weight="700" fill="#b45309" text-anchor="middle">(iw_p1_poison || iw_p2_poison))</text>
    <text x="82" y="96" font-size="7" fill="#dc2626" text-anchor="middle">Result: Suppressed at RegRead!</text>
  </g>

  <!-- Stage 4: LSU Execute & TLB -->
  <g transform="translate(500, 45)">
    <rect width="130" height="120" rx="5" fill="#f1f5f9" stroke="#94a3b8" stroke-width="1.2"/>
    <text x="65" y="22" font-size="10" font-weight="700" fill="#1e293b" text-anchor="middle">4. LSU Execution</text>
    <text x="65" y="45" font-size="8.5" fill="#475569" text-anchor="middle">Execute Valid Signal</text>
    <text x="65" y="70" font-size="8" fill="#dc2626" text-anchor="middle">io_core_exe_0_req_valid</text>
    <text x="65" y="85" font-size="7.5" fill="#64748b" text-anchor="middle">= 0 (No req sent)</text>
    <text x="65" y="105" font-size="8" fill="#16a34a" text-anchor="middle">TLB Miss Blocked</text>
  </g>

  <!-- Stage 5: Cache State / Side Channel -->
  <g transform="translate(650, 45)">
    <rect width="90" height="120" rx="5" fill="#f0fdf4" stroke="#16a34a" stroke-width="1.2"/>
    <text x="45" y="22" font-size="10" font-weight="700" fill="#166534" text-anchor="middle">5. Cache</text>
    <text x="45" y="45" font-size="8.5" fill="#166534" text-anchor="middle">Side Channel</text>
    <text x="45" y="75" font-size="8" fill="#15803d" text-anchor="middle">Clean State</text>
    <text x="45" y="95" font-size="7.5" fill="#166534" text-anchor="middle">No secret leak</text>
  </g>

  <!-- Connectors -->
  <line x1="135" y1="105" x2="158" y2="105" stroke="#334155" stroke-width="1.2" marker-end="url(#arr)"/>
  <line x1="285" y1="105" x2="308" y2="105" stroke="#334155" stroke-width="1.2" marker-end="url(#arr)"/>
  <line x1="475" y1="105" x2="498" y2="105" stroke="#334155" stroke-width="1.2" marker-end="url(#arr)"/>
  <line x1="630" y1="105" x2="648" y2="105" stroke="#334155" stroke-width="1.2" marker-end="url(#arr)"/>

  <!-- Legend & Microarchitectural Insight Box -->
  <rect x="25" y="180" width="715" height="65" rx="5" fill="#ffffff" stroke="#e2e8f0" stroke-width="1"/>
  <text x="35" y="200" font-size="9" font-weight="700" fill="#0f172a">Key Microarchitectural Finding on Historical Issue #715:</text>
  <text x="35" y="216" font-size="8" fill="#334155">1. At cycle 3809, the dependent load (+4) issued with physical source p18 poisoned (iw_p1_poisoned=1). LSU ld_miss was active.</text>
  <text x="35" y="230" font-size="8" fill="#334155">2. BOOM's hardware interlock suppressed register read valid. The simultaneous 0x59f TLB request belonged to independent load +8 (LQ slot 2).</text>
  <text x="35" y="242" font-size="8" font-weight="600" fill="#2563eb">Conclusion: SpecHunter's cycle-accurate VCD attribution disproved the reported runtime leak on historical BOOM.</text>
</svg>"""
    (FIG_DIR / "fig2_boom_pipeline.svg").write_text(svg)
    print("Generated fig2_boom_pipeline.svg")


def generate_eval_chart():
    svg = """<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 600 280" width="100%" height="100%" style="background:#ffffff; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif;">
  <rect x="5" y="5" width="590" height="270" rx="8" fill="#f8fafc" stroke="#cbd5e1" stroke-width="1.5"/>
  <text x="20" y="26" font-size="12" font-weight="700" fill="#1e293b">SEARCH EFFICIENCY: SPECHUNTER GUIDED VS. UNGUIDED RANDOM (1,000 SEEDS)</text>

  <!-- Axes -->
  <line x1="60" y1="220" x2="560" y2="220" stroke="#94a3b8" stroke-width="1.5"/>
  <line x1="60" y1="50" x2="60" y2="220" stroke="#94a3b8" stroke-width="1.5"/>

  <!-- Y-Axis labels (Discovery Rate) -->
  <text x="50" y="224" font-size="9" fill="#64748b" text-anchor="end">0%</text>
  <text x="50" y="180" font-size="9" fill="#64748b" text-anchor="end">25%</text>
  <text x="50" y="135" font-size="9" fill="#64748b" text-anchor="end">50%</text>
  <text x="50" y="90" font-size="9" fill="#64748b" text-anchor="end">75%</text>
  <text x="50" y="55" font-size="9" fill="#64748b" text-anchor="end">100%</text>

  <!-- Grid lines -->
  <line x1="60" y1="177" x2="560" y2="177" stroke="#e2e8f0" stroke-width="1" stroke-dasharray="3 3"/>
  <line x1="60" y1="135" x2="560" y2="135" stroke="#e2e8f0" stroke-width="1" stroke-dasharray="3 3"/>
  <line x1="60" y1="92" x2="560" y2="92" stroke="#e2e8f0" stroke-width="1" stroke-dasharray="3 3"/>
  <line x1="60" y1="55" x2="560" y2="55" stroke="#e2e8f0" stroke-width="1" stroke-dasharray="3 3"/>

  <!-- X-Axis labels (Attempts) -->
  <text x="91" y="235" font-size="8.5" fill="#64748b" text-anchor="middle">1</text>
  <text x="153" y="235" font-size="8.5" fill="#64748b" text-anchor="middle">3</text>
  <text x="215" y="235" font-size="8.5" fill="#64748b" text-anchor="middle">5</text>
  <text x="277" y="235" font-size="8.5" fill="#64748b" text-anchor="middle">7</text>
  <text x="339" y="235" font-size="8.5" fill="#64748b" text-anchor="middle">9</text>
  <text x="401" y="235" font-size="8.5" fill="#64748b" text-anchor="middle">11</text>
  <text x="463" y="235" font-size="8.5" fill="#64748b" text-anchor="middle">13</text>
  <text x="525" y="235" font-size="8.5" fill="#64748b" text-anchor="middle">16</text>
  <text x="300" y="252" font-size="9.5" font-weight="600" fill="#475569" text-anchor="middle">Search Attempts / Budget</text>

  <!-- Guided Curve (Rapid convergence to 100% at attempt 2) -->
  <!-- At attempt 1: 50%, attempt 2: 100% -->
  <polyline points="60,220 91,135 122,55 525,55" fill="none" stroke="#2563eb" stroke-width="2.5"/>
  <circle cx="122" cy="55" r="4.5" fill="#2563eb"/>
  <text x="135" y="50" font-size="9" font-weight="700" fill="#2563eb">SpecHunter Guided: 100% (Mean 1.5 attempts)</text>

  <!-- Random Curve (Logarithmic climb to 57.25% at attempt 16) -->
  <polyline points="60,220 91,208 122,197 153,186 184,177 215,168 246,160 277,153 308,147 339,142 370,137 401,133 432,129 463,126 494,124 525,122" fill="none" stroke="#dc2626" stroke-width="2.2" stroke-dasharray="4 2"/>
  <circle cx="525" cy="122" r="4" fill="#dc2626"/>
  <text x="390" y="115" font-size="9" font-weight="700" fill="#dc2626">Random: 57.25% [55.1%-59.4%]</text>

  <!-- Legend Card -->
  <rect x="230" y="150" width="220" height="42" rx="4" fill="#ffffff" stroke="#cbd5e1" stroke-width="0.8"/>
  <line x1="240" y1="162" x2="265" y2="162" stroke="#2563eb" stroke-width="2.5"/>
  <text x="272" y="165" font-size="8.5" fill="#1e293b">SpecHunter Agentic Search</text>
  <line x1="240" y1="178" x2="265" y2="178" stroke="#dc2626" stroke-width="2" stroke-dasharray="4 2"/>
  <text x="272" y="181" font-size="8.5" fill="#1e293b">Unguided Random Fuzzing (N=1000)</text>
</svg>"""
    (FIG_DIR / "fig3_eval_chart.svg").write_text(svg)
    print("Generated fig3_eval_chart.svg")


if __name__ == "__main__":
    generate_arch_diagram()
    generate_pipeline_diagram()
    generate_eval_chart()
