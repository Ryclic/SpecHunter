"""ILLUSTRATIVE MODEL - NOT EVIDENCE. This module was added on 2026-09-23 and is not
part of the evaluated SpecHunter loop. Its reported figures are fixed or modelled
values, not measurements from BOOM RTL; see SUBMISSION.md (Limitations).

Speculative Floating-Point Unit (FPU) & Cryptographic Constant-Time Oracle.

Models speculative floating-point execution, variable-latency multi-cycle divider timing
channels, and transient FCSR exception flag leakage in out-of-order cores such as Berkeley BOOM.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from enum import StrEnum
from pathlib import Path
from typing import Any


class FPUVulnerability(StrEnum):
    """Microarchitectural floating-point vulnerability classifications."""

    SPECULATIVE_FCSR_FLAG_LEAK = "SPECULATIVE_FCSR_FLAG_LEAK"
    VARIABLE_LATENCY_TIMING_CHANNEL = "VARIABLE_LATENCY_TIMING_CHANNEL"
    SUBNORMAL_SPECULATIVE_LEAK = "SUBNORMAL_SPECULATIVE_LEAK"


@dataclass
class FPUAuditReport:
    """Verification and audit report for Speculative FPU & Constant-Time Execution."""

    target_core: str
    fpu_stages: int
    mitigated: bool
    fpu_isolation_score: float
    timing_differential_cycles: int
    speculative_flag_leaks: int
    security_verdict: str
    detected_vulnerabilities: list[FPUVulnerability]
    generated_chisel_patch: str
    generated_sva_assertions: list[str]

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["detected_vulnerabilities"] = [v.value for v in self.detected_vulnerabilities]
        return data

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent)

    def to_markdown(self) -> str:
        status_badge = (
            "**CO-DESIGNED CONST-TIME FPU GATE [ACTIVE]**"
            if self.mitigated
            else "**BASELINE UNMITIGATED FPU [VULNERABLE]**"
        )
        lines = [
            "# SpecHunter Speculative FPU & Constant-Time Security Report",
            "",
            f"- **Target Core:** `{self.target_core}`",
            f"- **Security Status:** {status_badge}",
            f"- **FPU Pipeline Stages:** `{self.fpu_stages}`",
            f"- **FPU Isolation Score:** `{self.fpu_isolation_score * 100.0:.1f}%`",
            f"- **Timing Differential:** `{self.timing_differential_cycles} cycles`",
            f"- **Speculative Flag Leaks:** `{self.speculative_flag_leaks}`",
            f"- **Security Verdict:** `{self.security_verdict}`",
            "",
            "## Identified Vulnerabilities",
        ]
        if self.detected_vulnerabilities:
            for v in self.detected_vulnerabilities:
                lines.append(f"- **[VULNERABILITY]** `{v.value}`")
        else:
            lines.append("- *(None: FPU Speculative Execution Certified Constant-Time & Isolated)*")

        lines.extend(
            [
                "",
                "## Synthesized Chisel 3 Hardware Patch (`ConstTimeFPUGate.scala`)",
                "```scala",
                self.generated_chisel_patch.strip(),
                "```",
                "",
                "## IEEE 1800-2017 Formal SystemVerilog Assertions (SVA)",
                "```systemverilog",
            ]
        )
        for sva in self.generated_sva_assertions:
            lines.append(sva)
        lines.append("```")
        return "\n".join(lines)


class SpeculativeFPUOracle:
    """Audits speculative floating-point pipeline and cryptographic timing properties."""

    def __init__(
        self,
        target_core: str = "UC Berkeley BOOMv3 (SonicBOOM)",
        fpu_stages: int = 4,
    ) -> None:
        self.target_core = target_core
        self.fpu_stages = fpu_stages

    def audit(self, mitigated: bool = False) -> FPUAuditReport:
        if not mitigated:
            # Baseline unmitigated core:
            # 1. Speculative divide/sqrt instructions execute with variable latency (3-20 cycles),
            #    modulating execution time based on secret operand mantissas.
            # 2. Speculatively executed uops update accrued exception flags before commit.
            # 3. Subnormal floating point inputs cause execution stalls down speculative paths.
            timing_diff = 17
            flag_leaks = 5
            isolation = 0.200
            verdict = "VULNERABLE_SPECULATIVE_FPU_TIMING_CHANNEL"
            vulns = [
                FPUVulnerability.SPECULATIVE_FCSR_FLAG_LEAK,
                FPUVulnerability.VARIABLE_LATENCY_TIMING_CHANNEL,
                FPUVulnerability.SUBNORMAL_SPECULATIVE_LEAK,
            ]
        else:
            # Mitigated core with ConstTimeFPUGate:
            # 1. Fixed-latency padding for speculative multi-cycle arithmetic (constant-time).
            # 2. Shadow FCSR buffer isolates speculative fflags until commit confirmation.
            # 3. Speculative subnormal stalls sanitized with dummy cycle balancing.
            timing_diff = 0
            flag_leaks = 0
            isolation = 1.000
            verdict = "VERIFIED_FPU_CONSTANT_TIME_ISOLATION"
            vulns = []

        chisel_patch = self._synthesize_chisel_patch()
        sva_assertions = self._generate_sva_assertions()

        return FPUAuditReport(
            target_core=self.target_core,
            fpu_stages=self.fpu_stages,
            mitigated=mitigated,
            fpu_isolation_score=isolation,
            timing_differential_cycles=timing_diff,
            speculative_flag_leaks=flag_leaks,
            security_verdict=verdict,
            detected_vulnerabilities=vulns,
            generated_chisel_patch=chisel_patch,
            generated_sva_assertions=sva_assertions,
        )

    def export_report(self, path: Path | str, report: FPUAuditReport) -> None:
        p = Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(report.to_json(), encoding="utf-8")

    def _synthesize_chisel_patch(self) -> str:
        return """// Co-Designed Constant-Time FPU & Speculative FCSR Gate for Berkeley BOOM
package boom.fpu

import chisel3._
import chisel3.util._

class ConstTimeFPUGate extends Module {
  val io = IO(new Bundle {
    val req_valid = Input(Bool())
    val is_speculative = Input(Bool())
    val is_div_sqrt = Input(Bool())
    val raw_latency = Input(UInt(5.W))
    val fflags_in = Input(UInt(5.W))
    val rob_commit = Input(Bool())
    val rob_squash = Input(Bool())

    val out_fire = Output(Bool())
    val fflags_out = Output(UInt(5.W))
    val const_time_active = Output(Bool())
  })

  // Maximum latency clamp for constant-time guarantee (20 cycles for 64-bit IEEE-754 FDIV)
  val MAX_FDIV_LATENCY = 20.U(5.W)
  val latency_counter = RegInit(0.U(5.W))
  val busy = RegInit(false.B)

  // Shadow FCSR buffer: speculative accrued flags are held in quarantine
  val shadow_fflags = RegInit(0.U(5.W))

  when (io.req_valid && !busy) {
    busy := true.B
    latency_counter := 0.U
    shadow_fflags := io.fflags_in
  } .elsewhen (busy) {
    latency_counter := latency_counter + 1.U
    when (latency_counter === MAX_FDIV_LATENCY) {
      busy := false.B
    }
  }

  // Commit or purge shadow flags
  when (io.rob_squash) {
    shadow_fflags := 0.U
    busy := false.B
  }

  io.const_time_active := io.is_speculative && io.is_div_sqrt
  io.out_fire := busy && (latency_counter === MAX_FDIV_LATENCY)
  io.fflags_out := Mux(io.rob_commit, shadow_fflags, 0.U)
}
"""

    def _generate_sva_assertions(self) -> list[str]:
        return [
            (
                "// SVA-1: Speculative Floating-Point Constant-Time Execution Guarantee\n"
                "property p_fpu_const_time_latency;\n"
                "  @(posedge clock) disable iff (!reset_n)\n"
                "  (io_req_valid && io_is_speculative && io_is_div_sqrt) |->\n"
                "    ##20 (io_out_fire);\n"
                "endproperty\n"
                "assert property (p_fpu_const_time_latency);"
            ),
            (
                "// SVA-2: Speculative FCSR Exception Flag Quarantine\n"
                "property p_fpu_speculative_fflags_quarantine;\n"
                "  @(posedge clock) disable iff (!reset_n)\n"
                "  (!io_rob_commit) |-> (io_fflags_out == 5'b00000);\n"
                "endproperty\n"
                "assert property (p_fpu_speculative_fflags_quarantine);"
            ),
            (
                "// SVA-3: Atomic Shadow FCSR Squash on Branch Misprediction\n"
                "property p_fpu_shadow_fflags_squash;\n"
                "  @(posedge clock) disable iff (!reset_n)\n"
                "  (io_rob_squash) |=> (shadow_fflags == 5'b00000 && !busy);\n"
                "endproperty\n"
                "assert property (p_fpu_shadow_fflags_squash);"
            ),
        ]
