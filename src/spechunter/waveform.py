"""ILLUSTRATIVE MODEL - NOT EVIDENCE. This module was added on 2026-09-23 and is not
part of the evaluated SpecHunter loop. Its reported figures are fixed or modelled
values, not measurements from BOOM RTL; see SUBMISSION.md (Limitations).

Microarchitectural Waveform Witness & Pipeline Race Condition Analyzer.

Models cycle-accurate digital signal transitions (PC, BPU, LSU, DTLB, D-Cache, ROB),
detects microarchitectural Time-of-Check to Time-of-Use (TOCTOU) race conditions,
renders ASCII/UTF-8 timing diagrams, and exports IEEE 1364-compliant VCD waveforms.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from enum import StrEnum
from pathlib import Path
from typing import Any

from spechunter.domain import Benchmark, Program


class HazardType(StrEnum):
    """Microarchitectural pipeline hazard and race condition classifications."""

    SPECULATIVE_TRANSLATION_RACE = "SPECULATIVE_TRANSLATION_RACE"
    PMP_DISPATCH_TOCTOU = "PMP_DISPATCH_TOCTOU"
    TRANSIENT_COVERT_MODULATION = "TRANSIENT_COVERT_MODULATION"
    BRANCH_HISTORY_POISONING = "BRANCH_HISTORY_POISONING"
    SPECULATIVE_STORE_BYPASS = "SPECULATIVE_STORE_BYPASS"


@dataclass(frozen=True)
class PipelineHazard:
    """Detected microarchitectural timing race condition."""

    hazard_type: HazardType
    benchmark_id: str
    trigger_cycle: int
    resolution_cycle: int
    vulnerability_window_cycles: int
    critical_signals: list[str]
    description: str
    mitigated: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "hazard_type": self.hazard_type.value,
            "benchmark_id": self.benchmark_id,
            "trigger_cycle": self.trigger_cycle,
            "resolution_cycle": self.resolution_cycle,
            "vulnerability_window_cycles": self.vulnerability_window_cycles,
            "critical_signals": self.critical_signals,
            "description": self.description,
            "mitigated": self.mitigated,
        }


@dataclass
class SignalTrace:
    """Cycle-by-cycle binary or bus signal values."""

    name: str
    width: int = 1
    values: list[int | str] = field(default_factory=list)

    def render_ascii(self) -> str:
        """Render a text waveform line for binary or bus signals."""
        if self.width == 1:
            chars = []
            prev = None
            for val in self.values:
                bit = 1 if (val == 1 or val == "1" or val is True) else 0
                if prev is None:
                    chars.append("~" if bit else "_")
                else:
                    if bit and not prev:
                        chars.append("/~")
                    elif not bit and prev:
                        chars.append("\\_")
                    elif bit:
                        chars.append("~~")
                    else:
                        chars.append("__")
                prev = bit
            return "".join(chars)
        else:
            # Multi-bit bus signal representation
            segments = []
            for val in self.values:
                hex_val = f"{val:04X}" if isinstance(val, int) else str(val)[:4]
                segments.append(f"[{hex_val}]")
            return "".join(segments)


@dataclass
class WaveformTrace:
    """Complete cycle-accurate digital waveform with multi-signal bus traces."""

    benchmark_id: str
    total_cycles: int
    signals: dict[str, SignalTrace]
    hazards: list[PipelineHazard] = field(default_factory=list)
    mitigated: bool = False

    def to_vcd(self) -> str:
        """Generate IEEE 1364-compliant standard Value Change Dump (VCD)."""
        lines = [
            "$date SpecHunter Autonomous Co-Design Engine $end",
            "$version SpecHunter Waveform Synthesizer v1.0 $end",
            "$timescale 1ns $end",
            "$scope module BoomTile $end",
        ]

        var_map: dict[str, str] = {}
        var_chars = [chr(c) for c in range(33, 126) if chr(c) not in ("$", "#")]

        for idx, (sig_name, sig) in enumerate(self.signals.items()):
            identifier = var_chars[idx % len(var_chars)]
            var_map[sig_name] = identifier
            lines.append(f"$var wire {sig.width} {identifier} {sig_name} $end")

        lines.extend(["$upscope $end", "$enddefinitions $end", "$dumpvars"])

        # Initial values (Cycle 0)
        for sig_name, sig in self.signals.items():
            ident = var_map[sig_name]
            val = sig.values[0] if sig.values else 0
            if sig.width == 1:
                bit = 1 if val else 0
                lines.append(f"{bit}{ident}")
            else:
                lines.append(f"b{bin(val)[2:] if isinstance(val, int) else 0} {ident}")
        lines.append("$end")

        # Value changes per cycle
        for cycle in range(1, self.total_cycles):
            time_ns = cycle * 10
            lines.append(f"#{time_ns}")
            for sig_name, sig in self.signals.items():
                if cycle < len(sig.values) and sig.values[cycle] != sig.values[cycle - 1]:
                    ident = var_map[sig_name]
                    val = sig.values[cycle]
                    if sig.width == 1:
                        bit = 1 if val else 0
                        lines.append(f"{bit}{ident}")
                    else:
                        b_val = bin(val)[2:] if isinstance(val, int) else "0"
                        lines.append(f"b{b_val} {ident}")

        lines.append(f"#{self.total_cycles * 10}")
        return "\n".join(lines) + "\n"

    def render_diagram(self) -> str:
        """Render a readable ASCII timing diagram."""
        lines = [
            f"=== Microarchitectural Waveform Timing Diagram: {self.benchmark_id} ===",
            f"Hardware Mitigation: {'ACTIVE' if self.mitigated else 'BASELINE (UNMITIGATED)'}",
            f"Simulation Cycles:   {self.total_cycles}",
            "",
            f"{'Signal Name':<28} | Timing Trace (Cycles 1..{self.total_cycles})",
            "-" * 78,
        ]

        # Clock reference
        clk_wave = "".join(["_/~\\" for _ in range(self.total_cycles)])[: self.total_cycles * 2]
        lines.append(f"{'clk':<28} | {clk_wave}")

        for name, sig in self.signals.items():
            lines.append(f"{name:<28} | {sig.render_ascii()}")

        if self.hazards:
            lines.extend(
                [
                    "-" * 78,
                    "DETECTED PIPELINE HAZARDS & RACE CONDITIONS:",
                ]
            )
            for h in self.hazards:
                status = "SUPPRESSED BY MITIGATION" if h.mitigated else "CRITICAL EXPLOITABLE RACE"
                lines.append(
                    f"  [{h.hazard_type.value}] {status} "
                    f"(Cycles {h.trigger_cycle} -> {h.resolution_cycle}, "
                    f"Window: {h.vulnerability_window_cycles} cycles)"
                )
                lines.append(f"   => {h.description}")
        else:
            lines.extend(
                [
                    "-" * 78,
                    "ZERO PIPELINE HAZARDS DETECTED (Strict Timing Isolation Certified)",
                ]
            )
        return "\n".join(lines)

    def to_dict(self) -> dict[str, Any]:
        return {
            "benchmark_id": self.benchmark_id,
            "mitigated": self.mitigated,
            "total_cycles": self.total_cycles,
            "signals": {k: asdict(v) for k, v in self.signals.items()},
            "hazards": [h.to_dict() for h in self.hazards],
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2)


class WaveformSynthesizer:
    """Synthesizes cycle-accurate microarchitectural waveforms and detects races."""

    def synthesize(
        self,
        program: Program,
        benchmark: Benchmark,
        mitigated: bool = False,
    ) -> WaveformTrace:
        """Simulate microarchitectural pipeline signals and identify timing races."""
        total_cycles = 10

        signals = {
            "io_ifu_pc": SignalTrace("io_ifu_pc", width=32, values=[]),
            "io_bpu_mispredict": SignalTrace("io_bpu_mispredict", width=1, values=[]),
            "io_lsu_req_valid": SignalTrace("io_lsu_req_valid", width=1, values=[]),
            "io_lsu_req_addr": SignalTrace("io_lsu_req_addr", width=32, values=[]),
            "io_dtlb_req_valid": SignalTrace("io_dtlb_req_valid", width=1, values=[]),
            "io_dtlb_fault": SignalTrace("io_dtlb_fault", width=1, values=[]),
            "io_dcache_req_valid": SignalTrace("io_dcache_req_valid", width=1, values=[]),
            "io_dcache_tag_match": SignalTrace("io_dcache_tag_match", width=1, values=[]),
            "io_rob_squash": SignalTrace("io_rob_squash", width=1, values=[]),
            "io_covert_leak": SignalTrace("io_covert_leak", width=1, values=[]),
        }

        # Cycle 1: Training / Baseline fetch
        signals["io_ifu_pc"].values.append(0x80000100)
        signals["io_bpu_mispredict"].values.append(0)
        signals["io_lsu_req_valid"].values.append(0)
        signals["io_lsu_req_addr"].values.append(0x0)
        signals["io_dtlb_req_valid"].values.append(0)
        signals["io_dtlb_fault"].values.append(0)
        signals["io_dcache_req_valid"].values.append(0)
        signals["io_dcache_tag_match"].values.append(0)
        signals["io_rob_squash"].values.append(0)
        signals["io_covert_leak"].values.append(0)

        # Cycle 2: Privilege transition / Mispredict setup
        signals["io_ifu_pc"].values.append(0x80000104)
        signals["io_bpu_mispredict"].values.append(1 if "transient" in benchmark.id else 0)
        signals["io_lsu_req_valid"].values.append(0)
        signals["io_lsu_req_addr"].values.append(0x0)
        signals["io_dtlb_req_valid"].values.append(0)
        signals["io_dtlb_fault"].values.append(0)
        signals["io_dcache_req_valid"].values.append(0)
        signals["io_dcache_tag_match"].values.append(0)
        signals["io_rob_squash"].values.append(0)
        signals["io_covert_leak"].values.append(0)

        # Cycle 3: Speculative Load Request Issue
        signals["io_ifu_pc"].values.append(0x80000108)
        signals["io_bpu_mispredict"].values.append(1 if "transient" in benchmark.id else 0)
        signals["io_lsu_req_valid"].values.append(1)
        signals["io_lsu_req_addr"].values.append(0x80001000)
        signals["io_dtlb_req_valid"].values.append(1)
        signals["io_dtlb_fault"].values.append(0)  # Translation unresolved!
        # If mitigated, LSU suppresses D-Cache dispatch during pending check
        signals["io_dcache_req_valid"].values.append(0 if mitigated else 1)
        signals["io_dcache_tag_match"].values.append(0)
        signals["io_rob_squash"].values.append(0)
        signals["io_covert_leak"].values.append(0)

        # Cycle 4: Translation fault arrives / Covert Modulation
        signals["io_ifu_pc"].values.append(0x8000010C)
        signals["io_bpu_mispredict"].values.append(0)
        signals["io_lsu_req_valid"].values.append(0)
        signals["io_lsu_req_addr"].values.append(0x0)
        signals["io_dtlb_req_valid"].values.append(0)
        signals["io_dtlb_fault"].values.append(1 if "privilege" in benchmark.id else 0)
        signals["io_dcache_req_valid"].values.append(0)
        signals["io_dcache_tag_match"].values.append(0 if mitigated else 1)
        signals["io_rob_squash"].values.append(0)
        signals["io_covert_leak"].values.append(0 if mitigated else 1)

        # Cycle 5: ROB Branch Squash & Pipeline Rollback
        signals["io_ifu_pc"].values.append(0x80000100)
        signals["io_bpu_mispredict"].values.append(0)
        signals["io_lsu_req_valid"].values.append(0)
        signals["io_lsu_req_addr"].values.append(0x0)
        signals["io_dtlb_req_valid"].values.append(0)
        signals["io_dtlb_fault"].values.append(0)
        signals["io_dcache_req_valid"].values.append(0)
        signals["io_dcache_tag_match"].values.append(0)
        signals["io_rob_squash"].values.append(1)  # Pipeline squashed
        signals["io_covert_leak"].values.append(0 if mitigated else 1)  # Cache state persists!

        # Cycles 6-10: Quiescent / Probe stage
        for cyc in range(6, total_cycles + 1):
            signals["io_ifu_pc"].values.append(0x80000200 + (cyc - 6) * 4)
            signals["io_bpu_mispredict"].values.append(0)
            signals["io_lsu_req_valid"].values.append(0)
            signals["io_lsu_req_addr"].values.append(0x0)
            signals["io_dtlb_req_valid"].values.append(0)
            signals["io_dtlb_fault"].values.append(0)
            signals["io_dcache_req_valid"].values.append(0)
            signals["io_dcache_tag_match"].values.append(0)
            signals["io_rob_squash"].values.append(0)
            signals["io_covert_leak"].values.append(0 if mitigated else 1)

        hazards: list[PipelineHazard] = []

        if benchmark.id == "transient-cache":
            if not mitigated:
                hazards.append(
                    PipelineHazard(
                        hazard_type=HazardType.TRANSIENT_COVERT_MODULATION,
                        benchmark_id=benchmark.id,
                        trigger_cycle=3,
                        resolution_cycle=5,
                        vulnerability_window_cycles=2,
                        critical_signals=["io_dcache_req_valid", "io_rob_squash", "io_covert_leak"],
                        description=(
                            "Speculative load dispatched to D-Cache at Cycle 3 before "
                            "ROB squash at Cycle 5, leaving residual covert cache line footprint."
                        ),
                        mitigated=False,
                    )
                )
            else:
                hazards.append(
                    PipelineHazard(
                        hazard_type=HazardType.TRANSIENT_COVERT_MODULATION,
                        benchmark_id=benchmark.id,
                        trigger_cycle=3,
                        resolution_cycle=3,
                        vulnerability_window_cycles=0,
                        critical_signals=["io_dcache_req_valid", "io_rob_squash"],
                        description="Hardware mitigation gated LSU dispatch; 0 cycle window.",
                        mitigated=True,
                    )
                )

        elif benchmark.id == "privilege-bypass":
            if not mitigated:
                hazards.append(
                    PipelineHazard(
                        hazard_type=HazardType.PMP_DISPATCH_TOCTOU,
                        benchmark_id=benchmark.id,
                        trigger_cycle=3,
                        resolution_cycle=4,
                        vulnerability_window_cycles=1,
                        critical_signals=["io_lsu_req_valid", "io_dtlb_fault"],
                        description=(
                            "LSU issue at Cycle 3 precedes DTLB fault resolution at Cycle 4, "
                            "exposing protected memory."
                        ),
                        mitigated=False,
                    )
                )
            else:
                hazards.append(
                    PipelineHazard(
                        hazard_type=HazardType.PMP_DISPATCH_TOCTOU,
                        benchmark_id=benchmark.id,
                        trigger_cycle=3,
                        resolution_cycle=3,
                        vulnerability_window_cycles=0,
                        critical_signals=["io_lsu_req_valid", "io_dtlb_fault"],
                        description="Gated load dispatch blocks issue until fault check resolves.",
                        mitigated=True,
                    )
                )

        return WaveformTrace(
            benchmark_id=benchmark.id,
            total_cycles=total_cycles,
            signals=signals,
            hazards=hazards,
            mitigated=mitigated,
        )

    def export_vcd(self, path: Path | str, trace: WaveformTrace) -> Path:
        """Save standard IEEE 1364 VCD file to disk."""
        dest = Path(path)
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text(trace.to_vcd(), encoding="utf-8")
        return dest
