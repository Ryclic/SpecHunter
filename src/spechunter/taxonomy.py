"""ILLUSTRATIVE MODEL - NOT EVIDENCE. This module was added on 2026-09-23 and is not
part of the evaluated SpecHunter loop. Its reported figures are fixed or modelled
values, not measurements from BOOM RTL; see SUBMISSION.md (Limitations).

Formal microarchitectural taxonomy mapping speculative vulnerabilities to Berkeley BOOM RTL."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum


class SpectreVariant(StrEnum):
    SPECTRE_V1_BCB = "spectre-v1-bcb"
    SPECTRE_V2_BTI = "spectre-v2-bti"
    SPECTRE_V4_SSB = "spectre-v4-ssb"
    MELTDOWN_RDCL = "meltdown-rdcl"
    SEEDED_CACHE_LEAK = "seeded-cache-leak"
    SECURE_BASELINE = "secure-baseline"


@dataclass(frozen=True)
class MicroarchitecturalTaxonomy:
    """Formal taxonomy mapping speculative vulnerability variants to BOOM RTL subsystems."""

    variant: SpectreVariant
    name: str
    boom_subsystem: str
    speculation_window: str
    transmission_channel: str
    interlock_gate: str
    chisel_source: str


SPECTRE_TAXONOMY: dict[str, MicroarchitecturalTaxonomy] = {
    "spectre-v1-bcb": MicroarchitecturalTaxonomy(
        variant=SpectreVariant.SPECTRE_V1_BCB,
        name="Spectre-v1 Bounds Check Bypass",
        boom_subsystem="Branch Prediction Unit (BPU / GShare Direction Predictor)",
        speculation_window="Branch misprediction shadow in ROB before branch resolution",
        transmission_channel="L1 Data Cache timing / line state probe",
        interlock_gate="exu/core.scala: iss_valid && !(ld_miss && poisoned)",
        chisel_source="generators/boom/src/main/scala/exu/core.scala",
    ),
    "transient-cache": MicroarchitecturalTaxonomy(
        variant=SpectreVariant.SPECTRE_V1_BCB,
        name="Spectre-v1 Bounds Check Bypass",
        boom_subsystem="Branch Prediction Unit (BPU / GShare Direction Predictor)",
        speculation_window="Branch misprediction shadow in ROB before branch resolution",
        transmission_channel="L1 Data Cache timing / line state probe",
        interlock_gate="exu/core.scala: iss_valid && !(ld_miss && poisoned)",
        chisel_source="generators/boom/src/main/scala/exu/core.scala",
    ),
    "spectre-v2-bti": MicroarchitecturalTaxonomy(
        variant=SpectreVariant.SPECTRE_V2_BTI,
        name="Spectre-v2 Branch Target Injection",
        boom_subsystem="Branch Target Buffer (BTB) & Return Address Stack (RAS)",
        speculation_window="Indirect jump misdirection before BTB train resolution",
        transmission_channel="L1 Data Cache line modulation",
        interlock_gate="ifu/bpu.scala: btb_updates gated by privilege level",
        chisel_source="generators/boom/src/main/scala/ifu/bpu.scala",
    ),
    "spectre-v4-ssb": MicroarchitecturalTaxonomy(
        variant=SpectreVariant.SPECTRE_V4_SSB,
        name="Spectre-v4 Speculative Store Bypass",
        boom_subsystem="Load-Store Unit (LSU / Store Queue Forwarding Logic)",
        speculation_window="Speculative load bypass before preceding store address calculation",
        transmission_channel="Transient stale memory operand forwarded into cache-line encode",
        interlock_gate="lsu/lsu.scala: st_dep_mask & ld_wait_store",
        chisel_source="generators/boom/src/main/scala/exu/lsu/lsu.scala",
    ),
    "meltdown-rdcl": MicroarchitecturalTaxonomy(
        variant=SpectreVariant.MELTDOWN_RDCL,
        name="Meltdown-Style Rogue Data Cache Load",
        boom_subsystem="Load-Store Unit (LSU / PMP Privilege Boundary)",
        speculation_window="Delayed exception delivery / asynchronous fault commit",
        transmission_channel="Architectural register forwarding or cache residue",
        interlock_gate="lsu/lsu.scala: PMP privilege exception squashes uop",
        chisel_source="generators/boom/src/main/scala/exu/lsu/lsu.scala",
    ),
    "privilege-bypass": MicroarchitecturalTaxonomy(
        variant=SpectreVariant.MELTDOWN_RDCL,
        name="Meltdown-Style Rogue Data Cache Load",
        boom_subsystem="Load-Store Unit (LSU / PMP Privilege Boundary)",
        speculation_window="Delayed exception delivery / asynchronous fault commit",
        transmission_channel="Architectural register forwarding or cache residue",
        interlock_gate="lsu/lsu.scala: PMP privilege exception squashes uop",
        chisel_source="generators/boom/src/main/scala/exu/lsu/lsu.scala",
    ),
    "seeded-cache-leak": MicroarchitecturalTaxonomy(
        variant=SpectreVariant.SEEDED_CACHE_LEAK,
        name="Controlled Transient Cache-State Mutation",
        boom_subsystem="Load-Store Unit & Memory System",
        speculation_window="Controlled privilege transition and secret load window",
        transmission_channel="L1 Data Cache tag probe (O(W0) != O(W1))",
        interlock_gate="Harness privilege fence / LSU load-data gate",
        chisel_source="generators/boom/src/main/scala/exu/lsu/lsu.scala",
    ),
    "boom-positive-control": MicroarchitecturalTaxonomy(
        variant=SpectreVariant.SEEDED_CACHE_LEAK,
        name="Controlled Transient Cache-State Mutation",
        boom_subsystem="Load-Store Unit & Memory System",
        speculation_window="Controlled privilege transition and secret load window",
        transmission_channel="L1 Data Cache tag probe (O(W0) != O(W1))",
        interlock_gate="Harness privilege fence / LSU load-data gate",
        chisel_source="generators/boom/src/main/scala/exu/lsu/lsu.scala",
    ),
    "secure-baseline": MicroarchitecturalTaxonomy(
        variant=SpectreVariant.SECURE_BASELINE,
        name="Isolated Speculative Baseline",
        boom_subsystem="Full Out-of-Order Pipeline",
        speculation_window="N/A (Strict isolation enforced)",
        transmission_channel="None (O(W0) == O(W1))",
        interlock_gate="Complete architectural and microarchitectural fence",
        chisel_source="generators/boom/src/main/scala/exu/core.scala",
    ),
    "secure-control": MicroarchitecturalTaxonomy(
        variant=SpectreVariant.SECURE_BASELINE,
        name="Isolated Speculative Baseline",
        boom_subsystem="Full Out-of-Order Pipeline",
        speculation_window="N/A (Strict isolation enforced)",
        transmission_channel="None (O(W0) == O(W1))",
        interlock_gate="Complete architectural and microarchitectural fence",
        chisel_source="generators/boom/src/main/scala/exu/core.scala",
    ),
}
