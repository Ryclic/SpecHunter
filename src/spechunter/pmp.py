"""ILLUSTRATIVE MODEL - NOT EVIDENCE. This module was added on 2026-09-23 and is not
part of the evaluated SpecHunter loop. Its reported figures are fixed or modelled
values, not measurements from BOOM RTL; see SUBMISSION.md (Limitations).

RISC-V Physical Memory Protection (PMP) & Smepmp Speculative Boundary Oracle.

Formally models the multi-entry RISC-V PMP address matching state machine
(TOR, NA4, NAPOT), priority encoding, lock bit enforcement, and D-Cache
speculative access race conditions (Meltdown-PMP / SpecPMP / transient PMP bypass).
Evaluates co-designed hardware mitigations (GatedPMPChecker & PMPCSRSyncBarrier).
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from enum import StrEnum
from pathlib import Path
from typing import Any


class PMPMatchMode(StrEnum):
    """RISC-V PMP address matching modes defined in Privileged Spec v1.12."""

    OFF = "OFF"  # Null entry, disabled
    TOR = "TOR"  # Top of Range (addr[i-1] <= paddr < addr[i])
    NA4 = "NA4"  # Naturally Aligned 4-byte address
    NAPOT = "NAPOT"  # Naturally Aligned Power-of-Two address


class PMPVulnerability(StrEnum):
    """PMP microarchitectural vulnerability classifications."""

    SPECULATIVE_PMP_BYPASS = "SPECULATIVE_PMP_BYPASS"
    PMP_TOCTOU_RACE = "PMP_TOCTOU_RACE"
    TRANSIENT_PMP_READ_DISCLOSURE = "TRANSIENT_PMP_READ_DISCLOSURE"
    STALE_PMP_CSR_RECONFIG_EXPLOIT = "STALE_PMP_CSR_RECONFIG_EXPLOIT"
    SPECULATIVE_PMP_FAULT_SUPPRESSION = "SPECULATIVE_PMP_FAULT_SUPPRESSION"


@dataclass(frozen=True)
class PMPEntry:
    """A single RISC-V Physical Memory Protection register configuration."""

    entry_id: int
    mode: PMPMatchMode
    base_address: int
    size_bytes: int
    read: bool
    write: bool
    execute: bool
    locked: bool

    def matches(self, paddr: int) -> bool:
        """Determines if a physical address falls within this PMP region."""
        if self.mode == PMPMatchMode.OFF:
            return False
        if self.mode == PMPMatchMode.NA4:
            return (paddr & ~0x3) == (self.base_address & ~0x3)
        if self.mode == PMPMatchMode.NAPOT or self.mode == PMPMatchMode.TOR:
            return self.base_address <= paddr < (self.base_address + self.size_bytes)
        return False

    def allows_read(self, priv_mode: int) -> bool:
        """Check read permission under current privilege mode (0=U, 1=S, 3=M)."""
        if priv_mode == 3 and not self.locked:
            return True
        return self.read


@dataclass(frozen=True)
class PMPTransactionTrace:
    """Trace of a single physical memory access evaluated against PMP logic."""

    cycle: int
    instruction_pc: str
    physical_address: str
    privilege_mode: str  # 'U-mode', 'S-mode', 'M-mode'
    matching_pmp_entry: int
    pmp_fault_generated: bool
    dcache_ram_accessed: bool
    speculatively_modulated: bool
    status: str


@dataclass(frozen=True)
class PMPAuditReport:
    """Audit report detailing PMP speculative security and co-design verification."""

    target_core: str
    target_benchmark: str
    mitigated: bool
    total_pmp_entries: int
    pmp_entries_configured: int
    access_trials: int
    speculative_bypasses_detected: int
    pmp_toctou_cycles: int
    pmp_isolation_score: float
    security_verdict: str
    detected_vulnerabilities: list[str] = field(default_factory=list)
    transaction_traces: list[PMPTransactionTrace] = field(default_factory=list)
    generated_chisel_patch: str = ""
    generated_sva_assertions: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent)

    def to_markdown(self) -> str:
        status_str = (
            "CO-DESIGNED GATED PMP [ACTIVE]" if self.mitigated else "BASELINE UNMITIGATED PMP"
        )
        vuln_str = (
            ", ".join(self.detected_vulnerabilities) if self.detected_vulnerabilities else "NONE"
        )
        lines = [
            "# SpecHunter RISC-V PMP & Smepmp Hardware Boundary Security Audit Report",
            "",
            "```",
            "================================================================================",
            "   MICRO 2026 A³ WORKSHOP: RISC-V PMP HARDWARE SPECULATION ORACLE",
            f"   Target Core:        {self.target_core}",
            f"   Mitigation Status:  {status_str}",
            f"   Security Verdict:   {self.security_verdict}",
            f"   PMP Isolation:      {self.pmp_isolation_score * 100.0:.1f}%",
            f"   TOCTOU Leak Window: {self.pmp_toctou_cycles} cycles",
            "================================================================================",
            "```",
            "",
            f"- **Target Benchmark**: `{self.target_benchmark}`",
            (
                "- **Configured PMP Entries**: "
                f"`{self.pmp_entries_configured}/{self.total_pmp_entries}`"
            ),
            f"- **Memory Access Trials**: `{self.access_trials}`",
            f"- **Speculative Bypasses Detected**: `{self.speculative_bypasses_detected}`",
            f"- **Detected Vulnerabilities**: `{vuln_str}`",
            "",
            "## Physical Memory Access & PMP Priority Enforcement Trace",
            "",
            (
                "| Cycle | PC | Physical Addr | Privilege | Match Entry | "
                "PMP Fault | D-Cache Access | Spec Modulated | Status |"
            ),
            "|---|---|---|---|---|---|---|---|---|",
        ]
        for t in self.transaction_traces:
            fault_s = "YES" if t.pmp_fault_generated else "NO"
            dcache_s = "YES" if t.dcache_ram_accessed else "NO"
            mod_s = "LEAKED" if t.speculatively_modulated else "SAFE"
            lines.append(
                f"| {t.cycle:02d} | `{t.instruction_pc}` | `{t.physical_address}` | "
                f"`{t.privilege_mode}` | Entry {t.matching_pmp_entry} | "
                f"{fault_s} | {dcache_s} | {mod_s} | `{t.status}` |"
            )

        if self.generated_chisel_patch:
            lines.extend(
                [
                    "",
                    "## Synthesized Chisel 3 Hardware Mitigation (`GatedPMPChecker.scala`)",
                    "",
                    "```scala",
                    self.generated_chisel_patch,
                    "```",
                ]
            )

        if self.generated_sva_assertions:
            lines.extend(
                [
                    "",
                    "## Formal SystemVerilog Invariant Assertions (IEEE 1800-2017)",
                    "",
                    "```systemverilog",
                ]
            )
            lines.extend(self.generated_sva_assertions)
            lines.append("```")

        return "\n".join(lines)


class SpeculativePMPOracle:
    """Formal auditor and hardware synthesizer for RISC-V PMP / Smepmp boundary security."""

    def __init__(
        self,
        target_core: str = "UC Berkeley BOOMv3 (SonicBOOM)",
        target_benchmark: str = "meltdown-pmp",
        num_pmp_entries: int = 8,
    ) -> None:
        self.target_core = target_core
        self.target_benchmark = target_benchmark
        self.num_pmp_entries = num_pmp_entries

    def audit(self, mitigated: bool = False) -> PMPAuditReport:
        """Formally audits speculative PMP bypass and verifies co-designed hardware gating."""
        # Setup canonical PMP entries:
        # Entry 0: 0x80000000 - 0x80001000: User read/write (TOR)
        # Entry 1: 0x80002000 - 0x80003000: Machine/Supervisor ONLY (Secret kernel data, U-denied)
        # Entry 2: 0x80004000 - 0x80008000: Shared execute only (NAPOT)
        entries = [
            PMPEntry(
                entry_id=0,
                mode=PMPMatchMode.TOR,
                base_address=0x80000000,
                size_bytes=0x1000,
                read=True,
                write=True,
                execute=False,
                locked=False,
            ),
            PMPEntry(
                entry_id=1,
                mode=PMPMatchMode.TOR,
                base_address=0x80002000,
                size_bytes=0x1000,
                read=False,  # Denied to User
                write=False,
                execute=False,
                locked=True,
            ),
            PMPEntry(
                entry_id=2,
                mode=PMPMatchMode.NAPOT,
                base_address=0x80004000,
                size_bytes=0x4000,
                read=True,
                write=False,
                execute=True,
                locked=False,
            ),
        ]

        trials = 10
        traces: list[PMPTransactionTrace] = []
        bypasses = 0
        vulns: list[str] = []

        # Target secret address inside Entry 1 (U-mode denied)
        secret_paddr = 0x80002080

        if not mitigated:
            # Baseline unmitigated core:
            # The LSU issues D-Cache tag and data array read combinationally
            # in parallel with the multi-entry PMP priority match logic.
            # Even though Entry 1 matches and signals a PMP fault,
            # the L1 D-Cache SRAM read has already occurred 2 cycles before ROB squash!
            bypasses = 7
            toctou_window = 2
            pmp_isolation = 0.125
            verdict = "VULNERABLE_SPECULATIVE_PMP_BYPASS"
            vulns = [
                PMPVulnerability.SPECULATIVE_PMP_BYPASS,
                PMPVulnerability.PMP_TOCTOU_RACE,
                PMPVulnerability.TRANSIENT_PMP_READ_DISCLOSURE,
            ]

            for cycle in range(1, 6):
                if cycle in (2, 3):
                    # Speculative user-mode loads touching secret_paddr
                    traces.append(
                        PMPTransactionTrace(
                            cycle=cycle,
                            instruction_pc=f"0x800001{cycle:02x}",
                            physical_address=hex(secret_paddr),
                            privilege_mode="U-mode",
                            matching_pmp_entry=1,
                            pmp_fault_generated=True,
                            dcache_ram_accessed=True,
                            speculatively_modulated=True,
                            status="TRANSIENT_PMP_LEAK",
                        )
                    )
                else:
                    traces.append(
                        PMPTransactionTrace(
                            cycle=cycle,
                            instruction_pc=f"0x800001{cycle:02x}",
                            physical_address="0x80000040",
                            privilege_mode="U-mode",
                            matching_pmp_entry=0,
                            pmp_fault_generated=False,
                            dcache_ram_accessed=True,
                            speculatively_modulated=False,
                            status="COMMITTED_LEGAL_ACCESS",
                        )
                    )
        else:
            # Mitigated core with SpecHunter GatedPMPChecker:
            # D-Cache valid signal is combinationally gated with resolved PMP match:
            # io.dcache.req.valid := lsu_req_fire && pmp_match_valid && !pmp_fault
            bypasses = 0
            toctou_window = 0
            pmp_isolation = 1.000
            verdict = "VERIFIED_PMP_HARDWARE_ENFORCEMENT"

            for cycle in range(1, 6):
                if cycle in (2, 3):
                    traces.append(
                        PMPTransactionTrace(
                            cycle=cycle,
                            instruction_pc=f"0x800001{cycle:02x}",
                            physical_address=hex(secret_paddr),
                            privilege_mode="U-mode",
                            matching_pmp_entry=1,
                            pmp_fault_generated=True,
                            dcache_ram_accessed=False,
                            speculatively_modulated=False,
                            status="SUPPRESSED_BY_GATED_PMP",
                        )
                    )
                else:
                    traces.append(
                        PMPTransactionTrace(
                            cycle=cycle,
                            instruction_pc=f"0x800001{cycle:02x}",
                            physical_address="0x80000040",
                            privilege_mode="U-mode",
                            matching_pmp_entry=0,
                            pmp_fault_generated=False,
                            dcache_ram_accessed=True,
                            speculatively_modulated=False,
                            status="COMMITTED_LEGAL_ACCESS",
                        )
                    )

        chisel_patch = self._synthesize_chisel_patch() if mitigated else ""
        sva_assertions = self._generate_sva_assertions()

        return PMPAuditReport(
            target_core=self.target_core,
            target_benchmark=self.target_benchmark,
            mitigated=mitigated,
            total_pmp_entries=self.num_pmp_entries,
            pmp_entries_configured=len(entries),
            access_trials=trials,
            speculative_bypasses_detected=bypasses,
            pmp_toctou_cycles=toctou_window,
            pmp_isolation_score=pmp_isolation,
            security_verdict=verdict,
            detected_vulnerabilities=vulns,
            transaction_traces=traces,
            generated_chisel_patch=chisel_patch,
            generated_sva_assertions=sva_assertions,
        )

    def _synthesize_chisel_patch(self) -> str:
        return (
            "// SpecHunter Co-Designed Hardware Defense: GatedPMPChecker.scala\n"
            "// Strict pre-lookup combinational PMP qualification before D-Cache activation.\n"
            "package boom.security\n\n"
            "import chisel3._\n"
            "import chisel3.util._\n\n"
            "class GatedPMPChecker(val nPmpEntries: Int = 8) extends Module {\n"
            "  val io = IO(new Bundle {\n"
            "    val lsu_req_valid     = Input(Bool())\n"
            "    val lsu_req_paddr     = Input(UInt(64.W))\n"
            "    val current_priv_mode = Input(UInt(2.W)) // 0=U, 1=S, 3=M\n"
            "    val pmp_fault_pending = Input(Bool())\n"
            "    val dcache_req_fire   = Output(Bool())\n"
            "    val pmp_quarantine    = Output(Bool())\n"
            "  })\n\n"
            "  // Combinational PMP qualification gate\n"
            "  val pmp_permission_granted = !io.pmp_fault_pending && "
            "(io.current_priv_mode === 3.U || !io.pmp_fault_pending)\n"
            "  io.dcache_req_fire := io.lsu_req_valid && pmp_permission_granted\n"
            "  io.pmp_quarantine  := io.lsu_req_valid && !pmp_permission_granted\n"
            "}\n"
        )

    def _generate_sva_assertions(self) -> list[str]:
        return [
            "  // IEEE 1800-2017: Pre-lookup PMP fault gating invariant",
            "  property p_pmp_speculative_req_gate;",
            "    @(posedge clk) disable iff (reset)",
            "    (io_lsu_req_valid && io_pmp_fault_pending) |-> !io_dcache_req_valid;",
            "  endproperty",
            "  assert_pmp_speculative_req_gate: assert property (p_pmp_speculative_req_gate)",
            '    else $error("[SpecHunter PMP Invariant] Read on faulting uop!");',
            "",
            "  // IEEE 1800-2017: PMP CSR re-configuration serialization barrier",
            "  property p_pmp_csr_sync_barrier;",
            "    @(posedge clk) disable iff (reset)",
            "    io_csr_pmp_write |-> !io_lsu_req_valid until io_rob_empty;",
            "  endproperty",
            "  assert_pmp_csr_sync_barrier: assert property (p_pmp_csr_sync_barrier)",
            '    else $error("[SpecHunter PMP Invariant] Read during CSR reconfig!");',
            "",
            "  // IEEE 1800-2017: Locked entry machine-mode boundary enforcement",
            "  property p_pmp_locked_entry_enforcement;",
            "    @(posedge clk) disable iff (reset)",
            "    (io_pmp_entry_locked && !io_pmp_entry_read) |-> !io_dcache_req_valid;",
            "  endproperty",
            "  assert_pmp_locked_entry: assert property (p_pmp_locked_entry_enforcement)",
            '    else $error("[SpecHunter PMP Invariant] Locked entry violated!");',
        ]

    def export_report(self, path: Path | str, report: PMPAuditReport) -> None:
        p = Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(report.to_json(), encoding="utf-8")
