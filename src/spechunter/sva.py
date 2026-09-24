"""ILLUSTRATIVE MODEL - NOT EVIDENCE. This module was added on 2026-09-23 and is not
part of the evaluated SpecHunter loop. Its reported figures are fixed or modelled
values, not measurements from BOOM RTL; see SUBMISSION.md (Limitations).

SystemVerilog Assertion (SVA) formal property synthesis for Berkeley BOOM.

Generates formal assertions, cover properties, and bind files for proving
microarchitectural isolation boundaries in hardware simulation (iverilog, Verilator)
and formal property verification (JasperGold, SymbiYosys).
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class SVAProperty:
    """A formal SystemVerilog Assertion (SVA) specification."""

    property_id: str
    target_module: str
    subsystem: str
    cwe_id: str
    description: str
    clock_signal: str
    reset_signal: str
    property_definition: str
    assertion_statement: str
    cover_statement: str
    bind_statement: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def to_systemverilog(self) -> str:
        """Render complete SystemVerilog checker module with assertion and coverage."""
        return (
            f"// SpecHunter Formal SVA Checker: {self.property_id}\n"
            f"// Target Subsystem: {self.subsystem} ({self.target_module})\n"
            f"// Vulnerability Classification: {self.cwe_id}\n"
            f"// Description: {self.description}\n"
            f"module {self.property_id}_checker (\n"
            f"  input logic {self.clock_signal},\n"
            f"  input logic {self.reset_signal}\n"
            f");\n\n"
            f"{self.property_definition}\n\n"
            f"  // Formal Safety Assertion\n"
            f"  {self.assertion_statement}\n\n"
            f"  // Functional Reachability Coverage\n"
            f"  {self.cover_statement}\n"
            f"endmodule\n\n"
            f"// Module Bind Declaration\n"
            f"{self.bind_statement}\n"
        )


SVA_CATALOG: dict[str, SVAProperty] = {
    "pmp-speculative-isolation": SVAProperty(
        property_id="pmp_speculative_isolation",
        target_module="LSU",
        subsystem="Load-Store Unit Dispatch",
        cwe_id="CWE-1272",
        description=(
            "Enforce that speculative loads never dispatch to D-Cache when a privilege "
            "or PMP violation is pending on that uop."
        ),
        clock_signal="clock",
        reset_signal="reset",
        property_definition=(
            "  property p_pmp_speculative_isolation;\n"
            "    @(posedge clock) disable iff (reset)\n"
            "    (io_core_pmp_fault_pending || io_core_priv_violation) |-> !io_dcache_req_valid;\n"
            "  endproperty"
        ),
        assertion_statement=(
            "assert_pmp_speculative_isolation: assert property (p_pmp_speculative_isolation)\n"
            '    else $error("SpecHunter Violation: Speculative load during pending fault!");'
        ),
        cover_statement=(
            "cover_pmp_fault_handled: cover property (\n"
            "    @(posedge clock) disable iff (reset)\n"
            "    io_core_pmp_fault_pending && !io_dcache_req_valid\n"
            "  );"
        ),
        bind_statement=(
            "bind LSU pmp_speculative_isolation_checker inst_pmp_checker (\n"
            "  .clock(clock),\n"
            "  .reset(reset)\n"
            ");"
        ),
    ),
    "issue-715-translation-order": SVAProperty(
        property_id="issue_715_translation_order",
        target_module="LSU",
        subsystem="LSU Address Translation & D-Cache Tag Check",
        cwe_id="CWE-1037",
        description=(
            "Enforce that D-Cache tag lookup and way allocation remain disabled "
            "until DTLB virtual-to-physical address translation has completed without fault."
        ),
        clock_signal="clock",
        reset_signal="reset",
        property_definition=(
            "  property p_issue_715_translation_order;\n"
            "    @(posedge clock) disable iff (reset)\n"
            "    (!dtlb_resp_valid || dtlb_resp_miss) |-> !dcache_tag_match_en;\n"
            "  endproperty"
        ),
        assertion_statement=(
            "assert_translation_before_tag: assert property (p_issue_715_translation_order)\n"
            '    else $error("SpecHunter Violation: Tag lookup before translation resolves!");'
        ),
        cover_statement=(
            "cover_tlb_miss_gated: cover property (\n"
            "    @(posedge clock) disable iff (reset)\n"
            "    dtlb_resp_miss && !dcache_tag_match_en\n"
            "  );"
        ),
        bind_statement=(
            "bind LSU issue_715_translation_order_checker inst_translation_checker (\n"
            "  .clock(clock),\n"
            "  .reset(reset)\n"
            ");"
        ),
    ),
    "bpu-privilege-isolation": SVAProperty(
        property_id="bpu_privilege_isolation",
        target_module="BoomBPU",
        subsystem="Branch Prediction Unit",
        cwe_id="CWE-1037",
        description=(
            "Enforce that BPU branch history tables and BTB entries are flushed "
            "on privilege mode transitions to prevent cross-domain Spectre-v2 training."
        ),
        clock_signal="clock",
        reset_signal="reset",
        property_definition=(
            "  property p_bpu_privilege_isolation;\n"
            "    @(posedge clock) disable iff (reset)\n"
            "    io_priv_transition |=> (bht_io_flush && btb_io_flush);\n"
            "  endproperty"
        ),
        assertion_statement=(
            "assert_bpu_flushed_on_priv_switch: assert property (p_bpu_privilege_isolation)\n"
            '    else $error("SpecHunter Violation: BPU tables not flushed on priv transition!");'
        ),
        cover_statement=(
            "cover_bpu_flush_executed: cover property (\n"
            "    @(posedge clock) disable iff (reset)\n"
            "    io_priv_transition ##1 (bht_io_flush && btb_io_flush)\n"
            "  );"
        ),
        bind_statement=(
            "bind BoomBPU bpu_privilege_isolation_checker inst_bpu_checker (\n"
            "  .clock(clock),\n"
            "  .reset(reset)\n"
            ");"
        ),
    ),
    "covert-cache-line-clean": SVAProperty(
        property_id="covert_cache_line_clean",
        target_module="DCache",
        subsystem="L1 Data Cache Allocation",
        cwe_id="CWE-385",
        description=(
            "Enforce that speculative squashed instructions leave no observable "
            "side-channel footprint in cache replacement state."
        ),
        clock_signal="clock",
        reset_signal="reset",
        property_definition=(
            "  property p_covert_cache_line_clean;\n"
            "    @(posedge clock) disable iff (reset)\n"
            "    (io_squash_valid && io_speculative_way_alloc) |-> ##1 !cache_line_allocated;\n"
            "  endproperty"
        ),
        assertion_statement=(
            "assert_squashed_cache_clean: assert property (p_covert_cache_line_clean)\n"
            '    else $error("SpecHunter Violation: Cache allocated by squashed instruction!");'
        ),
        cover_statement=(
            "cover_squash_prevented_allocation: cover property (\n"
            "    @(posedge clock) disable iff (reset)\n"
            "    io_squash_valid ##1 !cache_line_allocated\n"
            "  );"
        ),
        bind_statement=(
            "bind DCache covert_cache_line_clean_checker inst_dcache_checker (\n"
            "  .clock(clock),\n"
            "  .reset(reset)\n"
            ");"
        ),
    ),
}


class SVAGenerator:
    """Synthesizes formal SystemVerilog Assertion specifications."""

    def __init__(self) -> None:
        self.catalog = SVA_CATALOG

    def list_properties(self) -> list[str]:
        return sorted(self.catalog.keys())

    def get_property(self, property_id: str) -> SVAProperty:
        if property_id not in self.catalog:
            raise KeyError(
                f"Unknown SVA property '{property_id}'. Available: {self.list_properties()}"
            )
        return self.catalog[property_id]

    def generate_bind_file(self, properties: list[str] | None = None) -> str:
        """Generate comprehensive SystemVerilog file with all properties and binds."""
        props = (
            [self.get_property(p) for p in properties]
            if properties
            else list(self.catalog.values())
        )

        header = (
            "// =========================================================================\n"
            "// SpecHunter Formal Verification Suite for Berkeley BOOM\n"
            "// Auto-generated SystemVerilog Assertions (SVA) & Module Binds\n"
            "// Standard: IEEE 1800-2017 SystemVerilog\n"
            "// =========================================================================\n\n"
            "`ifndef SPECHUNTER_SVA_SV\n"
            "`define SPECHUNTER_SVA_SV\n\n"
        )
        body = "\n".join(p.to_systemverilog() for p in props)
        footer = "\n`endif // SPECHUNTER_SVA_SV\n"
        return header + body + footer

    def export_bind_file(self, output_path: Path, properties: list[str] | None = None) -> Path:
        """Export SVA bind file to disk."""
        content = self.generate_bind_file(properties)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(content, encoding="utf-8")
        return output_path

    def to_json(self) -> str:
        data = {k: v.to_dict() for k, v in self.catalog.items()}
        return json.dumps(data, indent=2)
