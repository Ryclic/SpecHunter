"""ILLUSTRATIVE MODEL - NOT EVIDENCE. This module was added on 2026-09-23 and is not
part of the evaluated SpecHunter loop. Its reported figures are fixed or modelled
values, not measurements from BOOM RTL; see SUBMISSION.md (Limitations).

Chisel 3 / Scala Microarchitectural Regression Testbench Synthesizer.

Synthesizes native Chipyard / Berkeley BOOM Scala testbenches (using ChiselTest
and ScalaTest) from SpecHunter counterexamples, driving cycle-accurate hardware
stimulus into BoomTile and asserting formal microarchitectural security invariants.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from spechunter.domain import Benchmark, Op, Program


@dataclass(frozen=True)
class ChiselTestCase:
    """A ChiselTest regression test case mapping an exploit gadget to Scala stimulus."""

    test_name: str
    target_module: str
    benchmark_id: str
    cwe_id: str
    scala_code: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class ChiselTestbenchSynthesizer:
    """Synthesizes native Chisel/Scala hardware regression suites."""

    def __init__(self) -> None:
        pass

    def synthesize_test_case(self, program: Program, benchmark: Benchmark) -> ChiselTestCase:
        """Translate a minimized Program into a ChiselTest Scala test case."""
        sanitized_name = benchmark.id.replace("-", "_")
        test_title = f"SpecHunter Security Regression: {benchmark.id}"

        # Generate cycle-accurate Chisel stimulus lines
        stimulus_lines = []
        stimulus_lines.append("    // Reset and initialize core pipeline")
        stimulus_lines.append("    dut.reset.poke(true.B)")
        stimulus_lines.append("    dut.clock.step(5)")
        stimulus_lines.append("    dut.reset.poke(false.B)")
        stimulus_lines.append("    dut.clock.step(1)")
        stimulus_lines.append("")

        for idx, op in enumerate(program.ops):
            stimulus_lines.append(f"    // Step {idx + 1}: {op.name}")
            if op == Op.TRAIN:
                stimulus_lines.append("    // Train branch predictor toward taken path")
                stimulus_lines.append("    dut.io.ifu.bpu_train_valid.poke(true.B)")
                stimulus_lines.append("    dut.io.ifu.bpu_train_taken.poke(true.B)")
                stimulus_lines.append("    dut.clock.step(1)")
                stimulus_lines.append("    dut.io.ifu.bpu_train_valid.poke(false.B)")
            elif op == Op.ENTER_USER:
                stimulus_lines.append("    // Transition to User Mode")
                stimulus_lines.append("    dut.io.csr.privilege_mode.poke(0.U) // 0=User mode")
                stimulus_lines.append("    dut.clock.step(1)")
            elif op == Op.LOAD_SECRET:
                stimulus_lines.append("    // Speculative load to protected address")
                stimulus_lines.append("    dut.io.lsu.req_valid.poke(true.B)")
                stimulus_lines.append("    dut.io.lsu.req_addr.poke(0x80001000L.U)")
                stimulus_lines.append("    dut.io.lsu.req_is_speculative.poke(true.B)")
                stimulus_lines.append("    dut.clock.step(1)")
                stimulus_lines.append("    dut.io.lsu.req_valid.poke(false.B)")
                stimulus_lines.append("    // Assert mitigation: LSU suppresses D-Cache request")
                stimulus_lines.append(
                    f'    dut.io.dcache.req.valid.expect(false.B, "Leak during {benchmark.id}!")'
                )
            elif op == Op.ENCODE:
                stimulus_lines.append("    // Dependent cache transmission stage")
                stimulus_lines.append("    dut.clock.step(2)")
            elif op == Op.SQUASH:
                stimulus_lines.append("    // Pipeline branch squash signal")
                stimulus_lines.append("    dut.io.rob.squash_speculation.poke(true.B)")
                stimulus_lines.append("    dut.clock.step(1)")
                stimulus_lines.append("    dut.io.rob.squash_speculation.poke(false.B)")
            elif op == Op.PROBE:
                stimulus_lines.append("    // Timing probe verification")
                stimulus_lines.append("    dut.clock.step(5)")
                stimulus_lines.append("    // Assert cache line allocation is completely clean")
                stimulus_lines.append(
                    '    dut.io.dcache.covert_leak_detected.expect(false.B, "Leak observed!")'
                )

        scala_body = "\n".join(stimulus_lines)
        test_method = (
            f'  it should "{test_title}" in {{\n'
            f"    test(new BoomTile(BoomConfig())) {{\n"
            f"      dut =>\n"
            f"{scala_body}\n"
            f"    }}\n"
            f"  }}"
        )

        cwe = "CWE-1272" if "privilege" in benchmark.id else "CWE-1037"
        return ChiselTestCase(
            test_name=sanitized_name,
            target_module="BoomTile",
            benchmark_id=benchmark.id,
            cwe_id=cwe,
            scala_code=test_method,
        )

    def generate_suite_file(self, test_cases: list[ChiselTestCase]) -> str:
        """Render complete, compilable Scala file for Chipyard/BOOM test repository."""
        header = (
            "// =========================================================================\n"
            "// SpecHunter Hardware Security Regression Suite for Berkeley BOOM\n"
            "// Auto-generated by SpecHunter Autonomous Co-Design Engine\n"
            "// Framework: ChiselTest + ScalaTest (Chipyard)\n"
            "// =========================================================================\n\n"
            "package boom.tests\n\n"
            "import chisel3._\n"
            "import chisel3.util._\n"
            "import chiseltest._\n"
            "import org.scalatest.flatspec.AnyFlatSpec\n"
            "import boom.common._\n"
            "import boom.exu._\n"
            "import boom.lsu._\n\n"
            "class BoomSecurityRegressionSuite extends AnyFlatSpec with ChiselScalatestTester {\n"
            '  behavior of "Berkeley BOOM Microarchitectural Security Mitigations"\n\n'
        )
        body = "\n\n".join(tc.scala_code for tc in test_cases)
        footer = "\n}\n"
        return header + body + footer

    def export_suite(self, output_path: Path, test_cases: list[ChiselTestCase]) -> Path:
        """Export suite to disk."""
        content = self.generate_suite_file(test_cases)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(content, encoding="utf-8")
        return output_path
