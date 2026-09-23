"""Unit tests for Chisel 3 / Scala microarchitectural testbench synthesizer."""

from pathlib import Path

from spechunter.chisel_testbench import ChiselTestbenchSynthesizer, ChiselTestCase
from spechunter.domain import BENCHMARKS, Op, Program


def test_chisel_testbench_synthesize_case():
    synth = ChiselTestbenchSynthesizer()
    prog = Program((Op.TRAIN, Op.ENTER_USER, Op.LOAD_SECRET, Op.ENCODE, Op.SQUASH, Op.PROBE))
    bench = next(b for b in BENCHMARKS if b.id == "transient-cache")
    tc = synth.synthesize_test_case(prog, bench)

    assert isinstance(tc, ChiselTestCase)
    assert tc.benchmark_id == "transient-cache"
    assert tc.target_module == "BoomTile"
    assert "dut.io.ifu.bpu_train_valid" in tc.scala_code
    assert "dut.io.csr.privilege_mode" in tc.scala_code
    assert "dut.io.lsu.req_valid" in tc.scala_code
    assert "dut.io.dcache.req.valid.expect" in tc.scala_code


def test_chisel_testbench_generate_suite():
    synth = ChiselTestbenchSynthesizer()
    prog1 = Program((Op.TRAIN, Op.ENTER_USER, Op.LOAD_SECRET, Op.ENCODE, Op.SQUASH, Op.PROBE))
    prog2 = Program((Op.ENTER_USER, Op.LOAD_SECRET, Op.PROBE))
    bench1 = next(b for b in BENCHMARKS if b.id == "transient-cache")
    bench2 = next(b for b in BENCHMARKS if b.id == "privilege-bypass")

    tc1 = synth.synthesize_test_case(prog1, bench1)
    tc2 = synth.synthesize_test_case(prog2, bench2)
    suite = synth.generate_suite_file([tc1, tc2])

    assert "package boom.tests" in suite
    assert "class BoomSecurityRegressionSuite" in suite
    assert "ChiselScalatestTester" in suite
    assert "SpecHunter Security Regression: transient-cache" in suite
    assert "SpecHunter Security Regression: privilege-bypass" in suite


def test_chisel_testbench_export(tmp_path: Path):
    synth = ChiselTestbenchSynthesizer()
    prog = Program((Op.TRAIN, Op.ENTER_USER, Op.LOAD_SECRET, Op.ENCODE, Op.SQUASH, Op.PROBE))
    bench = next(b for b in BENCHMARKS if b.id == "transient-cache")
    tc = synth.synthesize_test_case(prog, bench)

    out = tmp_path / "BoomSecuritySuite.scala"
    exported = synth.export_suite(out, [tc])
    assert exported == out
    assert out.is_file()
    content = out.read_text(encoding="utf-8")
    assert "package boom.tests" in content
