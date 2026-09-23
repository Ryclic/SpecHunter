"""Tests for Microarchitectural Waveform Synthesis and Pipeline Race Condition Analyzer."""

from pathlib import Path

from spechunter.domain import BENCHMARKS, Op, Program
from spechunter.waveform import (
    HazardType,
    SignalTrace,
    WaveformSynthesizer,
)


def test_signal_trace_ascii_rendering():
    sig = SignalTrace(name="test_clk", width=1, values=[0, 1, 1, 0, 0])
    ascii_wave = sig.render_ascii()
    assert "_" in ascii_wave
    assert "~" in ascii_wave

    bus = SignalTrace(name="test_bus", width=32, values=[0x8000, 0x9000])
    bus_ascii = bus.render_ascii()
    assert "[8000]" in bus_ascii
    assert "[9000]" in bus_ascii


def test_waveform_synthesis_transient_cache_unmitigated():
    bench = next(b for b in BENCHMARKS if b.id == "transient-cache")
    prog = Program([Op.TRAIN, Op.ENTER_USER, Op.LOAD_SECRET, Op.ENCODE, Op.SQUASH, Op.PROBE])
    wsynth = WaveformSynthesizer()
    trace = wsynth.synthesize(prog, bench, mitigated=False)

    assert trace.benchmark_id == "transient-cache"
    assert not trace.mitigated
    assert trace.total_cycles == 10
    assert len(trace.hazards) == 1

    hazard = trace.hazards[0]
    assert hazard.hazard_type == HazardType.TRANSIENT_COVERT_MODULATION
    assert hazard.vulnerability_window_cycles == 2
    assert not hazard.mitigated
    assert "residual covert" in hazard.description


def test_waveform_synthesis_transient_cache_mitigated():
    bench = next(b for b in BENCHMARKS if b.id == "transient-cache")
    prog = Program([Op.TRAIN, Op.ENTER_USER, Op.LOAD_SECRET, Op.ENCODE, Op.SQUASH, Op.PROBE])
    wsynth = WaveformSynthesizer()
    trace = wsynth.synthesize(prog, bench, mitigated=True)

    assert trace.mitigated
    assert len(trace.hazards) == 1
    hazard = trace.hazards[0]
    assert hazard.vulnerability_window_cycles == 0
    assert hazard.mitigated
    assert "gated LSU dispatch" in hazard.description


def test_waveform_synthesis_privilege_bypass():
    bench = next(b for b in BENCHMARKS if b.id == "privilege-bypass")
    prog = Program([Op.ENTER_USER, Op.LOAD_SECRET, Op.PROBE])
    wsynth = WaveformSynthesizer()

    unmitigated = wsynth.synthesize(prog, bench, mitigated=False)
    assert unmitigated.hazards[0].hazard_type == HazardType.PMP_DISPATCH_TOCTOU
    assert unmitigated.hazards[0].vulnerability_window_cycles == 1
    assert not unmitigated.hazards[0].mitigated

    mitigated = wsynth.synthesize(prog, bench, mitigated=True)
    assert mitigated.hazards[0].vulnerability_window_cycles == 0
    assert mitigated.hazards[0].mitigated


def test_waveform_vcd_generation(tmp_path: Path):
    bench = next(b for b in BENCHMARKS if b.id == "transient-cache")
    prog = Program([Op.TRAIN, Op.LOAD_SECRET])
    wsynth = WaveformSynthesizer()
    trace = wsynth.synthesize(prog, bench, mitigated=False)

    vcd = trace.to_vcd()
    assert "$timescale 1ns $end" in vcd
    assert "$scope module BoomTile $end" in vcd
    assert "$var wire" in vcd
    assert "$dumpvars" in vcd
    assert "#10" in vcd

    vcd_path = tmp_path / "test_boom.vcd"
    wsynth.export_vcd(vcd_path, trace)
    assert vcd_path.exists()
    assert vcd_path.read_text() == vcd


def test_waveform_diagram_and_json():
    bench = next(b for b in BENCHMARKS if b.id == "transient-cache")
    prog = Program([Op.LOAD_SECRET])
    wsynth = WaveformSynthesizer()
    trace = wsynth.synthesize(prog, bench, mitigated=False)

    diagram = trace.render_diagram()
    assert "Microarchitectural Waveform Timing Diagram" in diagram
    assert "clk" in diagram
    assert "io_lsu_req_valid" in diagram
    assert "DETECTED PIPELINE HAZARDS" in diagram

    json_str = trace.to_json()
    assert '"benchmark_id": "transient-cache"' in json_str
    assert '"vulnerability_window_cycles": 2' in json_str
