"""Unit tests for microarchitectural Information Flow Tracking (IFT) engine."""

import json

from spechunter.domain import BENCHMARKS, Op, Program
from spechunter.taint import InformationFlowTracker, TaintReport


def test_taint_transient_cache_unmitigated():
    tracker = InformationFlowTracker(secret_bits=64)
    prog = Program((Op.TRAIN, Op.ENTER_USER, Op.LOAD_SECRET, Op.ENCODE, Op.SQUASH, Op.PROBE))
    bench = next(b for b in BENCHMARKS if b.id == "transient-cache")
    report = tracker.analyze(prog, bench, mitigated=False)

    assert isinstance(report, TaintReport)
    assert not report.non_interference_satisfied
    assert report.mutual_information_leakage_bits > 0.0
    assert report.leakage_classification == "TRANSIENT_COVERT_LEAKAGE"
    assert report.leakage_cycle == 4  # ENCODE stage
    assert report.residual_entropy_bits < 64.0


def test_taint_transient_cache_mitigated():
    tracker = InformationFlowTracker(secret_bits=64)
    prog = Program((Op.TRAIN, Op.ENTER_USER, Op.LOAD_SECRET, Op.ENCODE, Op.SQUASH, Op.PROBE))
    bench = next(b for b in BENCHMARKS if b.id == "transient-cache")
    report = tracker.analyze(prog, bench, mitigated=True)

    assert report.non_interference_satisfied
    assert report.mutual_information_leakage_bits == 0.0
    assert report.residual_entropy_bits == 64.0
    assert report.leakage_classification == "NON_INTERFERENT"
    assert report.leakage_cycle is None


def test_taint_privilege_bypass():
    tracker = InformationFlowTracker(secret_bits=64)
    prog = Program((Op.ENTER_USER, Op.LOAD_SECRET, Op.PROBE))
    bench = next(b for b in BENCHMARKS if b.id == "privilege-bypass")
    report = tracker.analyze(prog, bench, mitigated=False)

    assert not report.non_interference_satisfied
    assert report.mutual_information_leakage_bits == 64.0  # Full word exposed
    assert report.leakage_classification == "ARCHITECTURAL_EXPOSURE"


def test_taint_serialization():
    tracker = InformationFlowTracker(secret_bits=64)
    prog = Program((Op.TRAIN, Op.ENTER_USER, Op.LOAD_SECRET, Op.ENCODE, Op.SQUASH, Op.PROBE))
    bench = next(b for b in BENCHMARKS if b.id == "transient-cache")
    report = tracker.analyze(prog, bench, mitigated=False)

    data = report.to_dict()
    assert "mutual_information_leakage_bits" in data
    assert "execution_steps" in data
    assert len(data["execution_steps"]) == 6

    json_str = report.to_json()
    parsed = json.loads(json_str)
    assert parsed["benchmark_id"] == "transient-cache"


def test_taint_markdown_generation():
    tracker = InformationFlowTracker(secret_bits=64)
    prog = Program((Op.TRAIN, Op.ENTER_USER, Op.LOAD_SECRET, Op.ENCODE, Op.SQUASH, Op.PROBE))
    bench = next(b for b in BENCHMARKS if b.id == "transient-cache")
    report = tracker.analyze(prog, bench, mitigated=False)

    md = report.to_markdown()
    assert "# SpecHunter Information Flow Tracking & Non-Interference Analysis" in md
    assert "transient-cache" in md
    assert "Cycle-Accurate Taint Propagation Trace" in md
    assert "Input Secret Entropy" in md
