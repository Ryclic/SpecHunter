"""Unit tests for the hierarchical delta debugger."""

import json

from spechunter.backends import Backend, BackendConfig
from spechunter.domain import BENCHMARKS, Op, Program
from spechunter.minimizer import HierarchicalDeltaDebugger


def test_hierarchical_delta_debugger_transient_cache():
    benchmark = next(b for b in BENCHMARKS if b.id == "transient-cache")
    # Candidate with redundant NOPs and extraneous squash
    candidate = Program(
        (
            Op.NOP,
            Op.TRAIN,
            Op.NOP,
            Op.ENTER_USER,
            Op.NOP,
            Op.LOAD_SECRET,
            Op.ENCODE,
            Op.SQUASH,
            Op.PROBE,
        )
    )
    debugger = HierarchicalDeltaDebugger()
    with Backend(BackendConfig(kind="model")) as backend:
        report = debugger.minimize(backend, candidate, benchmark)

    assert report.original_length == 9
    assert report.minimized_length < report.original_length
    assert report.reduction_percentage > 0
    assert report.total_validations > 0
    assert "nop" not in report.minimized_ops
    assert Op.LOAD_SECRET.value in report.minimized_ops
    assert Op.ENCODE.value in report.minimized_ops
    assert len(report.steps_record) > 0


def test_minimizer_preserves_positive_control():
    benchmark = next(b for b in BENCHMARKS if b.id == "boom-positive-control")
    candidate = Program((Op.NOP, Op.ENTER_USER, Op.LOAD_SECRET, Op.NOP, Op.PROBE))
    debugger = HierarchicalDeltaDebugger(preserve_positive_control=True)
    with Backend(BackendConfig(kind="model")) as backend:
        report = debugger.minimize(backend, candidate, benchmark)

    assert Op.LOAD_SECRET.value in report.minimized_ops
    assert Op.PROBE.value in report.minimized_ops
    assert "nop" not in report.minimized_ops


def test_minimization_report_serialization():
    benchmark = next(b for b in BENCHMARKS if b.id == "privilege-bypass")
    candidate = Program((Op.NOP, Op.ENTER_USER, Op.LOAD_SECRET, Op.PROBE))
    debugger = HierarchicalDeltaDebugger()
    with Backend(BackendConfig(kind="model")) as backend:
        report = debugger.minimize(backend, candidate, benchmark)

    data = report.to_dict()
    assert data["original_length"] == 4
    assert data["minimized_length"] <= 3

    json_str = report.to_json()
    parsed = json.loads(json_str)
    assert parsed["minimized_digest"] == report.minimized_digest
