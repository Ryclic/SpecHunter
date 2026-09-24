"""Unit tests for DifferentialOracle and differential microarchitectural analysis."""

from spechunter.differential import DifferentialOracle
from spechunter.domain import BENCHMARKS, Op, Program


def test_differential_oracle_transient_cache():
    oracle = DifferentialOracle(backend_kind="model")
    bench = next(b for b in BENCHMARKS if b.id == "transient-cache")
    prog = Program((Op.TRAIN, Op.ENTER_USER, Op.LOAD_SECRET, Op.ENCODE, Op.SQUASH, Op.PROBE))

    res = oracle.evaluate(prog, bench)
    assert res.benchmark_id == "transient-cache"
    assert res.baseline_leakage is True
    assert res.mitigated_leakage is False
    assert res.leakage_eliminated is True
    assert res.architectural_equivalence is True
    assert res.timing_delta_cycles == 9
    assert res.verdict == "VERIFIED_MITIGATION"


def test_differential_oracle_secure_control():
    oracle = DifferentialOracle(backend_kind="model")
    bench = next(b for b in BENCHMARKS if b.id == "secure-control")
    prog = Program((Op.TRAIN, Op.ENTER_USER, Op.LOAD_SECRET, Op.ENCODE, Op.SQUASH, Op.PROBE))

    res = oracle.evaluate(prog, bench)
    assert res.benchmark_id == "secure-control"
    assert res.baseline_leakage is False
    assert res.mitigated_leakage is False
    assert res.verdict == "CONTROL_CLEAN"


def test_differential_oracle_privilege_bypass():
    oracle = DifferentialOracle(backend_kind="model")
    bench = next(b for b in BENCHMARKS if b.id == "privilege-bypass")
    prog = Program((Op.ENTER_USER, Op.LOAD_SECRET))

    res = oracle.evaluate(prog, bench)
    assert res.benchmark_id == "privilege-bypass"
    assert res.baseline_leakage is True
    assert res.mitigated_leakage is False
    assert res.verdict == "VERIFIED_ISOLATION"


def test_differential_suite_evaluation():
    oracle = DifferentialOracle(backend_kind="model")
    report = oracle.evaluate_suite()

    assert report.benchmarks_evaluated == 4
    assert report.vulnerabilities_detected == 3
    assert report.mitigations_verified == 3
    assert report.persistent_leaks == 0
    assert report.clean_controls == 1

    json_str = report.to_json()
    assert '"vulnerabilities_detected": 3' in json_str
    assert '"mitigations_verified": 3' in json_str
