import importlib.util
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
_spec = importlib.util.spec_from_file_location(
    "benchmark_performance", REPO_ROOT / "tools/benchmark_performance.py"
)
_mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_mod)
benchmark_strategy = _mod.benchmark_strategy
run_benchmarks = _mod.run_benchmarks


def test_benchmark_strategy_guided():
    res = benchmark_strategy("guided", iterations=4, trials=2)
    assert res["strategy"] == "guided"
    assert res["trials"] == 2
    assert res["total_executions"] > 0
    assert res["discovery_rate_pct"] == 100.0
    assert res["peak_rss_mb"] > 0


def test_benchmark_strategy_random():
    res = benchmark_strategy("random", iterations=4, trials=2)
    assert res["strategy"] == "random"
    assert res["trials"] == 2
    assert res["total_executions"] > 0


def test_run_benchmarks_generates_json(tmp_path):
    out = tmp_path / "perf.json"
    res = run_benchmarks(trials=2, output_path=out)
    assert out.is_file()
    assert "search_strategies" in res
    assert "chia_security_block" in res
    assert res["search_strategies"]["guided"]["discovery_rate_pct"] == 100.0
