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


def test_run_benchmarks_quiet(tmp_path, capsys):
    out = tmp_path / "perf_quiet.json"
    res = run_benchmarks(trials=2, output_path=out, quiet=True)
    captured = capsys.readouterr().out
    assert captured == ""
    assert out.is_file()
    assert "search_strategies" in res


def test_benchmark_main_json(capsys, monkeypatch, tmp_path):
    import json
    import sys

    out = tmp_path / "main_perf.json"
    main_func = _mod.main
    monkeypatch.setattr(
        sys, "argv", ["benchmark_performance.py", "--trials", "2", "--output", str(out), "--json"]
    )
    assert main_func() == 0
    captured = capsys.readouterr().out
    json_start = captured.find("{")
    assert json_start != -1
    data = json.loads(captured[json_start:])
    assert "search_strategies" in data
    assert data["search_strategies"]["guided"]["discovery_rate_pct"] == 100.0


def test_generate_benchmark_svg():
    gen_func = _mod.generate_benchmark_svg
    dummy = {
        "search_strategies": {
            "guided": {
                "discovery_rate_pct": 100.0,
                "sim_throughput_hz": 80000.0,
                "avg_duration_sec": 0.001,
            },
            "random": {
                "discovery_rate_pct": 0.0,
                "sim_throughput_hz": 60000.0,
                "avg_duration_sec": 0.0012,
            },
        },
        "system_peak_rss_mb": 400.0,
    }
    svg = gen_func(dummy)
    assert "<svg" in svg
    assert "</svg>" in svg
    assert "Guided Search" in svg
    assert "100.0%" in svg
    assert "400.0 MB" in svg


def test_run_benchmarks_generates_svg(tmp_path):
    out = tmp_path / "perf.json"
    svg_out = tmp_path / "perf.svg"
    res = run_benchmarks(trials=2, output_path=out, svg_path=svg_out, quiet=True)
    assert svg_out.is_file()
    assert "<svg" in svg_out.read_text(encoding="utf-8")
    assert "search_strategies" in res
