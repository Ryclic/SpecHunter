import json

from spechunter.ablation import (
    AblationStudy,
    get_default_ablation_study,
    render_ablation_json,
    render_ablation_markdown,
    render_ablation_terminal,
    two_proportion_z_test,
    wilson_score_interval,
)


def test_wilson_score_interval_bounds():
    lower, upper = wilson_score_interval(100, 100)
    assert lower > 0.95
    assert upper == 1.0

    lower, upper = wilson_score_interval(0, 100)
    assert lower == 0.0
    assert upper < 0.05

    lower, upper = wilson_score_interval(50, 100)
    assert 0.40 < lower < 0.50
    assert 0.50 < upper < 0.60

    # Edge cases
    assert wilson_score_interval(0, 0) == (0.0, 0.0)
    assert wilson_score_interval(-5, 10) == wilson_score_interval(0, 10)
    assert wilson_score_interval(15, 10) == wilson_score_interval(10, 10)


def test_two_proportion_z_test():
    # Identical proportions
    assert two_proportion_z_test(50, 100, 50, 100) == 1.0

    # Invalid trials
    assert two_proportion_z_test(10, 0, 10, 100) == 1.0
    assert two_proportion_z_test(10, 100, 10, 0) == 1.0

    # Large difference: 100/100 vs 0/100
    p = two_proportion_z_test(100, 100, 0, 100)
    assert p < 0.0001

    # Moderate difference
    p_mod = two_proportion_z_test(60, 100, 40, 100)
    assert 0.001 < p_mod < 0.05


def test_get_default_ablation_study():
    study = get_default_ablation_study("transient-cache")
    assert isinstance(study, AblationStudy)
    assert study.benchmark_name == "transient-cache"
    assert len(study.strategies) == 4

    strategy_ids = [s.strategy_id for s in study.strategies]
    assert "guided-invariant" in strategy_ids
    assert "greedy-heuristic" in strategy_ids
    assert "pure-llm-zero-shot" in strategy_ids
    assert "random-fuzzing" in strategy_ids

    guided = next(s for s in study.strategies if s.strategy_id == "guided-invariant")
    assert guided.discovery_rate_pct == 100.0
    assert guided.sim_throughput_hz > 80000.0
    assert guided.mean_ttfe_ms < 1.0
    assert guided.p_value_vs_random < 0.0001


def test_render_ablation_markdown():
    study = get_default_ablation_study("privilege-bypass")
    md = render_ablation_markdown(study)
    assert "# SpecHunter Ablation Study" in md
    assert "privilege-bypass" in md
    assert "Discovery Rate (%)" in md
    assert "SpecHunter Guided Invariant Search" in md
    assert "Unguided Random Fuzzing" in md
    assert "Empirical Findings & Insights" in md


def test_render_ablation_terminal():
    study = get_default_ablation_study("transient-cache")
    term = render_ablation_terminal(study)
    assert "=== SpecHunter Ablation Study" in term
    assert "transient-cache" in term
    assert "Strategy" in term
    assert "Key Takeaways:" in term


def test_render_ablation_json():
    study = get_default_ablation_study("transient-cache")
    raw = render_ablation_json(study)
    data = json.loads(raw)
    assert data["benchmark_name"] == "transient-cache"
    assert "strategies" in data
    assert len(data["strategies"]) == 4
