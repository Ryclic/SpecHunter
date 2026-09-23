"""Unit tests for the feedback-driven microarchitectural guided search engine."""

from spechunter.backends import Backend, BackendConfig
from spechunter.domain import BENCHMARKS, Op, Program
from spechunter.loop import validate
from spechunter.search import GuidedSearchEngine, evaluate_feedback


def test_evaluate_feedback_metrics():
    benchmark = BENCHMARKS[1]  # transient-cache
    config = BackendConfig(kind="model")
    prog_clean = Program((Op.ENTER_USER, Op.PROBE))
    prog_vuln = Program((Op.TRAIN, Op.ENTER_USER, Op.LOAD_SECRET, Op.ENCODE, Op.SQUASH, Op.PROBE))

    with Backend(config) as backend:
        v_clean = validate(backend, prog_clean, benchmark)
        score_clean, fb_clean = evaluate_feedback(v_clean, prog_clean)

        v_vuln = validate(backend, prog_vuln, benchmark)
        score_vuln, fb_vuln = evaluate_feedback(v_vuln, prog_vuln)

    assert score_vuln > score_clean
    assert fb_vuln["has_transient_load"] is True
    assert fb_vuln["has_diff"] is True


def test_guided_search_discovers_transient_cache():
    benchmark = next(b for b in BENCHMARKS if b.id == "transient-cache")
    engine = GuidedSearchEngine(BackendConfig(kind="model"), max_iterations=16, seed=42)
    result = engine.search(benchmark)

    assert result.success is True
    assert result.verdict == "VIOLATION_CONFIRMED"
    assert result.discovered_program is not None
    assert result.minimized_program is not None
    assert len(result.minimized_program.ops) <= len(result.discovered_program.ops)
    assert len(result.score_trajectory) > 0
    assert result.time_to_first_exploit_ms > 0
    assert result.simulations_evaluated > 0


def test_guided_search_discovers_privilege_bypass():
    benchmark = next(b for b in BENCHMARKS if b.id == "privilege-bypass")
    engine = GuidedSearchEngine(BackendConfig(kind="model"), max_iterations=16, seed=42)
    result = engine.search(benchmark)

    assert result.success is True
    assert result.verdict == "VIOLATION_CONFIRMED"
    assert result.discovered_program is not None


def test_guided_search_clean_on_secure_control():
    benchmark = next(b for b in BENCHMARKS if b.id == "secure-control")
    engine = GuidedSearchEngine(BackendConfig(kind="model"), max_iterations=8, seed=42)
    result = engine.search(benchmark)

    assert result.success is False
    assert result.verdict == "CLEAN_OR_EXHAUSTED"
    assert result.discovered_program is None
