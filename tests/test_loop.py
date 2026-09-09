import random
import shutil

import pytest

from spechunter.backends import Backend, BackendConfig
from spechunter.domain import BENCHMARKS, Observation, Op, Program
from spechunter.loop import attack, experiment, minimize, validate


def test_guided_discovers_seeded_bugs_and_rejects_control():
    report = experiment(iterations=3)
    assert report["metrics"]["discovered"] == 2
    assert report["metrics"]["false_positives"] == 0
    assert report["metrics"]["inconclusive_cases"] == 0
    assert not report["provenance"]["is_boom_evidence"]
    for result in report["results"][:2]:
        assert result["finding"]["repair"]["verified"]
        assert not result["finding"]["repair"]["rtl_patch_applied"]


def test_reproducible_random_baseline():
    assert experiment(strategy="random", seed=42) == experiment(strategy="random", seed=42)


def test_witness_is_one_minimal():
    with Backend(BackendConfig()) as backend:
        for benchmark in BENCHMARKS[:2]:
            candidate = attack(benchmark, "guided", random.Random(0), 1)
            reduced = minimize(backend, candidate, benchmark)
            assert validate(backend, reduced, benchmark).violation
            for i in range(len(reduced.ops)):
                assert not validate(
                    backend, Program(reduced.ops[:i] + reduced.ops[i + 1 :]), benchmark
                ).violation


def test_no_observation_is_not_a_finding():
    with Backend(BackendConfig()) as backend:
        assert validate(backend, Program((Op.NOP,)), BENCHMARKS[0]).status == "clean"


def test_nondeterminism_is_inconclusive():
    class Unstable:
        calls = 0

        def execute(self, *args):
            self.calls += 1
            return Observation((self.calls,), (), ())

    assert validate(Unstable(), Program((Op.NOP,)), BENCHMARKS[0]).status == "inconclusive"


@pytest.mark.parametrize("values", [[], ["bad"], ["nop"] * 129])
def test_reject_invalid_programs(values):
    with pytest.raises(ValueError):
        Program.parse(values)


@pytest.mark.rtl
@pytest.mark.skipif(not shutil.which("iverilog"), reason="Icarus Verilog unavailable")
def test_rtl_matches_model_for_random_and_guided_programs():
    rng = random.Random(19)
    programs = [attack(b, "guided", rng, i) for b in BENCHMARKS for i in (0, 1)]
    programs += [attack(BENCHMARKS[0], "random", rng, i) for i in range(100)]
    with Backend(BackendConfig()) as model, Backend(BackendConfig(kind="rtl")) as rtl:
        for program in programs:
            for secret in (0, 1):
                for bug in ("none", "privilege", "transient"):
                    assert rtl.execute(program, secret, bug) == model.execute(program, secret, bug)


def test_privileged_cache_encoding_is_outside_threat_model():
    program = Program.parse(["load_secret", "encode", "enter_user", "probe"])
    with Backend(BackendConfig()) as backend:
        assert validate(backend, program, BENCHMARKS[2]).status == "inconclusive"


def test_random_control_never_leaks():
    for seed in range(10):
        report = experiment(strategy="random", iterations=100, seed=seed)
        assert report["metrics"]["false_positives"] == 0
        assert report["metrics"]["inconclusive_cases"] == 0
