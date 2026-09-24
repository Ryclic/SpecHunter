from spechunter.agents import VertexAgentProvider
from spechunter.domain import BENCHMARKS


def test_positive_control_attacker_receives_threat_model_constraints():
    provider = object.__new__(VertexAgentProvider)
    captured = {}

    def generate(role, payload, schema):
        captured.update(payload)
        return {
            "outcome": "candidate",
            "rationale": "bounded positive-control candidate",
            "program": ["enter_user", "load_secret", "probe"],
        }

    provider._generate = generate
    benchmark = next(item for item in BENCHMARKS if item.id == "boom-positive-control")
    provider.attack(benchmark, {"hypothesis": "test"}, [], False)

    constraints = captured["benchmark_constraints"]
    assert any("enter_user before load_secret" in item for item in constraints)
    assert any("load_secret and a later probe" in item for item in constraints)
    assert any("Do not return exhausted" in item for item in constraints)
