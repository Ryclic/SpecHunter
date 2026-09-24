"""Tests for Monte Carlo Tree Search (MCTS) Exploit Synthesizer."""

import json
from pathlib import Path

from spechunter.domain import BENCHMARKS, Op, Program
from spechunter.mcts import MCTSNode, MCTSSearchEngine


def test_mcts_node_actions():
    node = MCTSNode(program=Program(ops=(Op.TRAIN,)))
    assert not node.is_fully_expanded
    assert len(node.untried_actions) > 5

    action = node.untried_actions.pop(0)
    child_prog = node.apply_action(action)
    child = MCTSNode(program=child_prog, parent=node, action=action, depth=1)
    node.children[action.key()] = child

    node.visit_count = 10
    child.visit_count = 2
    child.total_reward = 1.6
    assert child.q_value == 0.8
    best = node.best_child()
    assert best == child


def test_mcts_exploit_synthesis():
    target = BENCHMARKS[0]  # transient-cache
    engine = MCTSSearchEngine(benchmark=target, seed=42)
    result = engine.search(budget_iterations=25)

    assert result.simulations_evaluated > 0
    assert result.max_tree_depth > 0
    assert result.total_tree_nodes > 1
    assert result.discovered_program is not None
    assert len(result.action_frequencies) > 0


def test_mcts_serialization(tmp_path: Path):
    target = BENCHMARKS[1]  # privilege-bypass
    engine = MCTSSearchEngine(benchmark=target, seed=10)
    result = engine.search(budget_iterations=15)

    json_str = result.to_json()
    data = json.loads(json_str)
    assert "simulations_evaluated" in data
    assert "verdict" in data
    assert "action_frequencies" in data

    md_str = result.to_markdown()
    assert "# SpecHunter Monte Carlo Tree Search (MCTS)" in md_str
    assert "Algorithmic Action Frequency Distribution" in md_str

    out_file = tmp_path / "mcts_report.json"
    engine.export_report(out_file, result)
    assert out_file.exists()
    assert "simulations_evaluated" in out_file.read_text(encoding="utf-8")
