"""Tests for Multi-Core TileLink Cache Coherence & Cross-Core Snoop Analyzer."""

import json
from pathlib import Path

from spechunter.coherence import (
    CoherenceState,
    TileLinkCoherenceSimulator,
    TileLinkOpcode,
)


def test_coherence_unmitigated_cross_core_snoop_leak():
    sim = TileLinkCoherenceSimulator(num_cores=2)
    report = sim.simulate_attack(mitigated=False)

    assert report.system_cores == 2
    assert not report.mitigated
    assert report.core_initial_states[1] == CoherenceState.EXCLUSIVE.value
    assert report.core_final_states[1] == CoherenceState.SHARED.value
    assert report.victim_latency_delta_cycles == 142
    assert report.cross_core_leakage_bits == 1.0
    assert report.security_verdict == "CROSS_CORE_COHERENCE_EXPOSURE"
    assert len(report.transactions) >= 4

    channels = [t.channel for t in report.transactions]
    assert "A" in channels
    assert "B" in channels
    assert "C" in channels
    assert "D" in channels
    assert report.transactions[0].opcode == TileLinkOpcode.ACQUIRE_BLOCK


def test_coherence_mitigated_snoop_quarantine_isolation():
    sim = TileLinkCoherenceSimulator(num_cores=2)
    report = sim.simulate_attack(mitigated=True)

    assert report.mitigated
    assert report.core_initial_states[1] == CoherenceState.EXCLUSIVE.value
    assert report.core_final_states[1] == CoherenceState.EXCLUSIVE.value
    assert report.victim_latency_delta_cycles == 0
    assert report.cross_core_leakage_bits == 0.0
    assert report.security_verdict == "NON_INTERFERENT_ISOLATED"

    # In mitigated mode, Channel B Probe to Core 1 is never emitted
    channels = [t.channel for t in report.transactions]
    assert "B" not in channels


def test_coherence_report_serialization(tmp_path: Path):
    sim = TileLinkCoherenceSimulator(num_cores=2)
    report = sim.simulate_attack(mitigated=False)

    json_str = report.to_json()
    data = json.loads(json_str)
    assert data["cross_core_leakage_bits"] == 1.0
    assert "transactions" in data

    md_str = report.to_markdown()
    assert "# SpecHunter Multi-Core TileLink Coherence Snoop Security Report" in md_str
    assert "Dual-Core Berkeley BOOM" in md_str
    assert "TileLink-C Protocol Transaction Log" in md_str

    json_file = tmp_path / "coherence_report.json"
    sim.export_report(json_file, report)
    assert json_file.exists()
    assert "CROSS_CORE_COHERENCE_EXPOSURE" in json_file.read_text(encoding="utf-8")

    md_file = tmp_path / "coherence_report.md"
    sim.export_report(md_file, report)
    assert md_file.exists()
    assert "# SpecHunter Multi-Core TileLink" in md_file.read_text(encoding="utf-8")
