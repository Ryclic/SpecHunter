"""Unit tests for the microarchitectural adversarial program synthesizer."""

import json

from spechunter.domain import Op
from spechunter.synthesis import (
    MicroarchitecturalSynthesizer,
    SynthesisConfig,
    ThreatModel,
)


def test_synthesize_spectre_bcb():
    synth = MicroarchitecturalSynthesizer(seed=1)
    cfg = SynthesisConfig(threat_model=ThreatModel.SPECTRE_BCB, training_iterations=16)
    artifact = synth.synthesize(cfg)

    assert artifact.config.threat_model == ThreatModel.SPECTRE_BCB
    assert Op.TRAIN in artifact.program.ops
    assert Op.LOAD_SECRET in artifact.program.ops
    assert Op.ENCODE in artifact.program.ops
    assert Op.PROBE in artifact.program.ops
    assert "spechunter_spectre_bcb" in artifact.assembly_source
    assert len(artifact.pipeline_phases) >= 4
    assert artifact.expected_ttfe_cycles > 0


def test_synthesize_meltdown_rdcl():
    synth = MicroarchitecturalSynthesizer(seed=2)
    cfg = SynthesisConfig(threat_model=ThreatModel.MELTDOWN_RDCL)
    artifact = synth.synthesize(cfg)

    assert artifact.config.threat_model == ThreatModel.MELTDOWN_RDCL
    assert Op.ENTER_USER in artifact.program.ops
    assert Op.LOAD_SECRET in artifact.program.ops
    assert Op.PROBE in artifact.program.ops
    assert "spechunter_meltdown_rdcl" in artifact.assembly_source


def test_synthesize_issue_715():
    synth = MicroarchitecturalSynthesizer(seed=3)
    cfg = SynthesisConfig(threat_model=ThreatModel.BOOM_ISSUE_715, eviction_sets=32)
    artifact = synth.synthesize(cfg)

    assert artifact.config.threat_model == ThreatModel.BOOM_ISSUE_715
    assert "spechunter_issue_715" in artifact.assembly_source
    assert any("translation" in p["signal"].lower() for p in artifact.pipeline_phases)


def test_synthesize_spec_store_bypass():
    synth = MicroarchitecturalSynthesizer(seed=4)
    cfg = SynthesisConfig(threat_model=ThreatModel.SPEC_STORE_BYPASS)
    artifact = synth.synthesize(cfg)

    assert artifact.config.threat_model == ThreatModel.SPEC_STORE_BYPASS
    assert "spechunter_spec_store_bypass" in artifact.assembly_source


def test_synthesize_from_invariant():
    synth = MicroarchitecturalSynthesizer()
    art1 = synth.synthesize_from_invariant("observable-isolation", threat="transient-cache")
    assert art1.config.threat_model == ThreatModel.SPECTRE_BCB

    art2 = synth.synthesize_from_invariant("architectural-isolation", threat="privilege-bypass")
    assert art2.config.threat_model == ThreatModel.MELTDOWN_RDCL

    art3 = synth.synthesize_from_invariant("translation-isolation", threat="boom_issue_715")
    assert art3.config.threat_model == ThreatModel.BOOM_ISSUE_715


def test_mutate_parameters():
    synth = MicroarchitecturalSynthesizer(seed=42)
    cfg = SynthesisConfig(
        threat_model=ThreatModel.SPECTRE_BCB, training_iterations=12, delay_cycles=24
    )
    art = synth.synthesize(cfg)
    mutated = synth.mutate_parameters(art)

    assert mutated.config.threat_model == art.config.threat_model
    # Mutated configuration should modify either training or delay
    assert (
        mutated.config.training_iterations != art.config.training_iterations
        or mutated.config.delay_cycles != art.config.delay_cycles
    )


def test_artifact_serialization():
    synth = MicroarchitecturalSynthesizer()
    art = synth.synthesize(SynthesisConfig(threat_model=ThreatModel.SPECTRE_BCB))
    dict_data = art.to_dict()
    assert dict_data["threat_model"] == "spectre_bcb"
    assert isinstance(dict_data["program_ops"], list)

    json_str = art.to_json()
    parsed = json.loads(json_str)
    assert parsed["threat_model"] == "spectre_bcb"
