from spechunter.domain import BENCHMARKS
from spechunter.taxonomy import (
    SPECTRE_TAXONOMY,
    MicroarchitecturalTaxonomy,
    SpectreVariant,
)


def test_spectre_taxonomy_variants_complete():
    assert "spectre-v1-bcb" in SPECTRE_TAXONOMY
    assert "spectre-v2-bti" in SPECTRE_TAXONOMY
    assert "spectre-v4-ssb" in SPECTRE_TAXONOMY
    assert "meltdown-rdcl" in SPECTRE_TAXONOMY
    assert "seeded-cache-leak" in SPECTRE_TAXONOMY
    assert "secure-baseline" in SPECTRE_TAXONOMY


def test_taxonomy_attributes_structure():
    entry = SPECTRE_TAXONOMY["spectre-v1-bcb"]
    assert isinstance(entry, MicroarchitecturalTaxonomy)
    assert entry.variant == SpectreVariant.SPECTRE_V1_BCB
    assert "Branch Prediction" in entry.boom_subsystem
    assert "L1 Data Cache" in entry.transmission_channel
    assert "core.scala" in entry.interlock_gate
    assert "core.scala" in entry.chisel_source


def test_benchmarks_bind_taxonomy():
    for benchmark in BENCHMARKS:
        assert benchmark.id in SPECTRE_TAXONOMY
        taxonomy = SPECTRE_TAXONOMY[benchmark.id]
        assert isinstance(taxonomy, MicroarchitecturalTaxonomy)
        assert taxonomy.name
        assert taxonomy.boom_subsystem
