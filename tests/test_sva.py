"""Unit tests for SystemVerilog Assertion (SVA) formal property generator."""

import json
from pathlib import Path

import pytest

from spechunter.sva import SVA_CATALOG, SVAGenerator, SVAProperty


def test_sva_catalog_entries():
    gen = SVAGenerator()
    props = gen.list_properties()
    assert "pmp-speculative-isolation" in props
    assert "issue-715-translation-order" in props
    assert "bpu-privilege-isolation" in props
    assert "covert-cache-line-clean" in props


def test_sva_get_property():
    gen = SVAGenerator()
    prop = gen.get_property("pmp-speculative-isolation")
    assert isinstance(prop, SVAProperty)
    assert prop.property_id == "pmp_speculative_isolation"
    assert prop.target_module == "LSU"
    assert "CWE-1272" in prop.cwe_id
    assert "assert property" in prop.assertion_statement
    assert "cover property" in prop.cover_statement
    assert "bind LSU" in prop.bind_statement


def test_sva_unknown_property_raises():
    gen = SVAGenerator()
    with pytest.raises(KeyError, match="Unknown SVA property"):
        gen.get_property("non-existent-hazard")


def test_sva_render_systemverilog():
    gen = SVAGenerator()
    prop = gen.get_property("issue-715-translation-order")
    sv = prop.to_systemverilog()
    assert "module issue_715_translation_order_checker" in sv
    assert "p_issue_715_translation_order" in sv
    assert "assert property" in sv
    assert "cover property" in sv
    assert "bind LSU" in sv


def test_sva_generate_bind_file():
    gen = SVAGenerator()
    bind_file = gen.generate_bind_file()
    assert "`ifndef SPECHUNTER_SVA_SV" in bind_file
    assert "`define SPECHUNTER_SVA_SV" in bind_file
    assert "pmp_speculative_isolation_checker" in bind_file
    assert "issue_715_translation_order_checker" in bind_file
    assert "bpu_privilege_isolation_checker" in bind_file
    assert "`endif // SPECHUNTER_SVA_SV" in bind_file


def test_sva_export_bind_file(tmp_path: Path):
    gen = SVAGenerator()
    out = tmp_path / "boom_sva_bind.sv"
    exported = gen.export_bind_file(out)
    assert exported == out
    assert out.exists()
    content = out.read_text(encoding="utf-8")
    assert "SpecHunter Formal Verification Suite" in content
    assert len(content) > 1000


def test_sva_to_json():
    gen = SVAGenerator()
    data = json.loads(gen.to_json())
    assert isinstance(data, dict)
    assert len(data) == len(SVA_CATALOG)
    assert "pmp-speculative-isolation" in data
