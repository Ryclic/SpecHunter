"""Unit tests for PoC exploit disassembly and assembly export (spechunter.poc)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from spechunter.poc import (
    export_pocs,
    get_poc,
    list_pocs,
    render_poc_json,
    render_poc_text,
)


def test_list_pocs():
    pocs = list_pocs()
    assert "transient-cache" in pocs
    assert "privilege-bypass" in pocs
    assert "issue-715" in pocs


def test_get_poc():
    poc = get_poc("transient-cache")
    assert poc.name == "transient-cache"
    assert "Spectre-v1" in poc.variant
    assert len(poc.instructions) >= 5

    with pytest.raises(KeyError):
        get_poc("nonexistent-poc")


def test_render_poc_text():
    text = render_poc_text("issue-715")
    assert "SpecHunter Proof-of-Concept: issue-715" in text
    assert "0x80028e08" in text
    assert "59f50483" in text
    assert "lb sp, -2048(t1)" in text


def test_render_poc_json():
    raw_all = render_poc_json()
    all_data = json.loads(raw_all)
    assert "transient-cache" in all_data
    assert "privilege-bypass" in all_data
    assert "issue-715" in all_data

    raw_single = render_poc_json("privilege-bypass")
    single_data = json.loads(raw_single)
    assert single_data["name"] == "privilege-bypass"
    assert "Meltdown" in single_data["variant"]


def test_export_pocs(tmp_path: Path):
    out_dir = tmp_path / "pocs"
    exported = export_pocs(out_dir)
    assert len(exported) == 6  # 3 .s files + 3 .json files

    s_file = out_dir / "transient-cache.s"
    assert s_file.is_file()
    assert ".global _start" in s_file.read_text(encoding="utf-8")

    json_file = out_dir / "issue-715.json"
    assert json_file.is_file()
    data = json.loads(json_file.read_text(encoding="utf-8"))
    assert data["name"] == "issue-715"
