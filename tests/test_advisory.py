"""Unit tests for Hardware Security Advisory generator (spechunter.advisory)."""

from __future__ import annotations

import json

from spechunter.advisory import (
    get_advisory_data,
    render_advisory_html,
    render_advisory_json,
    render_advisory_markdown,
)


def test_get_advisory_data():
    data = get_advisory_data()
    assert data["advisory_id"] == "HSA-2026-0001"
    assert data["cwe_id"] == "CWE-1037"
    assert "BOOM" in data["target_core"]
    assert data["regression_scorecard"]["mutation_discovery_rate_pct"] == 100.0
    assert data["regression_scorecard"]["repair_clean_rate_pct"] == 100.0


def test_render_advisory_markdown():
    md = render_advisory_markdown()
    assert "# Hardware Security Advisory: HSA-2026-0001" in md
    assert "CWE-1037" in md
    assert "exu/lsu/lsu.scala" in md
    assert "Cycle 3804" in md
    assert "100.0%" in md


def test_render_advisory_html():
    html = render_advisory_html()
    assert "<!DOCTYPE html>" in html
    assert "HSA-2026-0001" in html
    assert "CWE-1037" in html
    assert "timeline" in html
    assert "<script" not in html.lower()  # Ensure zero <script> tags


def test_render_advisory_json():
    raw_json = render_advisory_json()
    data = json.loads(raw_json)
    assert data["advisory_id"] == "HSA-2026-0001"
    assert data["cvss_score"] == 7.4
    assert data["regression_scorecard"]["total_executions"] == 64
