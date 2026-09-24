import json
import xml.etree.ElementTree as ET

import pytest

from spechunter.harness import (
    HarnessReport,
    export_junit_xml,
    render_harness_json,
    render_harness_terminal,
    run_harness,
    run_single_harness_test,
)


def test_run_single_harness_test_vulnerable():
    res = run_single_harness_test("transient-cache", simulated_mitigation=False)
    assert res.test_id == "transient-cache"
    assert res.status == "VULNERABILITY_CONFIRMED"
    assert res.cycles_to_leak == 7
    assert res.leak_observed is True
    assert "D-Cache Set Tag Mismatch" in res.microarchitectural_signal
    assert "spec_fence" in res.remedy


def test_run_single_harness_test_mitigated():
    res = run_single_harness_test("issue-715", simulated_mitigation=True)
    assert res.test_id == "issue-715"
    assert res.status == "MITIGATED"
    assert res.cycles_to_leak == 0
    assert res.leak_observed is False
    assert "Speculation Gated" in res.microarchitectural_signal
    assert "dcache.fire" in res.remedy


def test_run_harness_all():
    report = run_harness()
    assert isinstance(report, HarnessReport)
    assert report.total_tests == 3
    assert report.vulnerabilities_confirmed == 3
    assert report.mitigated_count == 0
    assert len(report.results) == 3


def test_run_harness_subset():
    report = run_harness(poc_names=["privilege-bypass"])
    assert report.total_tests == 1
    assert report.results[0].test_id == "privilege-bypass"


def test_run_harness_invalid():
    with pytest.raises(ValueError, match="Unknown PoC"):
        run_harness(poc_names=["nonexistent-poc"])


def test_export_junit_xml_vulnerable(tmp_path):
    xml_path = tmp_path / "report.xml"
    report = run_harness(verify_mitigations=False)
    export_junit_xml(report, xml_path)

    assert xml_path.is_file()
    tree = ET.parse(xml_path)
    root = tree.getroot()
    assert root.tag == "testsuite"
    assert root.attrib["name"] == "SpecHunter.BOOM.SecuritySuite"
    assert root.attrib["tests"] == "3"
    assert root.attrib["failures"] == "3"

    testcases = root.findall("testcase")
    assert len(testcases) == 3
    for tc in testcases:
        failure = tc.find("failure")
        assert failure is not None
        assert "MicroarchitecturalVulnerability" in failure.attrib["type"]


def test_export_junit_xml_mitigated(tmp_path):
    xml_path = tmp_path / "mitigated.xml"
    report = run_harness(verify_mitigations=True)
    export_junit_xml(report, xml_path)

    assert xml_path.is_file()
    tree = ET.parse(xml_path)
    root = tree.getroot()
    assert root.attrib["failures"] == "0"

    testcases = root.findall("testcase")
    assert len(testcases) == 3
    for tc in testcases:
        assert tc.find("failure") is None


def test_render_harness_terminal_and_json():
    report = run_harness()
    term = render_harness_terminal(report)
    assert "=== Berkeley BOOM Upstream Security Test Harness ===" in term
    assert "transient-cache" in term

    raw_json = render_harness_json(report)
    data = json.loads(raw_json)
    assert data["total_tests"] == 3
    assert data["vulnerabilities_confirmed"] == 3
