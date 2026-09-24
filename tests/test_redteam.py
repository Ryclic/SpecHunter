"""Unit tests for AutonomousRedTeam campaign engine."""

from spechunter.domain import BENCHMARKS
from spechunter.redteam import AutonomousRedTeam


def test_autonomous_redteam_campaign():
    redteam = AutonomousRedTeam(backend_kind="model")
    report = redteam.run_campaign()

    assert report.targets_evaluated == 4
    assert report.vulnerabilities_discovered == 3
    assert report.mitigations_verified == 3
    assert report.attacker_exhaustion_rate == 1.0
    assert report.false_positives == 0
    assert report.all_syntax_valid is True
    assert report.verdict == "A3_HACKATHON_VICTORY_CERTIFIED"

    # Verify JSON output
    json_out = report.to_json()
    assert '"verdict": "A3_HACKATHON_VICTORY_CERTIFIED"' in json_out
    assert '"attacker_exhaustion_rate": 1.0' in json_out

    # Verify Markdown scorecard
    md_out = report.to_markdown()
    assert "# SpecHunter Autonomous Red-Team Campaign" in md_out
    assert "A3_HACKATHON_VICTORY_CERTIFIED" in md_out
    assert "| `privilege-bypass` | ✓ |" in md_out
    assert "| `transient-cache` | ✓ |" in md_out
    assert "| `secure-control` | ✗ |" in md_out


def test_autonomous_redteam_single_target():
    redteam = AutonomousRedTeam(backend_kind="model")
    target = next(b for b in BENCHMARKS if b.id == "transient-cache")
    res = redteam.run_target(target)

    assert res.benchmark_id == "transient-cache"
    assert res.discovered is True
    assert res.differential_verdict == "VERIFIED_MITIGATION"
    assert res.patch_id == "bpu-barrier-flush"
    assert res.patch_syntax_valid is True
    assert res.attacker_exhausted is True
