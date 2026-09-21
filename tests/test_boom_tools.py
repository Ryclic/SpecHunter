from pathlib import Path

ROOT = Path(__file__).parents[1]


def test_boom_inputs_are_pinned():
    pins = dict(
        line.split("=", 1)
        for line in (ROOT / "tools/boom/pins.env").read_text().splitlines()
        if line and not line.startswith("#")
    )
    assert pins["CHIPYARD_VERSION"] == "1.14.0"
    assert len(pins["CHIPYARD_REVISION"]) == 40
    assert pins["CHIPYARD_GLIBC"] == "2.34"
    assert len(pins["MINIFORGE_SHA256"]) == 64
    assert pins["BOOM_CONFIG"] == "SmallBoomV3Config"


def test_gcp_worker_has_hard_lifetime_and_no_cloud_identity():
    script = (ROOT / "tools/boom/gcp_worker.sh").read_text()
    assert "--max-run-duration=6h" in script
    assert "--instance-termination-action=DELETE" in script
    assert "--no-service-account" in script
    assert "--no-scopes" in script
    assert "--image-family=rocky-linux-9-optimized-gcp" in script


def test_smoke_requires_pinned_revision_and_real_payload_output():
    script = (ROOT / "tools/boom/build_and_smoke.sh").read_text()
    assert '== "$CHIPYARD_REVISION"' in script
    assert 'CONFIG="$BOOM_CONFIG"' in script
    assert "run-binary-fast" in script
    assert "Hello world from core 0, a sonicboom" in script
    assert '"simulator_sha256"' in script
