import hashlib
import json
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
    assert len(pins["BOOM_REVISION"]) == 40
    assert len(pins["BOOM_LSU_SHA256"]) == 64
    assert len(pins["BOOM_REPAIRED_LSU_SHA256"]) == 64


def test_candidate_boom_repair_is_minimal_and_fault_gated():
    patch = (ROOT / "tools/boom/patches/gate_faulting_loads.patch").read_text()
    assert patch.count("!ae_ld(w) && !pf_ld(w) && !ma_ld(w)") == 2
    assert patch.count("@@") == 2


def test_boom_repair_audit_binds_patch_and_source_pins():
    audit = json.loads((ROOT / "docs/evidence/boom-lsu-repair-audit-2026-09-11.json").read_text())
    patch = ROOT / audit["patch_path"]
    pins = dict(
        line.split("=", 1)
        for line in (ROOT / "tools/boom/pins.env").read_text().splitlines()
        if line and not line.startswith("#")
    )
    assert hashlib.sha256(patch.read_bytes()).hexdigest() == audit["patch_sha256"]
    assert audit["pristine_source_sha256"] == pins["BOOM_LSU_SHA256"]
    assert audit["repaired_source_sha256"] == pins["BOOM_REPAIRED_LSU_SHA256"]
    assert audit["rtl_before_after_validated"] is False


def test_bootstrap_rejects_root_owned_build_flow():
    script = (ROOT / "tools/boom/bootstrap.sh").read_text()
    assert "EUID -ne 0" in script
    assert '[[ -w "$parent_directory" ]]' in script


def test_gcp_worker_has_hard_lifetime_and_no_cloud_identity():
    script = (ROOT / "tools/boom/gcp_worker.sh").read_text()
    assert "--max-run-duration=6h" in script
    assert "--instance-termination-action=DELETE" in script
    assert "--no-service-account" in script
    assert "--no-scopes" in script
    assert "--image-family=rocky-linux-9-optimized-gcp" in script


def test_repair_builder_is_isolated_and_emits_bound_manifest():
    script = (ROOT / "tools/boom/build_repair_variant.sh").read_text()
    assert "cp -a --reflink=auto" in script
    assert '[[ ! -e "$repaired" ]]' in script
    assert "gate_faulting_loads.patch" in script
    assert 'CONFIG="$BOOM_CONFIG" clean' in script
    assert '"simulator_sha256"' in script


def test_smoke_requires_pinned_revision_and_real_payload_output():
    script = (ROOT / "tools/boom/build_and_smoke.sh").read_text()
    assert '== "$CHIPYARD_REVISION"' in script
    assert 'CONFIG="$BOOM_CONFIG"' in script
    assert "run-binary-fast" in script
    assert "Hello world from core 0, a sonicboom" in script
    assert '"simulator_sha256"' in script
    assert '-c safe.directory="$chipyard_directory"' in script


def test_privilege_smoke_uses_pmp_user_mode_and_two_executors():
    source = (ROOT / "tools/boom/privilege_smoke.S").read_text()
    script = (ROOT / "tools/boom/run_privilege_smoke.sh").read_text()
    assert "csrw pmpaddr0" in source
    assert "csrw pmpcfg0" in source
    assert "csrc mstatus" in source
    assert "mret" in source
    assert "mcause" in source
    assert "spike --isa=" in script
    assert '"$simulator"' in script
    assert "+max-cycles=10000000" in script
    assert '"spike_sha256"' in script
    assert '"spike_passed": True' in script
    assert '"boom_passed": True' in script
