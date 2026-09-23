import pytest

from spechunter.backends import BackendConfig


@pytest.mark.chia
def test_local_chia_node():
    pytest.importorskip("chia")
    from spechunter.chia_nodes import run_local

    report = run_local(BackendConfig(), iterations=2)
    assert report["metrics"]["discovered"] == 3
    assert report["metrics"]["false_positives"] == 0
    assert report["orchestration"]["engine"] == "chia"
    assert report["orchestration"]["execution"] == "local-ray"
    assert report["orchestration"]["node"] == "run_experiment"
    assert report["orchestration"]["ray_version"]
    assert report["orchestration"]["chialoops_version"]


@pytest.mark.chia
def test_chia_security_audit_block_benchmarks():
    pytest.importorskip("chia")
    from spechunter.chia_nodes import SpecHunterSecurityAuditBlock

    # Audit transient-cache
    block_v1 = SpecHunterSecurityAuditBlock(
        config=BackendConfig(),
        iterations=2,
        benchmark_id="transient-cache",
    )
    report_v1 = block_v1.execute(local=True)
    assert report_v1["metrics"]["discovered"] == 1
    assert report_v1["metrics"]["false_positives"] == 0

    # Audit secure-control
    block_sec = SpecHunterSecurityAuditBlock(
        config=BackendConfig(),
        iterations=2,
        benchmark_id="secure-control",
    )
    report_sec = block_sec.execute(local=True)
    assert report_sec["metrics"]["discovered"] == 0
    assert report_sec["metrics"]["false_positives"] == 0
