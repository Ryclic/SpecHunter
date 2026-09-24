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
