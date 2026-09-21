import importlib.util
import json
import sys
from pathlib import Path
from types import SimpleNamespace

ROOT = Path(__file__).parents[1]
SCRIPT = ROOT / "tools/boom/gcp_runner.py"
SPEC = importlib.util.spec_from_file_location("gcp_runner", SCRIPT)
assert SPEC and SPEC.loader
TRANSPORT = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(TRANSPORT)


def test_transport_uploads_executes_and_always_cleans(tmp_path, monkeypatch, capsys):
    config = tmp_path / "gcloud"
    config.mkdir()
    ssh_key = tmp_path / "google_compute_engine"
    ssh_key.write_text("test key")
    request = tmp_path / "request.json"
    request.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "program": ["enter_user"],
                "program_sha256": "digest",
                "secret": 0,
                "variant": "none",
                "target_revision": "revision",
            }
        )
    )
    calls = []

    def bounded(command, env, timeout):
        calls.append((command, env, timeout))
        output = b'{"target":"boom"}\n' if "trusted_runner.py" in " ".join(command) else b""
        return SimpleNamespace(returncode=0, stdout=output, stderr=b"")

    monkeypatch.setattr(TRANSPORT, "bounded", bounded)
    monkeypatch.setattr(TRANSPORT.shutil, "which", lambda _: "/usr/bin/gcloud")
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "gcp_runner.py",
            "--project",
            "spechunter",
            "--zone",
            "us-central1-a",
            "--instance",
            "boom-worker",
            "--gcloud-config",
            str(config),
            "--ssh-key-file",
            str(ssh_key),
            str(request),
        ],
    )
    assert TRANSPORT.main() == 0
    assert json.loads(capsys.readouterr().out) == {"target": "boom"}
    assert [call[0][1:3] for call in calls] == [
        ["compute", "scp"],
        ["compute", "ssh"],
        ["compute", "ssh"],
    ]
    remote = calls[0][0][4].split(":", 1)[1]
    assert remote.startswith("/tmp/spechunter-request-")
    assert remote in calls[1][0][-1]
    assert calls[2][0][-1] == f"rm -f -- {remote}"
    assert all(call[1]["CLOUDSDK_CONFIG"] == str(config) for call in calls)
    assert all(str(ssh_key) in call[0] for call in calls)
