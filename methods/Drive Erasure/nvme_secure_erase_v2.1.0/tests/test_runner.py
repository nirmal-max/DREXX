import sys
sys.path.insert(0, "src")

from nvme.models import Device
from nvme.runner import _sanitize_log_ok, execute_plan


def device():
    return Device("/dev/nvme0", "NVME", size_bytes=1024,
                  capabilities={"nvme_sanitize": True, "block_erase": True})


def test_status_parser():
    assert _sanitize_log_ok('{"sstat":"0x0001"}') == (True, "success")
    assert _sanitize_log_ok('{"sstat":"0x0002"}') == (False, "in_progress")
    assert _sanitize_log_ok('{"sstat":"0x0003"}') == (False, "failed")
    assert _sanitize_log_ok('not-json') == (False, "invalid_sanitize_log")


def test_execution_and_verification(monkeypatch, tmp_path):
    calls = []

    class Result:
        def __init__(self, rc=0, stdout="", stderr=""):
            self.returncode, self.stdout, self.stderr = rc, stdout, stderr

    def fake_run(cmd, **kwargs):
        calls.append(cmd)
        if cmd[1] == "sanitize":
            return Result()
        return Result(stdout='{"sstat":"0x0001"}')

    monkeypatch.setenv("DREX_ALLOW_DESTRUCTIVE", "1")
    result = execute_plan(device(), "block", str(tmp_path), runner=fake_run)
    assert result["status"] == "VERIFIED"
    assert calls[0][:3] == ["nvme", "sanitize", "/dev/nvme0"]
    assert calls[1][:2] == ["nvme", "sanitize-log"]


def test_execution_requires_explicit_gate(monkeypatch, tmp_path):
    monkeypatch.delenv("DREX_ALLOW_DESTRUCTIVE", raising=False)
    try:
        execute_plan(device(), "block", str(tmp_path), runner=lambda *a, **k: None)
    except RuntimeError as exc:
        assert "DREX_ALLOW_DESTRUCTIVE=1" in str(exc)
    else:
        raise AssertionError("destructive execution was not gated")
