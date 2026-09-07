import sys
from pathlib import Path
sys.path.insert(0, "src")
from overwrite.adapter import execute_file
from overwrite.models import Device
from overwrite.policy import plan
from overwrite.runner import execute_plan


def test_policy_uses_one_pass_for_hdd():
    p = plan(Device("x", "HDD", size_bytes=16))
    assert p.method == "HOST_OVERWRITE"
    assert p.commands == ("random",)


def test_policy_blocks_flash_by_default():
    p = plan(Device("x", "SSD", size_bytes=16))
    assert p.outcome == "BLOCKED"


def test_engine_overwrites_and_verifies(tmp_path):
    target = tmp_path / "target.bin"
    target.write_bytes(b"secret-data" * 100)
    original = target.read_bytes()
    result = execute_file(str(target), passes=("zero",))
    assert target.read_bytes() != original
    assert result[0]["bytes"] == len(original)
    assert result[0]["write_sha256"] == result[0]["readback_sha256"]


def test_runner_requires_explicit_destructive_gate(tmp_path, monkeypatch):
    target = tmp_path / "target.bin"
    target.write_bytes(b"secret")
    d = Device(str(target), "HDD", size_bytes=target.stat().st_size)
    monkeypatch.delenv("DREX_ALLOW_DESTRUCTIVE", raising=False)
    try:
        execute_plan(d, out=str(tmp_path / "evidence"))
        assert False
    except PermissionError:
        assert target.read_bytes() == b"secret"
