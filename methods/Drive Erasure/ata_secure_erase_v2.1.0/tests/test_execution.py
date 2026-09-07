import os
import sys
from types import SimpleNamespace

sys.path.insert(0, "src")

from ata.models import Device
from ata.runner import execute_plan


def test_execute_plan_runs_and_verifies_without_exposing_password(tmp_path, monkeypatch):
    calls = []

    def fake_runner(command):
        calls.append(command)
        if command[1] == "-I":
            return SimpleNamespace(returncode=0, stdout="Security:\n  not enabled", stderr="")
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    monkeypatch.setenv("DREX_CONFIRM_DESTRUCTIVE", "ERASE")
    device = Device("/dev/test", "HDD", capabilities={"ata_secure_erase": True})
    result = execute_plan(device, out=str(tmp_path), runner=fake_runner)

    assert result["status"] == "VERIFIED"
    assert [command[1] for command in calls] == [
        "--security-set-pass",
        "--security-erase",
        "--security-disable",
        "-I",
    ]
    assert calls[0][2]
    assert calls[0][2] != "<EPHEMERAL>"


def test_execute_plan_requires_explicit_destructive_opt_in():
    device = Device("/dev/test", "HDD", capabilities={"ata_secure_erase": True})
    os.environ.pop("DREX_CONFIRM_DESTRUCTIVE", None)
    try:
        execute_plan(device, runner=lambda command: None)
    except RuntimeError as exc:
        assert "destructive execution disabled" in str(exc)
    else:
        raise AssertionError("destructive execution was not blocked")
