import sys
sys.path.insert(0, "src")
import pytest
from smart.adapter import build_command, verification_command
from smart.models import Device


def device(**caps):
    return Device("/dev/test", "NVME", capabilities=caps)


def test_nvme_command_is_real_backend():
    assert build_command(device(nvme_sanitize=True), "NVME_SANITIZE") == ["nvme", "sanitize", "/dev/test", "--sanact=0x02", "--wait"]


def test_fake_backend_is_not_used():
    with pytest.raises(ValueError):
        build_command(device(), "ATA_SECURE_ERASE")


def test_qualified_commands_are_required():
    d = Device("/dev/test", "HDD", capabilities={})
    with pytest.raises(ValueError):
        build_command(d, "VERIFIED_OVERWRITE")


def test_verification_command_nvme():
    assert verification_command(device(), "NVME_SANITIZE") == ["nvme", "sanitize-log", "/dev/test", "-o", "json"]
