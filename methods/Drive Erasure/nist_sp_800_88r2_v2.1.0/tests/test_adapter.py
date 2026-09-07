import sys
sys.path.insert(0, "src")

import pytest
from nist.adapter import AdapterError, build_command
from nist.models import Device


def test_unqualified_device_is_blocked_from_command_build():
    d = Device("/dev/test", "NVME", capabilities={"native_sanitize": True})
    with pytest.raises(AdapterError):
        build_command(d, "DEVICE_NATIVE_SANITIZE")


def test_nvme_native_command():
    d = Device("/dev/nvme0", "NVME", capabilities={"nist_qualified": True, "native_sanitize": True})
    assert build_command(d, "DEVICE_NATIVE_SANITIZE") == ["nvme", "sanitize", "/dev/nvme0", "-a", "2"]


def test_sata_native_command():
    d = Device("/dev/sda", "SATA", capabilities={"nist_qualified": True, "native_sanitize": True})
    assert build_command(d, "DEVICE_NATIVE_SANITIZE") == ["hdparm", "--sanitize-block-erase", "/dev/sda"]


def test_crypto_erase_requires_explicit_command():
    d = Device("/dev/x", "SSD", capabilities={"nist_qualified": True, "crypto_erase": True})
    with pytest.raises(AdapterError):
        build_command(d, "CRYPTOGRAPHIC_ERASE")
