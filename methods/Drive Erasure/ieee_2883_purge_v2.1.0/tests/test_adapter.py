import sys
sys.path.insert(0, "src")
from ieee.models import Device
from ieee.adapter import build_command, build_verification_command


def dev(media):
    return Device("/dev/test", media, capabilities={"purge_qualified": True})


def test_nvme_crypto_command():
    assert build_command(dev("NVME"), "DEVICE_NATIVE_SANITIZE") == [
        "nvme", "sanitize", "/dev/test", "--sanact=4", "--wait"
    ]


def test_ata_crypto_command():
    assert build_command(dev("SATA"), "DEVICE_NATIVE_SANITIZE") == [
        "hdparm", "--sanitize-crypto-scramble", "/dev/test"
    ]


def test_scsi_block_command():
    d = Device("/dev/test", "SCSI", capabilities={"purge_qualified": True, "purge_action": "block"})
    assert build_command(d, "DEVICE_NATIVE_SANITIZE") == ["sg_sanitize", "--block", "/dev/test"]


def test_nvme_verification_command():
    assert build_verification_command(dev("NVME"), "DEVICE_NATIVE_SANITIZE") == [
        "nvme", "sanitize-log", "/dev/test"
    ]


def test_fake_backend_is_gone():
    d = dev("SATA")
    assert "native-sanitize" not in build_command(d, "DEVICE_NATIVE_SANITIZE")
