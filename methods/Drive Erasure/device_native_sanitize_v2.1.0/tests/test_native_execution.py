import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parents[1] / "src"))

from native.adapter import build_native_command
from native.runner import _nvme_status, _ata_status


def test_nvme_command():
    assert build_native_command("NVMe", "/dev/nvme0", "2") == [
        "nvme", "sanitize", "/dev/nvme0", "--sanact=2", "--wait"
    ]


def test_ata_block_erase_command():
    assert build_native_command("SATA", "/dev/sda", "block-erase") == [
        "hdparm", "--yes-i-know-what-i-am-doing", "--sanitize-block-erase", "/dev/sda"
    ]


def test_scsi_crypto_command():
    assert build_native_command("SAS", "/dev/sg0", "crypto-erase") == [
        "sg_sanitize", "--crypto", "--quick", "--wait", "/dev/sg0"
    ]


def test_rejects_fake_ata_backend():
    assert "ata-sanitize" not in build_native_command("SATA", "/dev/sda", "block-erase")


def test_nvme_status_parser():
    assert _nvme_status("Sanitize Status : 0x1") == "SUCCESS"
    assert _nvme_status("SSTAT : 0x2") == "IN_PROGRESS"
    assert _nvme_status("SSTAT : 0x3") == "FAILED"
    assert _nvme_status("SSTAT : 0x0") == "UNKNOWN"


def test_ata_status_parser():
    assert _ata_status("State: SD0 Sanitize Idle\nLast Sanitize Operation Completed Without Error") == "SUCCESS"
    assert _ata_status("State: SD2 Sanitize operation In Process") == "IN_PROGRESS"
    assert _ata_status("Last Sanitize Operation Failed") == "FAILED"
