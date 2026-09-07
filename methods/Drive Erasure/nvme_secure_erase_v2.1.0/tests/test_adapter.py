import sys
sys.path.insert(0, "src")

from nvme.adapter import build_command, build_log_command


def test_codes():
    assert build_command("/dev/nvme0", "block")[3] == "--sanact=0x02"
    assert build_command("/dev/nvme0", "crypto")[3] == "--sanact=0x04"
    assert build_command("/dev/nvme0", "overwrite")[3] == "--sanact=0x03"
    assert build_command("/dev/nvme0", "block")[-1] == "--wait"


def test_log_command():
    assert build_log_command("/dev/nvme0") == ["nvme", "sanitize-log", "/dev/nvme0", "-o", "json"]
