import sys
sys.path.insert(0, "src")

import pytest

from ata.adapter import build_commands, build_identify_command


def test_standard_sequence_uses_real_password():
    commands = build_commands("/dev/sda", "temporary-secret", False)
    assert commands == [
        ["hdparm", "--security-set-pass", "temporary-secret", "/dev/sda"],
        ["hdparm", "--security-erase", "temporary-secret", "/dev/sda"],
        ["hdparm", "--security-disable", "temporary-secret", "/dev/sda"],
    ]
    assert "<EPHEMERAL>" not in str(commands)


def test_enhanced():
    assert "--security-erase-enhanced" in build_commands("/dev/sda", "secret", True)[1]


def test_identify_command():
    assert build_identify_command("/dev/sda") == ["hdparm", "-I", "/dev/sda"]


def test_rejects_non_absolute_device():
    with pytest.raises(ValueError):
        build_commands("sda", "secret")


def test_rejects_empty_password():
    with pytest.raises(ValueError):
        build_commands("/dev/sda", "")
