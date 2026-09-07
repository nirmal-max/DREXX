from __future__ import annotations

from typing import Sequence


def build_commands(device: str, password: str, enhanced: bool = False) -> list[list[str]]:
    """Build the documented hdparm ATA security sequence.

    The password is deliberately supplied by the caller so the adapter never
    emits a fake credential such as '<EPHEMERAL>'. Callers must redact it from
    audit/evidence records.
    """
    if not isinstance(device, str) or not device.startswith("/"):
        raise ValueError("device must be an absolute device path")
    if not password or any(ch.isspace() for ch in password):
        raise ValueError("password must be non-empty and contain no whitespace")

    erase = "--security-erase-enhanced" if enhanced else "--security-erase"
    return [
        ["hdparm", "--security-set-pass", password, device],
        ["hdparm", erase, password, device],
        ["hdparm", "--security-disable", password, device],
    ]


def build_identify_command(device: str) -> list[str]:
    if not isinstance(device, str) or not device.startswith("/"):
        raise ValueError("device must be an absolute device path")
    return ["hdparm", "-I", device]
