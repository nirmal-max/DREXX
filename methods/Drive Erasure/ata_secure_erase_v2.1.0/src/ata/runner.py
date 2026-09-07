from __future__ import annotations

import os
import secrets
import subprocess
from pathlib import Path

from .adapter import build_commands, build_identify_command
from .audit import write
from .policy import plan
from .safety import guard


def make_plan(device, requested="best"):
    return plan(device, requested)


def _run(command: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        command,
        check=False,
        capture_output=True,
        text=True,
        timeout=24 * 60 * 60,
    )


def _verification_ok(stdout: str, stderr: str) -> bool:
    text = f"{stdout}\n{stderr}".lower()
    # hdparm -I normally reports "not enabled" after security-disable.
    return "security:" in text and "not enabled" in text


def execute_plan(device, requested="best", out="evidence", runner=_run):
    """Execute ATA Secure Erase only after an explicit destructive-use opt-in.

    The opt-in prevents accidental invocation from tests/UI code. Set
    DREX_CONFIRM_DESTRUCTIVE=ERASE on the controlled target system.
    """
    p = plan(device, requested)
    guard(device, True)
    if p.outcome != "PLANNED":
        raise RuntimeError(p.rationale)
    if os.environ.get("DREX_CONFIRM_DESTRUCTIVE") != "ERASE":
        raise RuntimeError(
            "destructive execution disabled; set DREX_CONFIRM_DESTRUCTIVE=ERASE "
            "on the controlled target system"
        )

    password = secrets.token_hex(16)
    commands = build_commands(device.path, password, p.method.endswith("ENHANCED"))
    results = []
    try:
        for command in commands:
            result = runner(command)
            results.append({
                "argv": ["<REDACTED>" if i == 2 else value for i, value in enumerate(command)],
                "returncode": result.returncode,
                "stdout": result.stdout,
                "stderr": result.stderr,
            })
            if result.returncode != 0:
                raise RuntimeError(f"hdparm command failed with exit code {result.returncode}")

        identify = runner(build_identify_command(device.path))
        if identify.returncode != 0 or not _verification_ok(identify.stdout, identify.stderr):
            raise RuntimeError("ATA post-condition verification failed: security state is not proven disabled")

        record = {
            "plan": p.to_dict(),
            "status": "VERIFIED",
            "commands": [r["argv"] for r in results],
            "verification": "hdparm -I reports security not enabled",
        }
        return {"plan": p.to_dict(), "status": "VERIFIED", "evidence": write(out, record)}
    finally:
        # Keep the secret out of Python locals as far as practical; it is never
        # returned or persisted in evidence.
        password = ""
