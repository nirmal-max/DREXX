from __future__ import annotations

import re
import shutil
import subprocess

from .adapter import build_native_command
from .audit import write
from .policy import plan
from .safety import guard


def make_plan(device, requested="best"):
    return plan(device, requested)


def _sanitize_status_command(device):
    media = device.media_type.upper()
    if media == "NVME":
        # sanitize-log is retained as the broadly supported nvme-cli alias.
        return ["nvme", "sanitize-log", device.path]
    if media in ("SAS", "SCSI"):
        return ["sg_requests", "--num=1", "--progress", device.path]
    if media in ("SATA", "HDD", "SSD"):
        return ["hdparm", "--sanitize-status", device.path]
    raise ValueError("unsupported media")


def _nvme_status(stdout: str) -> str:
    """Return SUCCESS, IN_PROGRESS, FAILED, or UNKNOWN from sanitize-log."""
    text = stdout.lower()
    match = re.search(r"(?:sstat|sanitize\s+status)[^0-9a-f]*(0x[0-9a-f]+)", text)
    if not match:
        return "UNKNOWN"
    code = int(match.group(1), 16) & 0x7
    return {1: "SUCCESS", 2: "IN_PROGRESS", 3: "FAILED"}.get(code, "UNKNOWN")


def _ata_status(stdout: str) -> str:
    text = stdout.lower()
    if "completed without error" in text or "sanitize idle" in text and "last sanitize operation" in text:
        return "SUCCESS"
    if "in process" in text or "in progress" in text:
        return "IN_PROGRESS"
    if "failed" in text or "error" in text:
        return "FAILED"
    return "UNKNOWN"


def execute_plan(device, requested="best", out="evidence", *, arm=False, runner=None):
    if not arm:
        raise PermissionError("destructive native sanitize requires arm=True")

    p = plan(device, requested)
    guard(device, True)
    if p.outcome != "PLANNED":
        raise RuntimeError(p.rationale)

    command = build_native_command(device.media_type, device.path, _action_for_plan(p.method))
    run = runner or _run_command
    result = run(command)
    base = {"plan": p.to_dict(), "command": command, "returncode": result.returncode}

    if result.returncode != 0:
        base.update(status="FAILED", stderr=result.stderr[-4000:])
        return {"plan": p.to_dict(), "status": "FAILED", "evidence": write(out, base)}

    verify_command = _sanitize_status_command(device)
    verification = run(verify_command)
    base["verification_command"] = verify_command
    base["verification_returncode"] = verification.returncode
    base["verification_stdout"] = verification.stdout[-4000:]

    if verification.returncode != 0:
        base.update(status="INDETERMINATE", verification_stderr=verification.stderr[-4000:])
        return {"plan": p.to_dict(), "status": "INDETERMINATE", "evidence": write(out, base)}

    media = device.media_type.upper()
    state = (_nvme_status(verification.stdout) if media == "NVME" else
             _ata_status(verification.stdout) if media in ("SATA", "HDD", "SSD") else
             "SUCCESS" if "progress" not in verification.stdout.lower() else "IN_PROGRESS")

    if state == "SUCCESS":
        base["status"] = "VERIFIED"
        return {"plan": p.to_dict(), "status": "VERIFIED", "evidence": write(out, base)}

    base["status"] = "INDETERMINATE" if state == "IN_PROGRESS" else "FAILED" if state == "FAILED" else "INDETERMINATE"
    return {"plan": p.to_dict(), "status": base["status"], "evidence": write(out, base)}


def _action_for_plan(method):
    return {
        "NVME_SANITIZE": "2",
        "ATA_SANITIZE": "block-erase",
        "SCSI_SANITIZE": "block-erase",
    }.get(method, "")


def _run_command(command):
    if shutil.which(command[0]) is None:
        raise RuntimeError(f"required utility not installed: {command[0]}")
    return subprocess.run(command, check=False, capture_output=True, text=True, timeout=86400)
