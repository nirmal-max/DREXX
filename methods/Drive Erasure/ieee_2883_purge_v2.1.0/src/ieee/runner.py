from __future__ import annotations

import subprocess
from .adapter import build_command, build_verification_command
from .policy import plan
from .safety import guard
from .audit import write


def make_plan(device, requested="best"):
    return plan(device, requested)


def _run(command):
    return subprocess.run(command, capture_output=True, text=True, check=False)


def _verification_ok(device, method, stdout):
    text = stdout.lower()
    if device.media_type.upper() == "NVME" and method == "DEVICE_NATIVE_SANITIZE":
        # nvme sanitize-log reports status in the log. Refuse success if
        # firmware reports an explicit failure/in-progress state.
        if "failed" in text or "in progress" in text:
            return False
    if device.media_type.upper() in ("SATA", "ATA", "HDD", "SSD"):
        if "failed" in text or "in progress" in text:
            return False
    return True


def execute_plan(device, requested="best", out="evidence"):
    p = plan(device, requested)
    guard(device, True)
    if p.outcome != "PLANNED":
        raise RuntimeError(p.rationale)

    command = build_command(device, p.method)
    result = _run(command)
    record = {
        "plan": p.to_dict(),
        "command": command,
        "returncode": result.returncode,
        "stdout": result.stdout,
        "stderr": result.stderr,
        "status": "FAILED" if result.returncode else "EXECUTED",
    }
    if result.returncode != 0:
        record["status"] = "FAILED"
        return {"plan": p.to_dict(), "status": "FAILED", "evidence": write(out, record)}

    verify_command = build_verification_command(device, p.method)
    verify = _run(verify_command)
    record.update({
        "verification_command": verify_command,
        "verification_returncode": verify.returncode,
        "verification_stdout": verify.stdout,
        "verification_stderr": verify.stderr,
    })
    verified = verify.returncode == 0 and _verification_ok(device, p.method, verify.stdout)
    record["status"] = "VERIFIED" if verified else "INDETERMINATE"
    status = "VERIFIED" if verified else "INDETERMINATE"
    return {"plan": p.to_dict(), "status": status, "evidence": write(out, record)}
