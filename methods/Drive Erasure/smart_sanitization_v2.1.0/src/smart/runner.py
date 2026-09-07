from __future__ import annotations

import os
import subprocess
from .adapter import build_command, verification_command
from .policy import plan
from .safety import guard
from .audit import write


def make_plan(device, requested="best"):
    return plan(device, requested)


def _run(command):
    return subprocess.run(command, check=False, capture_output=True, text=True, timeout=86400)


def execute_plan(device, requested="best", out="evidence"):
    p = plan(device, requested)
    if p.outcome != "PLANNED":
        raise RuntimeError(p.rationale)
    guard(device, True)
    if os.environ.get("DREX_ALLOW_DESTRUCTIVE") != "1":
        raise PermissionError("destructive execution requires DREX_ALLOW_DESTRUCTIVE=1")

    command = build_command(device, p.method)
    result = _run(command)
    record = {
        "plan": p.to_dict(),
        "status": "EXECUTED" if result.returncode == 0 else "FAILED",
        "returncode": result.returncode,
        "stdout": result.stdout[-4096:],
        "stderr": result.stderr[-4096:],
    }
    if result.returncode != 0:
        record["verification"] = "NOT_RUN"
        return {**record, "evidence": write(out, record)}

    verify = verification_command(device, p.method)
    v = _run(verify)
    verified = v.returncode == 0
    record.update({
        "status": "VERIFIED" if verified else "INDETERMINATE",
        "verification_returncode": v.returncode,
        "verification_stdout": v.stdout[-4096:],
        "verification_stderr": v.stderr[-4096:],
        "verification": "PASS" if verified else "FAIL",
    })
    return {**record, "evidence": write(out, record)}
