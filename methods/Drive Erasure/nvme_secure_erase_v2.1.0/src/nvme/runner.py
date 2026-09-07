import json
import os
import subprocess

from .adapter import build_command, build_log_command
from .audit import write
from .policy import plan
from .safety import guard


def make_plan(device, requested="best"):
    return plan(device, requested)


def _run(cmd, runner=subprocess.run):
    return runner(cmd, capture_output=True, text=True, check=False)


def _sanitize_log_ok(stdout):
    try:
        data = json.loads(stdout or "{}")
    except json.JSONDecodeError:
        return False, "invalid_sanitize_log"
    # nvme-cli JSON field names vary by version; accept only explicit success.
    status = str(data.get("sstat", data.get("sanitize_status", data.get("status", "")))).lower()
    if status in {"0x0001", "1", "success", "successful"}:
        return True, "success"
    if status in {"0x0002", "2", "in_progress", "in progress"}:
        return False, "in_progress"
    if status in {"0x0003", "3", "failed", "failure"}:
        return False, "failed"
    return False, "unknown_status"


def execute_plan(device, requested="best", out="evidence", runner=subprocess.run):
    p = plan(device, requested)
    guard(device, True)
    if p.outcome != "PLANNED":
        raise RuntimeError(p.rationale)
    if os.environ.get("DREX_ALLOW_DESTRUCTIVE") != "1":
        raise RuntimeError("destructive execution requires DREX_ALLOW_DESTRUCTIVE=1")

    action = requested if requested in ("block", "crypto", "overwrite") else p.method.rsplit("_", 1)[-1].lower()
    command = build_command(device.path, action)
    result = _run(command, runner)
    if result.returncode != 0:
        return {"plan": p.to_dict(), "status": "FAILED", "returncode": result.returncode,
                "stderr": result.stderr, "evidence": write(out, {"plan": p.to_dict(), "status": "FAILED", "returncode": result.returncode})}

    verify = _run(build_log_command(device.path), runner)
    ok, verification = _sanitize_log_ok(verify.stdout)
    status = "VERIFIED" if ok else ("INDETERMINATE" if verification in {"in_progress", "unknown_status", "invalid_sanitize_log"} else "FAILED")
    record = {"plan": p.to_dict(), "status": status, "verification": verification,
              "command": command, "returncode": result.returncode}
    return {**record, "evidence": write(out, record)}
