import subprocess

from .policy import plan
from .safety import guard
from .audit import write
from .adapter import AdapterError, build_command, execution_allowed


def make_plan(device, requested="best"):
    return plan(device, requested)


def execute_plan(device, requested="best", out="evidence", dry_run=False):
    p = plan(device, requested)
    guard(device, True)
    if p.outcome != "PLANNED":
        raise RuntimeError(p.rationale)

    command = build_command(device, p.method)
    record = {"plan": p.to_dict(), "command": command, "status": "READY_TO_EXECUTE"}

    if dry_run:
        record["status"] = "DRY_RUN"
        return {"plan": p.to_dict(), "status": "DRY_RUN", "command": command, "evidence": write(out, record)}

    if not execution_allowed():
        raise AdapterError("Destructive execution is disabled; set DREX_ALLOW_DESTRUCTIVE=1 only in a controlled qualified environment")

    try:
        completed = subprocess.run(command, check=False, capture_output=True, text=True)
    except OSError as exc:
        record.update({"status": "FAILED", "error": str(exc)})
        write(out, record)
        raise

    if completed.returncode != 0:
        record.update({
            "status": "FAILED",
            "returncode": completed.returncode,
            "stdout": completed.stdout[-4000:],
            "stderr": completed.stderr[-4000:],
        })
        raise RuntimeError(record["stderr"] or "sanitization command failed")

    record.update({
        "status": "COMPLETED_PENDING_VALIDATION",
        "returncode": completed.returncode,
        "stdout": completed.stdout[-4000:],
        "stderr": completed.stderr[-4000:],
    })
    return {"plan": p.to_dict(), "status": record["status"], "evidence": write(out, record)}
