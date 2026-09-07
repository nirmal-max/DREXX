import os
from .policy import plan
from .safety import guard
from .adapter import execute_file
from .audit import write


def make_plan(device, requested="best"):
    return plan(device, requested)


def execute_plan(device, requested="best", out="evidence"):
    p = plan(device, requested)
    if p.outcome != "PLANNED":
        raise RuntimeError(p.rationale)
    guard(device, True)
    if os.environ.get("DREX_ALLOW_DESTRUCTIVE") != "1":
        raise PermissionError("destructive execution requires DREX_ALLOW_DESTRUCTIVE=1")
    result = execute_file(device.path, passes=("random",), size=device.size_bytes if device.size_bytes > 0 else None)
    record = {"plan": p.to_dict(), "status": "VERIFIED", "execution": result}
    return {"plan": p.to_dict(), "status": "VERIFIED", "execution": result, "evidence": write(out, record)}
