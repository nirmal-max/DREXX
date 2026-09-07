from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
import os
import tempfile


@dataclass(frozen=True)
class TraceRule:
    rule_id: str
    label: str
    paths: tuple[str, ...]
    platforms: tuple[str, ...] = ("all",)


def platform_name():
    if os.name == "nt":
        return "windows"
    if os.name == "posix":
        return "posix"
    return "other"


def baseline_rules():
    rules = [
        TraceRule("posix-temp", "POSIX temporary data", ("/tmp", "/var/tmp"), ("posix",)),
        TraceRule("user-cache", "User cache", (str(Path.home()/".cache"),), ("posix",)),
        TraceRule("windows-temp", "Windows temporary data",
                  ("%TEMP%", "%LOCALAPPDATA%\\Temp"), ("windows",)),
    ]
    return tuple(rules)


def expand_rule(rule: TraceRule):
    out=[]
    for raw in rule.paths:
        value=os.path.expandvars(os.path.expanduser(raw))
        out.append(Path(value))
    return out
