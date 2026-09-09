"""Resumable task ledger, progress that survives the session ending.

    python scripts/tasks.py                # show state, run whatever is now runnable
    python scripts/tasks.py --status       # show state only, run nothing
    python scripts/tasks.py --run g1b      # run one task by id
    python scripts/tasks.py --log          # tail the append-only history

THE PROBLEM THIS SOLVES. Work spread across sessions loses its place. Someone runs half the
checklist, the session ends, and the next person cannot tell what was done from what was
merely attempted, so the safe move is to redo everything, and the honest move is to admit
nothing is known. Both are expensive.

State lives in `evidence/tasks/state.json` and history in `evidence/tasks/history.log`,
which is **append-only**. A state file can be rewritten; a history cannot, so the two
together answer both "where are we" and "how did we get here".

THREE RULES THAT KEEP IT HONEST, each the opposite of a way this could quietly lie:

  1. DONE REQUIRES AN ARTEFACT. A task is complete only when the file it was supposed to
     produce exists. Nothing is marked done because it ran, or because it exited zero, or
     because someone said so. If the artefact is missing the task is not done, whatever
     happened.

  2. BLOCKED NAMES THE MISSING THING, and is re-checked every run. "needs an elevated
     shell" and "failed" are different states with different remedies, and a task that
     becomes runnable later must start running by itself rather than waiting for someone
     to notice.

  3. NOTHING IS EVER SILENTLY SKIPPED. A task nobody can run appears in every report with
     the reason, forever, until it is done or deliberately dropped.
"""
from __future__ import annotations

import argparse
import json
import os
import platform
import shutil
import subprocess
import sys
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Callable, Optional

ROOT = Path(__file__).resolve().parents[1]
STATE_DIR = ROOT / "evidence" / "tasks"
STATE = STATE_DIR / "state.json"
HISTORY = STATE_DIR / "history.log"

PENDING, RUNNING, DONE, BLOCKED, FAILED = "PENDING", "RUNNING", "DONE", "BLOCKED", "FAILED"


# ─────────────────────────────────────────────────────── prerequisites

def _elevated() -> bool:
    if os.name != "nt":
        return os.geteuid() == 0 if hasattr(os, "geteuid") else False
    try:
        import ctypes
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:  # noqa: BLE001
        return False


def _internet() -> bool:
    import socket
    try:
        socket.setdefaulttimeout(3)
        socket.socket(socket.AF_INET, socket.SOCK_STREAM).connect(("8.8.8.8", 53))
        return True
    except OSError:
        return False


def _tool(name: str) -> Callable[[], bool]:
    return lambda: shutil.which(name) is not None


def _phone_attached() -> bool:
    """A WPD/MTP device is present. Cheap, read-only, no admin."""
    if os.name != "nt":
        return False
    try:
        out = subprocess.run(
            ["powershell", "-NoProfile", "-Command",
             "if (Get-PnpDevice -PresentOnly -Class WPD -EA SilentlyContinue) {'yes'} else {'no'}"],
            capture_output=True, text=True, timeout=60, check=False)
        return "yes" in out.stdout
    except (OSError, subprocess.SubprocessError):
        return False


PREREQS = {
    "elevated": (_elevated, "an ELEVATED PowerShell (Run as Administrator)"),
    "internet": (_internet, "an internet connection"),
    "adb": (_tool("adb"), "the Android platform-tools (adb) on PATH"),
    "second_laptop": (lambda: False, "the second laptop reachable over the link"),
    "usb_ethernet": (lambda: False, "a USB-to-Ethernet adapter and cable"),
    "usb_stick": (lambda: False, "a sacrificial USB stick"),
    "human": (lambda: False, "a person (CAPTCHA, a login, a physical action)"),
    "phone": (_phone_attached, "the phone attached over USB"),
}


@dataclass
class Task:
    id: str
    what: str                       # what it establishes, not what it runs
    artefact: str                   # the file that proves it happened
    argv: Optional[list] = None     # None => not automatable, a human does it
    needs: list = field(default_factory=list)
    manual_steps: str = ""
    minutes: int = 0
    timeout: int = 3600


TASKS = [
    Task("phone-probe",
         "read-only probe of the attached phone: device class, USB descriptors, and "
         "whether the OS exposes a block device at all",
         "validation/device_note10/evidence/device_probe-*.json",
         ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File",
          "validation/device_note10/probe_device.ps1"],
         needs=["phone"], minutes=2),

    Task("phone-identity",
         "device identity over MTP, manufacturer, model, serial, capacity. The BSA "
         "§63(4) Part A particulars, read without touching a single file of the owner's",
         "validation/device_note10/evidence/mtp_identity-*.json",
         ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File",
          "validation/device_note10/mtp_identity.ps1"],
         needs=["phone"], minutes=3),

    Task("full-checks",
         "every automated check: 620 tests, three-implementation canary, adversarial "
         "audit, corpus replay, benchmarks, fragment bench, CFReDS stress, GB-scale carve",
         "evidence/run_all.json",
         [sys.executable, "scripts/run_all.py"], minutes=7, timeout=5400),

    Task("g1b-refusal",
         "the fail-closed half of the handshake: with the witness down, the operation is "
         "blocked, a REFUSED entry is written, and the chain still verifies",
         "evidence/g1_handshake.json",
         [sys.executable, "scripts/prep/g1_handshake.py",
          "--witness", "http://127.0.0.1:9", "--phase", "b"], minutes=1),

    Task("corpus-pin",
         "real observations pinned as permanent regression cases",
         "corpus/carve/", [sys.executable, "scripts/pin_corpus.py", "--pin-cfreds"],
         minutes=2),

    Task("cargo-audit",
         "the Rust verifier's dependencies checked against the RustSec advisory database",
         "evidence/cargo_audit.txt", None,
         needs=["internet"], minutes=15,
         manual_steps="cargo install cargo-audit; cd rust/akhanda-verify; "
                      "cargo audit > ../../evidence/cargo_audit.txt"),

    Task("fs-matrix",
         "detect_filesystem against real NTFS, FAT32, exFAT and ReFS volumes, every one "
         "backed by a .vhdx FILE, so no physical disk is touched",
         "evidence/fs_matrix.json",
         ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File",
          "scripts/prep/fs_matrix.ps1"],
         needs=["elevated"], minutes=20),

    Task("vhd-erase",
         "a real block-device erasure with no hardware: a VHD attaches as a genuine "
         "\\\\.\\PhysicalDriveN and is deleted afterwards",
         "evidence/vhd_erase.json",
         ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File",
          "scripts/prep/vhd_erase.ps1"],
         needs=["elevated"], minutes=20),

    Task("lb03",
         "LB-03: the witness key is unreadable from the operator account. Access Denied "
         "is the PASS, and the captured failure is the evidence",
         "evidence/lb03_witness_boundary.json", None,
         needs=["elevated", "human"], minutes=45,
         manual_steps="Elevated: scripts\\prep\\lb03_setup.ps1. Log in as `witness`, boot "
                      "the node once, then icacls the key directory. Back as operator: "
                      "scripts\\prep\\lb03_verify.ps1"),

    Task("g24-link",
         "the operator-to-witness link on the transport that will be used on the day",
         "evidence/g24_link_check.json", None,
         needs=["usb_ethernet", "second_laptop"], minutes=30,
         manual_steps="Static IPs 192.168.50.1/.2, allow TCP 8000 on the Private profile, "
                      "then: python scripts/prep/g24_link_check.py --witness "
                      "http://192.168.50.1:8000 --transport usb-ethernet-direct"),

    Task("g1a-handshake",
         "one dual-signed entry produced on real hardware, screen recorded",
         "evidence/g1_handshake.json", None,
         needs=["second_laptop", "usb_ethernet"], minutes=60,
         manual_steps="Witness machine: python src/witness/node.py. Operator: python "
                      "scripts/prep/g1_handshake.py --witness http://192.168.50.1:8000 "
                      "--phase a. RECORD THE SCREEN."),

    Task("g2b-usb",
         "one real USB stick wiped end to end, imaged before and after, canary grepped",
         "evidence/g2b_after.sha256", None,
         needs=["usb_stick", "human"], minutes=90,
         manual_steps="Follow scripts/prep/g2b_usb_wipe.md. Check BOTH easy-to-skip cases: "
                      "asking for Purge on flash must record Clear, and a failed read-back "
                      "must not record VERIFIED."),

    Task("patent-search",
         "the InPASS search, the last thing that could still disprove the main claim. "
         "Until it is done, 'no patent exists' must not be said",
         "research/round2/inpass_search.md", None,
         needs=["internet", "human"], minutes=30,
         manual_steps="iprsearch.ipindia.gov.in/PublicSearch/, CAPTCHA-gated, no API. "
                      "Terms: chain of custody, data sanitization, digital evidence, "
                      "forensic certificate. Retrieve the CUSAT patent number while there."),

    Task("anchor",
         "one real OpenTimestamps receipt, kept as evidence",
         "evidence/anchor.ots", None,
         needs=["internet"], minutes=10,
         manual_steps="pip install opentimestamps-client, then: python -m cli anchor"),

    Task("user-manuals",
         "user manuals, a named deliverable of the problem statement, currently absent",
         "docs/USER_MANUAL.md", None,
         needs=["human"], minutes=120,
         manual_steps="Operator guide for each of the three PS modules, plus how to read a "
                      "certificate. Delegate to the documentation owner."),
]


# ─────────────────────────────────────────────────────── state

def _load() -> dict:
    if STATE.is_file():
        try:
            return json.loads(STATE.read_text(encoding="utf-8"))
        except ValueError:
            # A corrupt state file must not erase history or block a run. It is moved
            # aside, named, and the run continues from what the artefacts prove.
            STATE.rename(STATE.with_suffix(f".corrupt-{int(time.time())}.json"))
    return {}


def _save(state: dict) -> None:
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    tmp = STATE.with_suffix(".tmp")
    tmp.write_text(json.dumps(state, indent=2, sort_keys=True), encoding="utf-8")
    tmp.replace(STATE)


def _history(msg: str) -> None:
    """Append-only. Never rewritten, never truncated, never rotated in place."""
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    stamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    with open(HISTORY, "a", encoding="utf-8") as fh:
        fh.write(f"{stamp}  {msg}\n")


def artefact_exists(task: Task) -> bool:
    """RULE 1. Done means the artefact is there, not that something ran.

    A trailing "/" means a directory that must be non-empty; a "*" is a glob, because
    several tasks write timestamped files rather than one fixed name.
    """
    pattern = task.artefact
    if pattern.endswith("/"):
        d = ROOT / pattern.rstrip("/")
        return d.is_dir() and any(d.iterdir())
    if "*" in pattern:
        parent = ROOT / Path(pattern).parent
        return parent.is_dir() and any(parent.glob(Path(pattern).name))
    return (ROOT / pattern).exists()


def blockers(task: Task) -> list:
    """RULE 2. Re-checked every run, so a task unblocks itself."""
    out = []
    for need in task.needs:
        check, description = PREREQS.get(need, (lambda: False, need))
        if not check():
            out.append(description)
    return out


def run_task(task: Task, state: dict) -> str:
    if artefact_exists(task):
        state[task.id] = {"status": DONE, "artefact": task.artefact,
                          "at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}
        return DONE

    missing = blockers(task)
    if missing or task.argv is None:
        reason = ("; ".join(missing) if missing
                  else "not automatable, a person has to do this")
        state[task.id] = {"status": BLOCKED, "needs": reason, "minutes": task.minutes,
                          "manual_steps": task.manual_steps}
        return BLOCKED

    _history(f"RUN    {task.id}  {' '.join(str(a) for a in task.argv)}")
    t0 = time.perf_counter()
    try:
        proc = subprocess.run(task.argv, cwd=str(ROOT), capture_output=True, text=True,
                              timeout=task.timeout, check=False)
        code, tail = proc.returncode, (proc.stdout or "")[-2000:]
    except subprocess.TimeoutExpired:
        code, tail = None, f"timed out after {task.timeout}s"
    except (OSError, subprocess.SubprocessError) as exc:
        code, tail = None, f"{type(exc).__name__}: {exc}"
    secs = round(time.perf_counter() - t0, 1)

    # RULE 1 again, and this is the important application of it: a zero exit code does not
    # make a task done. The artefact does.
    produced = artefact_exists(task)
    status = DONE if produced else FAILED
    state[task.id] = {"status": status, "exit_code": code, "seconds": secs,
                      "artefact": task.artefact, "produced": produced,
                      "at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                      "tail": tail[-600:] if status == FAILED else ""}
    _history(f"{status:<6} {task.id}  exit={code} {secs}s artefact={'yes' if produced else 'NO'}")
    return status


def main() -> int:
    ap = argparse.ArgumentParser(description="Resumable task ledger.")
    ap.add_argument("--status", action="store_true", help="show state, run nothing")
    ap.add_argument("--run", metavar="ID", help="run one task by id")
    ap.add_argument("--log", action="store_true", help="print the append-only history")
    args = ap.parse_args()

    if args.log:
        print(HISTORY.read_text(encoding="utf-8") if HISTORY.is_file() else "(no history yet)")
        return 0

    state = _load()
    STATE_DIR.mkdir(parents=True, exist_ok=True)

    print(f"AKHANDA task ledger    {time.strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"host {platform.node()} · elevated={_elevated()} · internet={_internet()}")
    print("=" * 78)

    selected = [t for t in TASKS if not args.run or t.id == args.run]
    if args.run and not selected:
        print(f"unknown task {args.run!r}; known: {[t.id for t in TASKS]}", file=sys.stderr)
        return 2

    if not args.status:
        _history(f"---- ledger run: {len(selected)} task(s) considered ----")

    for task in selected:
        if args.status:
            status = (DONE if artefact_exists(task)
                      else (BLOCKED if (blockers(task) or task.argv is None) else PENDING))
        else:
            status = run_task(task, state)
        mark = {DONE: "done", BLOCKED: "blocked", FAILED: "FAILED",
                PENDING: "ready", RUNNING: "..."}[status]
        print(f"[{mark:^8}] {task.id:<16} {task.what[:60]}")
        if status == BLOCKED:
            missing = blockers(task) or ["not automatable, a person has to do this"]
            print(f"           needs: {'; '.join(missing)}  (~{task.minutes} min)")
        elif status == FAILED:
            print(f"           artefact NOT produced: {task.artefact}")

    if not args.status:
        _save(state)

    done = [t for t in selected if artefact_exists(t)]
    blocked = [t for t in selected if not artefact_exists(t)
               and (blockers(t) or t.argv is None)]
    failed = [t.id for t in selected
              if state.get(t.id, {}).get("status") == FAILED]

    print("=" * 78)
    print(f"done {len(done)} · blocked {len(blocked)} · failed {len(failed)} "
          f"of {len(selected)}")
    if blocked:
        mins = sum(t.minutes for t in blocked)
        print(f"\nBLOCKED, {mins} minutes of work waiting on something:")
        for t in blocked:
            missing = blockers(t) or ["a person"]
            print(f"  {t.id:<16} ~{t.minutes:>3} min   needs {'; '.join(missing)}")
            if t.manual_steps:
                print(f"                   {t.manual_steps[:150]}")
    if failed:
        print(f"\nFAILED: {failed} , see evidence/tasks/history.log")

    print(f"\nstate   {STATE}")
    print(f"history {HISTORY}  (append-only)")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
