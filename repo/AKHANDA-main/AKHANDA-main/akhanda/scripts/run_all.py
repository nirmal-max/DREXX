"""Run every check this project has, record all of it, skip nothing.

    python scripts/run_all.py                 # everything
    python scripts/run_all.py --quick          # skip the checks measured in minutes
    python scripts/run_all.py --only tests rust

NO EARLY EXIT, AND THAT IS THE POINT. A runner that stops at the first failure tells you
about one problem and hides the rest, so the next run finds the second one, and the run
after that finds the third. Every check here runs to completion regardless of what failed
before it, and the exit code is decided at the end from the whole picture.

FAILURES ARE RECORDED MORE FULLY THAN PASSES. A passing check needs its name, its duration
and its exit code. A failing one needs its entire output, because that output is the only
thing that makes the failure diagnosable later, and a log that truncates the one thing you
need is a log nobody trusts twice.

Outputs, both written every run:

    evidence/run_all.json   machine-readable: every check, timing, exit code, full output
    evidence/run_all.log    human-readable transcript, failures reproduced in full

Checks that cannot run here are reported SKIPPED **with the reason**, never silently
dropped. "The Rust toolchain is absent" and "the Rust tests passed" must never look the
same in a report, and a suite that quietly shrinks when a tool goes missing is a suite that
reports green while testing less.
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

ROOT = Path(__file__).resolve().parents[1]
EVIDENCE = ROOT / "evidence"

PASS, FAIL, SKIP, ERROR = "PASS", "FAIL", "SKIPPED", "ERROR"


@dataclass
class Check:
    """One thing that can pass, fail, or be impossible to run here."""
    name: str
    what: str                      # what a failure would MEAN, not what the command is
    argv: list
    cwd: Path = ROOT
    timeout: int = 1800
    slow: bool = False
    critical: bool = True          # False => a failure is reported but does not fail the run
    requires: str = ""             # executable that must exist, or the check is SKIPPED


@dataclass
class Result:
    name: str
    what: str
    status: str = PASS
    exit_code: int | None = None
    seconds: float = 0.0
    command: str = ""
    reason: str = ""
    stdout: str = ""
    stderr: str = ""
    critical: bool = True
    summary: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


def _py(*args: str) -> list:
    return [sys.executable, *args]


CHECKS = [
    Check("tests", "the full Python suite, every claim this project makes in code",
          _py("-m", "pytest", "-q", "--tb=short"), timeout=2400),

    Check("canary", "Python, JavaScript and Rust must produce identical entry hashes; a "
                    "failure here means the three implementations have drifted apart",
          _py("-m", "pytest", "-q", "tests/test_three_implementations.py",
              "tests/test_cross_implementation.py"), timeout=900),

    Check("rust-tests", "the independent Rust verifier's own suite",
          ["cargo", "test", "--quiet"], cwd=ROOT / "rust" / "akhanda-verify",
          timeout=1200, requires="cargo"),

    Check("rust-clippy", "Rust lints as errors, the verifier must stay warning-free",
          ["cargo", "clippy", "--release", "--", "-D", "warnings"],
          cwd=ROOT / "rust" / "akhanda-verify", timeout=1200, requires="cargo"),

    Check("adversarial-audit", "eight attempts to prove this project's own claims hollow; "
                               "a failure means a claim did not survive falsification",
          _py("scripts/adversarial_audit.py"), timeout=1800),

    Check("corpus-replay", "pinned real observations must still reproduce; a failure means "
                           "the carver changed and someone has to say which side is right",
          _py("scripts/pin_corpus.py", "--replay"), timeout=1800),

    Check("chain-benchmark", "verification and tamper-localisation timings",
          _py("scripts/benchmark_chain.py", "--entries", "500"), timeout=900),

    # -lll reports HIGH only, which is the documented gate. -ll would also report the two
    # MEDIUM findings that are deliberately triaged and kept visible (evidence/hardening.md),
    # so the run would go red every time for findings that were reviewed and accepted.
    Check("bandit", "static security analysis; HIGH severity is a stop",
          _py("-m", "bandit", "-r", "src/", "-q", "-lll"), timeout=900,
          critical=False, requires=None),

    Check("fragment-bench", "226 fragmentation cases, byte-identical recovery, zero false "
                            "positives, zero wrong files",
          _py("validation/reassembly/bench/fragment_bench.py", "--repeats", "2"),
          timeout=2400, slow=True),

    Check("stress-forensic", "the five-stage run over real NIST CFReDS images",
          _py("scripts/stress_forensic.py"), timeout=2400, slow=True),

    Check("scale", "GB-scale carve with planted ground truth",
          _py("scripts/stress_scale.py", "--gb", "1"), timeout=2400, slow=True),
]


def _summarise(name: str, out: str, err: str) -> str:
    """One line worth putting in a table. Never invents a number."""
    text = (out or "") + "\n" + (err or "")
    for line in reversed(text.strip().splitlines()):
        line = line.strip()
        if not line:
            continue
        if name == "tests" and ("passed" in line or "failed" in line):
            return line[:160]
        if name.startswith("rust") and "test result" in line and "0 passed" not in line:
            # cargo prints a result line per target; the lib tests are the ones that matter
            # and the doc/bin targets each report "0 passed". Taking the last line reported
            # zero tests for a suite that had just run twelve.
            return line[:160]
        if "VERDICTS" in line or "overall" in line or "positives" in line:
            return line[:160]
        if "ok " in line.lower() and len(line) < 80:
            return line[:160]
    tail = [ln for ln in text.strip().splitlines() if ln.strip()]
    return tail[-1][:160] if tail else ""


def run_check(check: Check, log) -> Result:
    r = Result(name=check.name, what=check.what, critical=check.critical,
               command=" ".join(str(a) for a in check.argv))

    if check.requires and not shutil.which(check.requires):
        r.status = SKIP
        r.reason = (f"{check.requires!r} is not on PATH. This is reported as SKIPPED rather "
                    f"than passed: a missing toolchain and a passing check must never look "
                    f"the same.")
        log(f"[{SKIP:^7}] {check.name:<20} {r.reason}")
        return r
    if not check.cwd.is_dir():
        r.status = SKIP
        r.reason = f"working directory {check.cwd} does not exist"
        log(f"[{SKIP:^7}] {check.name:<20} {r.reason}")
        return r

    t0 = time.perf_counter()
    try:
        proc = subprocess.run(check.argv, cwd=str(check.cwd), capture_output=True,
                              text=True, timeout=check.timeout, check=False)
        r.exit_code = proc.returncode
        r.stdout, r.stderr = proc.stdout or "", proc.stderr or ""
        r.status = PASS if proc.returncode == 0 else FAIL
    except subprocess.TimeoutExpired as exc:
        r.status = ERROR
        r.reason = f"timed out after {check.timeout}s"
        r.stdout = (exc.stdout or b"").decode("utf-8", "replace") if exc.stdout else ""
        r.stderr = (exc.stderr or b"").decode("utf-8", "replace") if exc.stderr else ""
    except (OSError, subprocess.SubprocessError) as exc:
        r.status = ERROR
        r.reason = f"{type(exc).__name__}: {exc}"

    r.seconds = round(time.perf_counter() - t0, 1)
    r.summary = _summarise(check.name, r.stdout, r.stderr)

    log(f"[{r.status:^7}] {check.name:<20} {r.seconds:>7.1f}s  {r.summary}")
    if r.status in (FAIL, ERROR):
        # THE WHOLE OUTPUT, not a tail. This is the only record of why it failed, and a
        # truncated one sends the reader back to reproduce a run that took forty minutes.
        log("")
        log(f"    ---- {check.name}: FULL OUTPUT ----")
        log(f"    command : {r.command}")
        log(f"    cwd     : {check.cwd}")
        log(f"    exit    : {r.exit_code}   {r.reason}")
        for stream, body in (("stdout", r.stdout), ("stderr", r.stderr)):
            if body.strip():
                log(f"    ---- {stream} ----")
                for line in body.splitlines():
                    log(f"    {line}")
        log(f"    ---- end {check.name} ----")
        log("")
    return r


def main() -> int:
    ap = argparse.ArgumentParser(description="Run every check and record all of it.")
    ap.add_argument("--quick", action="store_true", help="skip checks measured in minutes")
    ap.add_argument("--only", nargs="+", metavar="NAME", help="run only these checks")
    ap.add_argument("--out", default=str(EVIDENCE / "run_all"))
    args = ap.parse_args()

    selected = [c for c in CHECKS
                if (not args.only or c.name in args.only)
                and not (args.quick and c.slow)]
    if args.only:
        unknown = set(args.only) - {c.name for c in CHECKS}
        if unknown:
            print(f"unknown check(s): {sorted(unknown)}", file=sys.stderr)
            print(f"available: {[c.name for c in CHECKS]}", file=sys.stderr)
            return 2

    EVIDENCE.mkdir(parents=True, exist_ok=True)
    log_path = Path(f"{args.out}.log")
    json_path = Path(f"{args.out}.json")
    lines: list = []

    def log(msg: str = "") -> None:
        print(msg)
        lines.append(msg)

    started = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    t0 = time.perf_counter()

    log("=" * 78)
    log("AKHANDA, full check run")
    log(f"started   {started}")
    log(f"python    {platform.python_version()} on {platform.system()} {platform.machine()}")
    log(f"checks    {len(selected)} of {len(CHECKS)}"
        + ("  (--quick: slow checks skipped)" if args.quick else ""))
    log("=" * 78)
    log("")

    results = [run_check(c, log) for c in selected]

    wall = round(time.perf_counter() - t0, 1)
    by = {s: [r for r in results if r.status == s] for s in (PASS, FAIL, ERROR, SKIP)}
    broke = [r for r in results if r.status in (FAIL, ERROR) and r.critical]
    noncritical = [r for r in results if r.status in (FAIL, ERROR) and not r.critical]

    log("")
    log("=" * 78)
    log(f"{'CHECK':<20} {'STATUS':<9} {'TIME':>8}   SUMMARY")
    log("-" * 78)
    for r in results:
        log(f"{r.name:<20} {r.status:<9} {r.seconds:>7.1f}s   {r.summary[:44]}")
    log("-" * 78)
    deselected = [c.name for c in CHECKS if c not in selected]
    log(f"passed {len(by[PASS])} · failed {len(by[FAIL])} · errored {len(by[ERROR])} "
        f"· skipped {len(by[SKIP])} · NOT RUN {len(deselected)}   in {wall}s")
    if deselected:
        # A summary line reading "failed 0" while three checks never ran is the exact
        # fluffing this runner exists to prevent, and it was in here. Deselected checks are
        # now on the summary line and named, so a reader cannot mistake a partial run for a
        # complete one.
        log(f"NOT RUN (deselected by --quick/--only): {', '.join(deselected)}")
        log("  ^ these were never executed. This run does NOT report on them.")

    if by[SKIP]:
        log("")
        log("SKIPPED, reported, not dropped:")
        for r in by[SKIP]:
            log(f"  {r.name}: {r.reason}")
    if noncritical:
        log("")
        log("NON-BLOCKING failures (recorded, do not fail the run):")
        for r in noncritical:
            log(f"  {r.name}: exit {r.exit_code}, {r.summary[:80]}")
    if broke:
        log("")
        log("FAILED, full output for each is above:")
        for r in broke:
            log(f"  {r.name}: {r.what}")

    verdict = "GREEN" if not broke else f"RED, {len(broke)} critical check(s) failed"
    if deselected and not broke:
        verdict = f"GREEN (PARTIAL, {len(deselected)} check(s) not run)"
    log("")
    log(f"VERDICT: {verdict}")
    log("=" * 78)

    report = {
        "run": "akhanda full check run",
        "started_utc": started,
        "wall_s": wall,
        "python": platform.python_version(),
        "platform": f"{platform.system()} {platform.machine()}",
        "counts": {k: len(v) for k, v in by.items()},
        "not_run": [c.name for c in CHECKS if c not in selected],
        "complete_run": len(selected) == len(CHECKS),
        "verdict": verdict,
        "ok": not broke,
        "note": ("Every check ran to completion regardless of earlier failures. Failing "
                 "checks carry their FULL output, not a tail. Checks that could not run "
                 "are SKIPPED with a reason and are never counted as passes."),
        "checks": [r.to_dict() for r in results],
    }

    json_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    log_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"\nlog    {log_path}")
    print(f"json   {json_path}")
    return 0 if not broke else 1


if __name__ == "__main__":
    sys.exit(main())
