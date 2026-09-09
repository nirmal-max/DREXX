"""Self-accumulating regression corpus, every real operation becomes a permanent test.

THE HONEST VERSION OF "THE TOOL IMPROVES WITH EACH TASK". The tool does not change its own
code; that would be inadmissible, because a process that rewrites itself is a process the
certificate cannot describe (BSA 2023 s.63(4)). What it accumulates is EVIDENCE ABOUT
ITSELF: each real run is pinned as a case the tool must keep reproducing forever.

The asymmetry this fixes is real. Test fixtures are chosen by the author, so they encode
what the author already thought of. Real drives are not chosen by anyone, a stick with a
truncated JPEG at offset 0x4A2000, a chain written on a machine with a different locale,
an erase that hit three bad sectors. Those are the cases that find bugs, and today they
are seen once and thrown away. Every one that is not pinned is a regression waiting to
happen quietly.

    record(kind, inputs, digest, meta) -> Path      # pin one real observation
    replay(entry, recompute)           -> dict      # does it still reproduce?
    replay_all(recompute_for)          -> report    # the CI gate
    stats()                            -> dict

WHAT A PINNED CASE IS. A digest plus enough context to recompute it, never the evidence
itself. The corpus must be committable to a public repository, so it holds no drive
contents, no carved files, and no case identifiers. A corpus that cannot be shared cannot
be a regression suite, and a corpus holding evidence should never be shared.

WHAT PINNING DOES NOT MEAN. A pinned digest is what the tool DID, not what is CORRECT. If
a run was wrong, pinning it pins the bug, so a change in a digest is a question ("which
of these two is right?"), never automatically a failure of the new code. `replay_all`
reports drift and refuses to guess which side of it is the truth.
"""
from __future__ import annotations

import json
import os
import platform
import sys
import time
from pathlib import Path
from typing import Callable, Optional

from attestation.toolref import tool_ref

CORPUS_VERSION = "1"

# Kinds of observation worth pinning. Closed, like every other vocabulary here: an
# open-ended `kind` produces a corpus nobody can query and a replay nobody can route.
KINDS = ("carve", "erase", "chain", "case")


def corpus_dir(base: Optional[Path] = None) -> Path:
    """Where pinned cases live. Under the repo, not under AKHANDA_HOME.

    Deliberate: the corpus is source, not state. It belongs in version control beside the
    tests it effectively is, and a corpus living in a per-machine home directory would be
    a regression suite that only one machine ever runs.
    """
    if base is not None:
        return Path(base)
    env = os.environ.get("AKHANDA_CORPUS")
    if env:
        return Path(env)
    return Path(__file__).resolve().parents[2] / "corpus"


def _environment() -> dict:
    """Enough about the machine to explain a divergence, and nothing that identifies it.

    No hostname, no username, no paths. A corpus entry is committed to a public repo; a
    field that leaks the examiner's machine would make the corpus unshareable, and an
    unshareable regression suite is not one.
    """
    return {
        "python": platform.python_version(),
        "system": platform.system(),
        "machine": platform.machine(),
        "byteorder": sys.byteorder,
    }


def record(kind: str, *, inputs: dict, digest: str, meta: Optional[dict] = None,
           base: Optional[Path] = None) -> Path:
    """Pin one real observation as a permanent regression case.

    `inputs` must be everything needed to recompute `digest` EXCEPT the evidence itself , 
    a file's size and SHA-256 rather than its bytes, a device's kind rather than its
    serial. If a case cannot be described that way it should not be pinned; a corpus that
    needs the original drive is a corpus that will never be replayed.
    """
    if kind not in KINDS:
        raise ValueError(f"kind must be one of {KINDS}; got {kind!r}")
    if not digest:
        raise ValueError("a case with no digest pins nothing")

    d = corpus_dir(base) / kind
    d.mkdir(parents=True, exist_ok=True)

    case = {
        "corpus_version": CORPUS_VERSION,
        "kind": kind,
        "digest": digest,
        "inputs": inputs,
        "meta": meta or {},
        "recorded_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "recorded_by_tool": tool_ref(),
        "environment": _environment(),
        "meaning": (
            "This is what the tool DID on real input, pinned so it must keep doing it. "
            "It is not a statement that the result is CORRECT: if the run was wrong, this "
            "pins the bug. A future mismatch is a question about which of the two results "
            "is right, not an automatic verdict against the newer one."
        ),
    }

    # Name by digest so the same observation cannot be pinned twice under two names, and
    # so a case file's name is checkable against its contents.
    path = d / f"{digest[:16]}.json"
    if path.exists():
        return path
    path.write_text(json.dumps(case, indent=2, sort_keys=True), encoding="utf-8")
    return path


def load_all(base: Optional[Path] = None) -> list:
    """Every pinned case. A malformed file is reported as a case that fails to load,
    never skipped, silently ignoring corpus entries would let the suite shrink to zero
    without anyone noticing."""
    root = corpus_dir(base)
    cases = []
    if not root.is_dir():
        return cases
    for path in sorted(root.rglob("*.json")):
        try:
            case = json.loads(path.read_text(encoding="utf-8"))
            case["_path"] = str(path)
            cases.append(case)
        except (OSError, ValueError) as exc:
            cases.append({"_path": str(path), "_broken": f"{type(exc).__name__}: {exc}"})
    return cases


def replay(case: dict, recompute: Callable[[dict], Optional[str]]) -> dict:
    """Re-run one pinned case. `recompute(inputs) -> digest | None`.

    None means the case could not be replayed here, its input file is not on this
    machine, say. That is UNAVAILABLE, and it is deliberately not a pass: a corpus where
    every case quietly became unavailable would report a green suite while testing
    nothing.
    """
    if case.get("_broken"):
        return {"status": "BROKEN", "path": case.get("_path", ""),
                "reason": case["_broken"]}
    if case.get("corpus_version") != CORPUS_VERSION:
        return {"status": "BROKEN", "path": case.get("_path", ""),
                "reason": f"corpus_version {case.get('corpus_version')!r} is not "
                          f"{CORPUS_VERSION!r}; refused rather than mis-replayed"}

    try:
        got = recompute(case["inputs"])
    except Exception as exc:  # noqa: BLE001 - a replay reports, it does not propagate
        return {"status": "ERROR", "path": case["_path"], "kind": case["kind"],
                "reason": f"{type(exc).__name__}: {exc}"}

    if got is None:
        return {"status": "UNAVAILABLE", "path": case["_path"], "kind": case["kind"],
                "reason": "inputs not present on this machine; NOT counted as a pass"}
    if got == case["digest"]:
        return {"status": "REPRODUCED", "path": case["_path"], "kind": case["kind"]}
    return {
        "status": "DRIFTED", "path": case["_path"], "kind": case["kind"],
        "pinned": case["digest"], "got": got,
        "pinned_by_tool": case.get("recorded_by_tool", ""),
        "current_tool": tool_ref(),
        "reason": (
            "this input no longer produces the pinned digest. Which of the two is correct "
            "is a question for a human: the pin may have captured a bug that is now fixed, "
            "or the fix may have broken it. The tool that pinned it is named above so the "
            "two builds can be compared rather than guessed between."
        ),
    }


def replay_all(recompute_for: dict, base: Optional[Path] = None) -> dict:
    """Replay the whole corpus. `recompute_for` maps kind -> recompute callable.

    This is the CI gate. It fails on DRIFTED, BROKEN and ERROR, and reports UNAVAILABLE
    separately without failing, a machine that lacks the CFReDS images should not fail
    the build, but it must not be able to report a green corpus either.
    """
    cases = load_all(base)
    results = []
    for case in cases:
        kind = case.get("kind", "")
        fn = recompute_for.get(kind)
        if fn is None and not case.get("_broken"):
            results.append({"status": "UNAVAILABLE", "path": case.get("_path", ""),
                            "kind": kind, "reason": f"no recompute function for {kind!r}"})
            continue
        results.append(replay(case, fn) if fn else replay(case, lambda _i: None))

    counts: dict = {}
    for r in results:
        counts[r["status"]] = counts.get(r["status"], 0) + 1

    failed = counts.get("DRIFTED", 0) + counts.get("BROKEN", 0) + counts.get("ERROR", 0)
    return {
        "corpus_version": CORPUS_VERSION,
        "total": len(cases),
        "counts": counts,
        "ok": failed == 0,
        "results": results,
        "reason": (
            f"{counts.get('REPRODUCED', 0)}/{len(cases)} reproduced"
            + (f", {counts['UNAVAILABLE']} unavailable on this machine"
               if counts.get("UNAVAILABLE") else "")
            + (f", {failed} FAILED" if failed else "")
        ) if cases else "corpus is empty: nothing has been pinned yet",
    }


def stats(base: Optional[Path] = None) -> dict:
    """What the corpus has accumulated. The number that should only ever grow."""
    cases = load_all(base)
    by_kind: dict = {}
    for c in cases:
        by_kind[c.get("kind", "?")] = by_kind.get(c.get("kind", "?"), 0) + 1
    return {
        "total": len(cases),
        "by_kind": by_kind,
        "broken": sum(1 for c in cases if c.get("_broken")),
        "corpus_dir": str(corpus_dir(base)),
        "meaning": ("Each case is one real observation the tool must keep reproducing. "
                    "This count should only ever grow; a drop means cases were deleted, "
                    "which is a decision someone has to justify."),
    }
