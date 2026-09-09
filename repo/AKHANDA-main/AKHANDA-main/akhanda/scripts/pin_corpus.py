"""Pin real observations into the regression corpus, and replay what is already pinned.

    python scripts/pin_corpus.py --pin-cfreds     # pin the five NIST images
    python scripts/pin_corpus.py --replay         # the CI gate
    python scripts/pin_corpus.py --stats

This is the honest form of "the tool improves with each task": it does not change its own
code, it accumulates cases it must keep reproducing. Every real drive that goes through
the tool should end up here, so that the awkward inputs, the ones nobody would have
thought to write a fixture for, become permanent.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from attestation import corpus  # noqa: E402
from recovery.engine import carve, outcome_for, result_hash, summarize  # noqa: E402

DATA = ROOT / "tests" / "data"


def _file_id(path: Path) -> dict:
    """Identify an input without storing it. Size plus digest, never the bytes."""
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for block in iter(lambda: fh.read(1 << 20), b""):
            h.update(block)
    return {"name": path.name, "size": path.stat().st_size, "sha256": h.hexdigest()}


# --------------------------------------------------------------------------- recompute

def recompute_carve(inputs: dict):
    """Find the image by CONTENT, not by path, and re-derive its carve digest.

    Matching on sha256 rather than a stored path is what makes a pinned case portable: the
    same image carries the same identity on any machine, and a path pinned on one laptop
    is meaningless on another.
    """
    want = inputs.get("sha256", "")
    for candidate in sorted(DATA.glob("*.dd")) + sorted(DATA.glob("*.img")):
        if candidate.stat().st_size != inputs.get("size"):
            continue
        if _file_id(candidate)["sha256"] == want:
            return result_hash(carve(str(candidate)))
    return None  # not on this machine -> UNAVAILABLE, never a silent pass


RECOMPUTE = {"carve": recompute_carve}


# -------------------------------------------------------------------------------- pin

def pin_cfreds() -> int:
    images = sorted(DATA.glob("L*_Graphic.dd"))
    if not images:
        print(f"no CFReDS images under {DATA}", file=sys.stderr)
        return 2

    for path in images:
        ident = _file_id(path)
        artifacts = carve(str(path))
        digest = result_hash(artifacts)
        summary = summarize(artifacts)
        out = corpus.record(
            "carve",
            inputs=ident,
            digest=digest,
            meta={
                "source": "NIST CFReDS graphic image",
                "artifacts": len(artifacts),
                "outcome": outcome_for(artifacts),
                "by_type": summary.get("by_type", {}),
                "truncated": summary.get("truncated", 0),
                "note": ("Reference data, not team-generated. L2 and L3 contain no "
                         "contiguous file by construction, so a low artifact count on "
                         "those is the expected result and not a regression."),
            },
        )
        print(f"pinned {path.name:<18} {len(artifacts):>2} artefacts  "
              f"{digest[:16]}…  -> {out.name}")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description="Pin and replay real regression cases.")
    ap.add_argument("--pin-cfreds", action="store_true")
    ap.add_argument("--replay", action="store_true")
    ap.add_argument("--stats", action="store_true")
    args = ap.parse_args()

    if args.pin_cfreds:
        return pin_cfreds()

    if args.stats or not (args.replay):
        s = corpus.stats()
        print(f"corpus   : {s['corpus_dir']}")
        print(f"cases    : {s['total']}  {s['by_kind']}")
        if s["broken"]:
            print(f"BROKEN   : {s['broken']}")
        print(f"meaning  : {s['meaning']}")
        if not args.replay:
            return 0

    report = corpus.replay_all(RECOMPUTE)
    print(f"\nreplay   : {report['reason']}")
    for r in report["results"]:
        if r["status"] == "REPRODUCED":
            continue
        print(f"  {r['status']:<12} {Path(r.get('path', '')).name}  {r.get('reason', '')}")
        if r["status"] == "DRIFTED":
            print(f"      pinned by {r['pinned_by_tool']}")
            print(f"      current   {r['current_tool']}")
            print(f"      pinned {r['pinned'][:16]}…  got {r['got'][:16]}…")
    print(f"\nok       : {report['ok']}")
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
