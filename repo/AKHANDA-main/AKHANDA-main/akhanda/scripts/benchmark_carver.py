"""
Automated carver benchmark against NIST CFReDS.

    PYTHONPATH=src python scripts/benchmark_carver.py
    PYTHONPATH=src python scripts/benchmark_carver.py --json evidence/carver.json

Scores every NIST image present in tests/data against published ground truth and writes a
machine-readable record. No synthetic data, no self-generated images, no partial credit.

Scoring is deliberately strict:

  * A hit is a **byte-identical SHA-256 match** against one of NIST's source files.
    Not "looks like a JPEG", not "opens in a viewer". The same bytes, or it does not count.
  * **Precision** = exact matches / artefacts reported. Every false positive costs.
  * **Recall**    = distinct source files recovered / source files in the corpus.

NIST's levels are a difficulty ladder, and reporting one number across all of them hides
what the tool actually does:

    L0  non-fragmented          the case signature carving is FOR
    L1  sequential fragments
    L2  non-sequential fragments
    L3  missing fragments
    L4  nested files
    L5  braided files           adversarial by construction

Any tool claiming a single headline figure across L0-L5 is averaging away the distinction
an examiner needs. This prints per-level and refuses to emit a blended average.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from recovery.engine import HIGH, carve, outcome_for, summarize  # noqa: E402

DATA = ROOT / "tests" / "data"

ORIGINALS = ("09260002.jpg", "02010026.jpg", "000_0021.png", "100_0183.gif",
             "100_0018.tif", "100_0304crop.bmp", "02010025.pcx")

LEVELS = {
    "L0": "non-fragmented, the case signature carving is designed for",
    "L1": "sequential fragmentation",
    "L2": "non-sequential fragmentation",
    "L3": "missing fragments",
    "L4": "nested files",
    "L5": "braided files, adversarial by construction",
}


def ground_truth() -> dict:
    out = {}
    for f in ORIGINALS:
        p = DATA / f
        if p.is_file():
            out[hashlib.sha256(p.read_bytes()).hexdigest()] = (f, p.stat().st_size)
    return out


def files_present(image: Path, originals: dict) -> list:
    """Which source files are contiguously present in this image.

    Recall must be measured against what is ACTUALLY in the image, not against the whole
    corpus. NIST's images do not each contain all seven sources, L0 holds six, so
    dividing by seven understates the tool by exactly the files that were never there.
    That was a defect in the measurement, not in the carver.

    A contiguous byte search answers this exactly for the non-fragmented levels. For the
    fragmented ones nothing is contiguous by construction, so the honest denominator is
    zero and recall is reported as not-applicable rather than as 0%.
    """
    blob = image.read_bytes()
    return [name for name, data in originals.items() if blob.find(data) >= 0]


def score(image: Path, truth: dict, originals: dict) -> dict:
    t0 = time.perf_counter()
    arts = carve(str(image))
    elapsed = time.perf_counter() - t0

    exact = [a for a in arts if a["sha256"] in truth]
    recovered = sorted({truth[a["sha256"]][0] for a in exact})
    present = files_present(image, originals)
    s = summarize(arts)

    # Of the artefacts the tool presented as HIGH confidence, how many are real files?
    high = [a for a in arts if a["confidence"] == HIGH]
    high_exact = [a for a in high if a["sha256"] in truth]

    mb = image.stat().st_size / (1024 * 1024)
    return {
        "image": image.name,
        "bytes": image.stat().st_size,
        "seconds": round(elapsed, 2),
        "throughput_mb_s": round(mb / elapsed, 1) if elapsed else None,
        "reported": len(arts),
        "exact": len(exact),
        "recovered": recovered,
        "present": present,
        "precision": round(len(exact) / len(arts) * 100, 1) if arts else 0.0,
        # against files actually in THIS image; None when nothing is contiguous
        "recall": (round(len(recovered) / len(present) * 100, 1) if present else None),
        "recall_vs_corpus": round(len(recovered) / len(truth) * 100, 1) if truth else 0.0,
        "high_confidence": len(high),
        "high_precision": round(len(high_exact) / len(high) * 100, 1) if high else 0.0,
        "by_type": s["by_type"],
        "by_confidence": s["by_confidence"],
        "outcome": outcome_for(arts),
    }


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.strip().splitlines()[0])
    ap.add_argument("--json", default=None, help="write the record here")
    ap.add_argument("--min-l0-precision", type=float, default=None,
                    help="exit non-zero if L0 precision falls below this")
    args = ap.parse_args()

    truth = ground_truth()
    if not truth:
        print("NIST ground-truth source files not found in tests/data.")
        print("See tests/test_recovery_nist.py for the download commands.")
        return 2

    originals = {f: (DATA / f).read_bytes() for f in ORIGINALS if (DATA / f).is_file()}
    images = sorted(DATA.glob("L?_*.dd"))
    if not images:
        print(f"no NIST images in {DATA}")
        return 2

    print(f"NIST CFReDS carver benchmark, {len(truth)} ground-truth source files")
    print("=" * 100)
    print(f"{'image':<18}{'level':<6}{'in img':>7}{'rep':>5}{'exact':>7}"
          f"{'prec':>8}{'recall':>8}{'HIGHp':>8}{'MB/s':>7}  outcome")
    print("-" * 100)

    rows = []
    for img in images:
        r = score(img, truth, originals)
        level = img.name[:2]
        rows.append({**r, "level": level, "level_note": LEVELS.get(level, "")})
        rec = f"{r['recall']:>7.1f}%" if r["recall"] is not None else "    n/a "
        print(f"{img.name:<18}{level:<6}{len(r['present']):>7}{r['reported']:>5}"
              f"{r['exact']:>7}{r['precision']:>7.1f}%{rec}{r['high_precision']:>7.1f}%"
              f"{r['throughput_mb_s'] or 0:>7.1f}  {r['outcome']}")

    print("-" * 100)
    for row in rows:
        if row["recovered"]:
            print(f"  {row['image']:<18} intact: {', '.join(row['recovered'])}")

    l0 = next((r for r in rows if r["level"] == "L0"), None)
    if l0:
        print()
        print(f"  L0 (non-fragmented, the case carving is FOR): "
              f"precision {l0['precision']}%  recall {l0['recall']}%  "
              f"({l0['exact']} of {len(l0['present'])} files present, byte-identical)")
        print("  Fragmented levels are lower BY CONSTRUCTION, signature carving cannot")
        print("  reassemble non-contiguous extents, and NIST built L2-L5 to show it.")
        print("  Where nothing is contiguous, recall is n/a rather than 0%: there was no")
        print("  intact file to recover. Reporting one blended figure would hide all of this.")

    if args.json:
        out = Path(args.json)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(
            {"corpus": "NIST CFReDS FileCarving",
             "ground_truth_files": len(truth),
             "generated_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
             "results": rows}, indent=2), encoding="utf-8")
        print(f"\nwritten: {out}")

    if args.min_l0_precision is not None and l0:
        if l0["precision"] < args.min_l0_precision:
            print(f"\nFAIL: L0 precision {l0['precision']}% < {args.min_l0_precision}%")
            return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
