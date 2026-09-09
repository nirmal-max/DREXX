"""Fragment reassembly validation bench, many files, many fragmentations, one oracle.

WHY THIS EXISTS SEPARATELY FROM tests/. The reassembly claim rested on ONE file, in ONE
format, from ONE disk image (NIST CFReDS L2). That is a real result and it was scored at
p ≈ 0.85 with an explicit penalty for exactly that narrowness. A single success is an
anecdote; the penalty was correct and the only honest way to remove it is to widen the
evidence rather than to re-argue the same run.

This bench fragments REAL files in CONTROLLED, ADVERSARIAL ways and measures byte-identical
recovery across every case. Ground truth is the original file's SHA-256, so "recovered"
means the same bytes, never "a decoder accepted it".

    python validation/reassembly/bench/fragment_bench.py
    python validation/reassembly/bench/fragment_bench.py --repeats 5   # more split points

Two families of case, and BOTH are required:

    POSITIVE  the file is present in pieces and MUST be recovered byte-identically.
    NEGATIVE  the file is absent, incomplete, or mixed with another file's fragments,
              and the tool MUST NOT claim a recovery.

A bench with only positives measures eagerness, not accuracy. The negatives are where a
reassembler earns trust: splicing the first half of one photograph onto the second half of
another produces a file that opens perfectly and is evidentially worthless.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import random
import struct
import sys
import time
import zlib
from dataclasses import dataclass, field
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "src"))

from recovery.engine import carve  # noqa: E402
from recovery.reassemble import reassemble  # noqa: E402

DATA = ROOT / "tests" / "data"
RESULTS = ROOT / "validation" / "reassembly" / "results"

# Filler that is NOT innocuous. Deterministic SHA-256 output carries no PNG structure, so a
# bench built only on it would never test whether the scanner rejects near-misses. Some
# cases below deliberately salt the gap with PNG-shaped decoys instead.
def filler(seed: int, n: int) -> bytes:
    out = bytearray()
    c = seed
    while len(out) < n:
        out += hashlib.sha256(c.to_bytes(8, "big")).digest()
        c += 1
    return bytes(out[:n])


def decoy_chunks(seed: int, n: int) -> bytes:
    """Bytes that LOOK like PNG chunks and are not: right type tokens, wrong CRCs.

    This is the adversarial filler. Any scanner that trusts a four-byte type token without
    checking the checksum will pick these up, and the negative cases will catch it.
    """
    rnd = random.Random(seed)
    out = bytearray()
    types = [b"IDAT", b"IHDR", b"IEND", b"pHYs", b"tEXt"]
    while len(out) < n:
        ln = rnd.randrange(16, 512)
        body = bytes(rnd.randrange(256) for _ in range(ln))
        out += struct.pack(">I", ln) + rnd.choice(types) + body
        out += struct.pack(">I", rnd.randrange(1 << 32))     # deliberately wrong CRC
    return bytes(out[:n])


@dataclass
class Case:
    name: str
    kind: str                    # "positive" | "negative"
    image: bytes
    expect_sha256: str = ""      # positive: must be recovered. negative: must NOT appear.
    note: str = ""


@dataclass
class Outcome:
    case: str
    kind: str
    passed: bool
    recovered: int
    matched: bool
    detail: str = ""
    fragments: int = 0
    boundary: bool = False

    def to_dict(self) -> dict:
        return {"case": self.case, "kind": self.kind, "passed": self.passed,
                "recovered": self.recovered, "matched": self.matched,
                "fragments": self.fragments, "boundary_recovered": self.boundary,
                "detail": self.detail}


# ───────────────────────────────────────────────────── fragmentation patterns

def split_at(blob: bytes, pos: int) -> tuple:
    return blob[:pos], blob[pos:]


def case_swapped(src: bytes, name: str, pos: int, gap: int, decoy: bool) -> Case:
    """The CFReDS L2 shape: two fragments, SECOND HALF STORED FIRST."""
    a, b = split_at(src, pos)
    pad = decoy_chunks(pos, gap) if decoy else filler(pos, gap)
    return Case(name, "positive", pad[:gap // 2] + b + pad[gap // 2:] + a,
                hashlib.sha256(src).hexdigest(),
                f"2 fragments, order reversed, split at {pos}, "
                f"{'decoy-salted' if decoy else 'plain'} gap {gap}")


def case_inorder(src: bytes, name: str, pos: int, gap: int) -> Case:
    """Two fragments, correct order, separated by a gap."""
    a, b = split_at(src, pos)
    return Case(name, "positive", filler(1, 4096) + a + filler(pos, gap) + b + filler(9, 4096),
                hashlib.sha256(src).hexdigest(),
                f"2 fragments, in order, split at {pos}, gap {gap}")


def case_at_end(src: bytes, name: str, pos: int) -> Case:
    """First fragment runs to the LAST BYTE of the image.

    This is the off-by-one that was found in the module: the straddle search bounded its
    loop exclusively and lost the one chunk it existed to recover, failing as
    "no boundary chunk" rather than as an error.
    """
    a, b = split_at(src, pos)
    return Case(name, "positive", b + filler(3, 8192) + a,
                hashlib.sha256(src).hexdigest(),
                f"first fragment ends at the final byte of the image, split at {pos}")


def case_three(src: bytes, name: str, p1: int, p2: int) -> Case:
    """Three fragments, shuffled, BEYOND the documented two-fragment capability.

    Classified as a LIMIT case, not a positive. The module documents two fragments, so
    failing to recover three is correct behaviour rather than a defect. What is NOT
    acceptable is returning something WRONG: the first run of this bench found the module
    reporting a file 5,193,132 bytes short, missing its entire middle fragment, which
    Pillow decoded happily as "PNG 2580x1932 RGB".

    So a limit case passes only when the tool returns NOTHING. Silence at the edge of a
    capability is honest; a plausible wrong answer is the failure this category exists to
    catch.
    """
    a, b, c = src[:p1], src[p1:p2], src[p2:]
    return Case(name, "limit",
                filler(2, 2048) + c + filler(4, 4096) + a + filler(6, 4096) + b,
                hashlib.sha256(src).hexdigest(),
                f"THREE fragments shuffled at {p1}/{p2}, beyond the documented "
                "2-fragment capability; must return nothing rather than a partial file")


# ───────────────────────────────────────────────────── negative cases

def case_absent(name: str) -> Case:
    return Case(name, "negative", decoy_chunks(11, 6 << 20), "",
                "6 MB of PNG-SHAPED DECOYS with wrong CRCs, must recover nothing")


def case_truncated(src: bytes, name: str) -> Case:
    """Header present, tail missing. There is no IEND, so no complete file exists."""
    return Case(name, "negative", filler(5, 4096) + src[:len(src) // 2] + filler(7, 4096), "",
                "first half only, no IEND, a partial file must not be reported as recovered")


def case_headless(src: bytes, name: str) -> Case:
    """The CFReDS L3 shape: tail present, header absent."""
    return Case(name, "negative", filler(8, 4096) + src[len(src) // 2:] + filler(10, 4096), "",
                "second half only, no IHDR, the L3 shape; no dimensions, so no valid file")


def case_mixed(a_src: bytes, b_src: bytes, name: str) -> Case:
    """THE MOST IMPORTANT NEGATIVE IN THIS FILE.

    The first half of one PNG and the second half of a DIFFERENT PNG. Both halves are made
    of genuine, CRC-valid chunks, so every fragment "belongs" to a real file, just not to
    the same one. A spliced result decodes perfectly and is evidentially worthless.

    If a reassembler joins these, it will do the same thing on a disk holding two
    photographs, and no decoder check will ever notice.
    """
    a = a_src[:len(a_src) // 2]
    b = b_src[len(b_src) // 2:]
    return Case(name, "negative", filler(12, 4096) + a + filler(13, 8192) + b, "",
                "first half of one PNG + second half of ANOTHER, both halves CRC-valid; "
                "splicing them yields a file that decodes and is evidence of nothing")


# ───────────────────────────────────────────────────── runner

def run_case(case: Case, tmp: Path) -> Outcome:
    img = tmp / "case.img"
    img.write_bytes(case.image)
    try:
        got = reassemble(str(img))
    except Exception as exc:  # noqa: BLE001
        return Outcome(case.name, case.kind, False, 0, False,
                       f"reassemble raised {type(exc).__name__}: {exc}")
    finally:
        pass

    hashes = {r["sha256"] for r in got}
    frags = got[0]["fragments"] if got else []
    boundary = bool(got and got[0].get("boundary_recovered"))

    if case.kind == "positive":
        matched = case.expect_sha256 in hashes
        return Outcome(case.name, "positive", matched, len(got), matched,
                       case.note if matched else f"{case.note}, NOT RECOVERED",
                       len(frags), boundary)

    if case.kind == "limit":
        # Beyond the documented capability. Returning nothing is the pass; returning a
        # file -- even one that decodes -- is the dangerous failure.
        wrong = [h for h in hashes if h != case.expect_sha256]
        ok = len(got) == 0
        detail = case.note if ok else (
            f"{case.note}, RETURNED {len(got)} FILE(S), "
            + ("none matching the original" if wrong else "matching the original"))
        return Outcome(case.name, "limit", ok, len(got),
                       case.expect_sha256 in hashes, detail, len(frags), boundary)

    # Negative: any reported reassembly is a false positive.
    ok = len(got) == 0
    return Outcome(case.name, "negative", ok, len(got), False,
                   case.note if ok else f"{case.note}, FALSE POSITIVE: reported "
                                        f"{len(got)} reassembly/ies")


def build_cases(repeats: int) -> list:
    # Prefer the built corpus: 28 PNGs across four colour types and three orders of
    # magnitude of size. Fall back to tests/data if it has not been built, so the bench
    # still runs on a fresh checkout rather than failing to start.
    corpus = ROOT / "validation" / "reassembly" / "corpus"
    pngs = sorted(corpus.glob("*.png")) or sorted(DATA.glob("*.png"))
    if not pngs:
        raise SystemExit(f"no PNG sources; run build_corpus.py or check {DATA}")

    cases: list = []
    rnd = random.Random(20260901)

    for src_path in pngs:
        src = src_path.read_bytes()
        stem = src_path.stem
        n = len(src)

        for i in range(repeats):
            # Split points chosen to land INSIDE chunks as often as possible, because the
            # straddling chunk is the hard part. Fixed seed, so a failure is reproducible.
            pos = rnd.randrange(int(n * 0.2), int(n * 0.8))
            cases.append(case_swapped(src, f"{stem}/swapped#{i}", pos, 16384, decoy=(i % 2 == 0)))
            cases.append(case_inorder(src, f"{stem}/inorder#{i}", pos, 8192))

        cases.append(case_at_end(src, f"{stem}/frag-at-image-end", int(n * 0.6)))
        cases.append(case_three(src, f"{stem}/three-fragments", int(n * 0.3), int(n * 0.7)))

        cases.append(case_truncated(src, f"{stem}/truncated-no-IEND"))
        cases.append(case_headless(src, f"{stem}/headless-no-IHDR"))

    cases.append(case_absent("decoys-only"))
    if len(pngs) >= 2:
        a, b = pngs[0].read_bytes(), pngs[1].read_bytes()
        cases.append(case_mixed(a, b, "MIXED-two-different-pngs"))
    else:
        # One PNG in the corpus: build the second from the first by re-encoding, so the
        # most important negative still runs rather than being silently skipped.
        try:
            import io

            from PIL import Image
            im = Image.open(io.BytesIO(pngs[0].read_bytes()))
            buf = io.BytesIO()
            im.resize((im.width // 2, im.height // 2)).save(buf, "PNG")
            cases.append(case_mixed(pngs[0].read_bytes(), buf.getvalue(),
                                    "MIXED-two-different-pngs"))
        except Exception as exc:  # noqa: BLE001
            print(f"  ! could not build the MIXED case: {exc}", file=sys.stderr)
    return cases


def main() -> int:
    ap = argparse.ArgumentParser(description="Fragment reassembly validation bench.")
    ap.add_argument("--repeats", type=int, default=3,
                    help="random split points per file per pattern")
    ap.add_argument("--out", default=str(RESULTS / "fragment_bench.json"))
    args = ap.parse_args()

    import tempfile
    tmp = Path(tempfile.mkdtemp())

    cases = build_cases(args.repeats)
    print(f"{len(cases)} cases\n")

    outcomes = []
    t0 = time.perf_counter()
    for c in cases:
        o = run_case(c, tmp)
        outcomes.append(o)
        mark = "pass" if o.passed else "FAIL"
        extra = ""
        if o.kind == "positive" and o.passed:
            extra = f"  [{o.fragments} frags{', boundary' if o.boundary else ''}]"
        print(f"  [{mark}] {o.kind:<8} {o.case:<34}{extra}")
        if not o.passed:
            print(f"         {o.detail}")
    wall = time.perf_counter() - t0

    pos = [o for o in outcomes if o.kind == "positive"]
    neg = [o for o in outcomes if o.kind == "negative"]
    lim = [o for o in outcomes if o.kind == "limit"]
    pos_ok = [o for o in pos if o.passed]
    neg_ok = [o for o in neg if o.passed]
    lim_ok = [o for o in lim if o.passed]
    # THE HEADLINE SAFETY NUMBER: any case, of any kind, that produced a file which is not
    # byte-identical to the original. This is the one that must be zero.
    wrong_files = [o for o in outcomes if o.recovered > 0 and not o.matched]

    report = {
        "check": "fragment reassembly validation bench",
        "ran_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "wall_s": round(wall, 1),
        "cases": len(cases),
        "positive": {"total": len(pos), "recovered": len(pos_ok),
                     "rate_pct": round(100.0 * len(pos_ok) / len(pos), 1) if pos else None},
        "negative": {"total": len(neg), "correctly_refused": len(neg_ok),
                     "false_positives": len(neg) - len(neg_ok)},
        "limit": {"total": len(lim), "safely_refused": len(lim_ok),
                  "returned_something_anyway": len(lim) - len(lim_ok),
                  "meaning": "beyond the documented 2-fragment capability; silence is the "
                             "correct answer and a plausible wrong file is the failure"},
        "wrong_files_reported": len(wrong_files),
        "ok": (len(pos_ok) == len(pos) and len(neg_ok) == len(neg)
               and len(lim_ok) == len(lim) and not wrong_files),
        "standard": ("recovered means BYTE-IDENTICAL to the original by SHA-256, never "
                     "'a decoder accepted it'. A negative case passes only when NOTHING "
                     "is reported."),
        "results": [o.to_dict() for o in outcomes],
    }

    Path(args.out).parent.mkdir(parents=True, exist_ok=True)
    Path(args.out).write_text(json.dumps(report, indent=2), encoding="utf-8")

    print(f"\npositives  {len(pos_ok)}/{len(pos)} recovered byte-identically")
    print(f"negatives  {len(neg_ok)}/{len(neg)} correctly refused "
          f"({len(neg) - len(neg_ok)} false positive)")
    print(f"wall       {wall:.1f}s")
    print(f"written    {args.out}")
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
