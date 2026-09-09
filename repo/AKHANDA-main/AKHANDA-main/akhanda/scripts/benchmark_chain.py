"""G8, chain verification timing benchmark.

Answers one question with numbers instead of a claim: does verification stay usable as
the ledger grows, and how long does it take to LOCALISE a tamper rather than just detect
one? Emits evidence/chain_benchmark.json.

    python scripts/benchmark_chain.py [--entries 500] [--repeats 5]

Not a test. Nothing here asserts a threshold, because a threshold that depends on the
machine it ran on is a claim about the machine, not the code. It records what this
machine did, and BUILD_LOG.md quotes it with the machine named.
"""
from __future__ import annotations

import argparse
import json
import statistics
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from attestation.core import Chain, verify_chain_report  # noqa: E402
from attestation.keys import load_or_create_operator_key  # noqa: E402

EVIDENCE = ROOT / "evidence"


def build_chain(n: int, key):
    """A chain of n real, really-signed entries. No mocking, signing is the cost."""
    chain = Chain()
    for i in range(n):
        chain.append(
            op_type="ERASE" if i % 2 == 0 else "RECOVER",
            target_ref=f"/dev/benchmark{i}",
            timestamp=f"2026-09-01T00:{i // 60:02d}:{i % 60:02d}Z",
            method="Clear",
            result_hash=f"{i:064x}",
            operator_decl=f"benchmark entry {i}",
            concur_decl="",
            custody_tier="SOFTWARE_KEY",
            operator_key=key,
            outcome="VERIFIED",
        )
    return chain


def time_it(fn, repeats: int) -> dict:
    samples = []
    for _ in range(repeats):
        t0 = time.perf_counter()
        fn()
        samples.append((time.perf_counter() - t0) * 1000.0)
    return {
        "repeats": repeats,
        "median_ms": round(statistics.median(samples), 3),
        "min_ms": round(min(samples), 3),
        "max_ms": round(max(samples), 3),
    }


def main() -> int:
    ap = argparse.ArgumentParser(description="Time chain verification and tamper localisation.")
    ap.add_argument("--entries", type=int, default=500)
    ap.add_argument("--repeats", type=int, default=5)
    ap.add_argument("--out", default=str(EVIDENCE / "chain_benchmark.json"))
    args = ap.parse_args()

    key = load_or_create_operator_key()
    pub = key.public_key()

    t0 = time.perf_counter()
    chain = build_chain(args.entries, key)
    build_ms = (time.perf_counter() - t0) * 1000.0

    entries = chain.entries
    n = len(entries)

    # 1. Key-free verification only (the layer that always runs).
    keyfree = time_it(lambda: verify_chain_report(entries), args.repeats)

    # 2. Full verification, signatures re-checked against the real public key.
    signed = time_it(lambda: verify_chain_report(entries, operator_pub=pub), args.repeats)

    # 3. Tamper LOCALISATION: corrupt the middle entry, then time how long the verifier
    #    takes to name the broken seq. Detecting is not the interesting number; saying
    #    WHERE is what a forensic examiner is asked in court.
    victim = n // 2
    original = entries[victim].operator_decl
    entries[victim].operator_decl = original + " [TAMPERED]"

    report = verify_chain_report(entries, operator_pub=pub)
    localise = time_it(lambda: verify_chain_report(entries, operator_pub=pub), args.repeats)
    located_at = report.broken_seq
    entries[victim].operator_decl = original  # restore

    restored = verify_chain_report(entries, operator_pub=pub)

    out = {
        "entries": n,
        "machine_note": "record the machine name in BUILD_LOG.md; timings are machine-specific",
        "build_chain_ms": round(build_ms, 3),
        "build_per_entry_ms": round(build_ms / n, 4),
        "verify_key_free": keyfree,
        "verify_with_signatures": signed,
        "verify_per_entry_us": round(signed["median_ms"] * 1000.0 / n, 2),
        "tamper_localisation": {
            **localise,
            "tampered_seq": victim,
            "located_at_seq": located_at,
            "correctly_localised": located_at == victim,
            "reason": report.reason,
        },
        "restored_verifies": bool(restored.ok),
    }

    Path(args.out).parent.mkdir(parents=True, exist_ok=True)
    Path(args.out).write_text(json.dumps(out, indent=2), encoding="utf-8")

    print(f"entries                  {n}")
    print(f"build (sign) per entry   {out['build_per_entry_ms']} ms")
    print(f"verify key-free          {keyfree['median_ms']} ms median")
    print(f"verify with signatures   {signed['median_ms']} ms median "
          f"({out['verify_per_entry_us']} us/entry)")
    print(f"tamper localisation      {localise['median_ms']} ms median, "
          f"tampered seq {victim} -> located {located_at} "
          f"({'correct' if out['tamper_localisation']['correctly_localised'] else 'WRONG'})")
    print(f"restored chain verifies  {out['restored_verifies']}")
    print(f"written                  {args.out}")

    if not out["tamper_localisation"]["correctly_localised"] or not out["restored_verifies"]:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
