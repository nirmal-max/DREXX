"""
Seed console/chain.json so the console renders without the backend running.

    PYTHONPATH=src python scripts/seed_console.py

This exists because role 4's acceptance test is exactly that: the console must render
correct state from a chain.json the lead provides, with nothing else running. The chain
written here is deliberately MIXED - some entries dual-signed, some operator-only, tiers
varying - so the console has to render the honest, uneven case rather than a uniform
green screenshot that proves nothing.
"""

import hashlib
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from attestation import tiers
from attestation.core import Chain, key_id

# Deliberately mixed: the console has to render the honest uneven case, including an
# operation that completed WITHOUT passing its own verification and an attempt that was
# blocked outright. A uniform green screenshot proves nothing.
OPS = [
    ("RECOVER", "seized-laptop.dd", "2026-01-01T10:00:00Z", "Clear",
     tiers.FULL_CUSTODY, "COM9:9f2a1c7b04e5d613", "VERIFIED"),
    ("RECOVER", "seized-laptop.dd", "2026-01-01T10:05:00Z", "Clear",
     tiers.FULL_CUSTODY, "COM9:1b8d4e0a72c9f356", "PARTIAL"),
    ("ERASE", "/dev/sdb", "2026-01-01T11:00:00Z", "Clear",
     tiers.WITNESS_COSIGNED, "", "VERIFIED"),
    ("ERASE", "/dev/sdc", "2026-01-01T11:30:00Z", "Clear",
     tiers.SOFTWARE_KEY, "", "UNVERIFIED"),   # wipe ran, read-back did NOT confirm it
    ("REFUSED", "/dev/sdd", "2026-01-01T11:45:00Z", "NotPerformed",
     tiers.SOFTWARE_KEY, "", "NOT_PERFORMED"),
]


def main() -> int:
    op_key = Ed25519PrivateKey.generate()
    concur_key = Ed25519PrivateKey.generate()

    chain = Chain(chain_id="case-2026-014")
    for i, (op, target, ts, method, tier, pref, outcome) in enumerate(OPS):
        chain.append(op, target, ts, method, f"{i:02x}" * 32,
                     "operator: J. Rao, Forensic Analyst",
                     "expert: K. Singh, Expert Witness",
                     tier, op_key, presence_ref=pref, outcome=outcome)

    head = "00" * 32
    for e in chain.entries:
        if not tiers.has_witness(e.custody_tier):
            continue                       # the witness never saw this entry
        sig = concur_key.sign(bytes.fromhex(e.entry_hash)).hex()
        head = hashlib.sha256((head + e.entry_hash).encode()).hexdigest()
        chain.attach_cosignature(e.seq, sig, key_id(concur_key.public_key()),
                                 head, e.seq)

    out = ROOT / "console" / "chain.json"
    out.write_text(chain.to_json(), encoding="utf-8")
    dual = sum(1 for e in chain.entries if e.is_dual_signed())
    print(f"wrote {out}")
    print(f"  chain id     : {chain.chain_id}")
    print(f"  entries      : {len(chain.entries)} ({dual} dual-signed, "
          f"{len(chain.entries) - dual} operator-only)")
    print(f"  head         : {chain.head_hash()}")
    print(f"  witness head : {head}")
    print("\nOpen console/index.html, or serve it:")
    print("  python -m http.server 8080 --directory console")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
