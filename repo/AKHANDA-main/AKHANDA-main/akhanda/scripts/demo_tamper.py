"""
The demo centrepiece. Run this on stage.

    PYTHONPATH=src python scripts/demo_tamper.py

Three acts, in increasing order of what they prove:

  ACT 1  A tampered entry is caught and NAMED. Every competitor tool does this much.
  ACT 2  A DELETED entry is caught. Independently-signed certificates do NOT do this -
         nothing stops a record being removed from the middle of a pile of PDFs.
  ACT 3  A FULL CHAIN REWRITE passes every local check, and the witness still catches it.
         This is the act no single-machine ledger can perform.

No hardware is required. The witness is simulated in-process so the demo cannot be
broken by a Pi failing to join the wifi on stage; the real Pi runs the identical head
construction (there is a test that pins the two together).
"""

import hashlib
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from attestation import tiers
from attestation.core import Chain, key_id, verify_chain_report
from witness.client import compare_witness_head

RULE = "=" * 78


def banner(text: str) -> None:
    print(f"\n{RULE}\n{text}\n{RULE}")


def build_chain(op_key, chain_id="case-2026-014"):
    c = Chain(chain_id=chain_id)
    ops = [
        ("RECOVER", "seized-laptop.dd", "2026-01-01T10:00:00Z", "Clear"),
        ("RECOVER", "seized-laptop.dd", "2026-01-01T10:05:00Z", "Clear"),
        ("ERASE", "/dev/sdb", "2026-01-01T11:00:00Z", "Clear"),
        ("ERASE", "/dev/sdc", "2026-01-01T11:30:00Z", "Clear"),
    ]
    for i, (op, target, ts, method) in enumerate(ops):
        c.append(op, target, ts, method, f"{i:02x}" * 32,
                 "operator: J. Rao", "expert: K. Singh",
                 tiers.WITNESS_COSIGNED, op_key)
    return c


def simulate_witness(chain, concur_key):
    """Stand-in for the Pi. Co-signs every entry and keeps its OWN head record."""
    head = "00" * 32
    for e in chain.entries:
        sig = concur_key.sign(bytes.fromhex(e.entry_hash)).hex()
        head = hashlib.sha256((head + e.entry_hash).encode()).hexdigest()
        chain.attach_cosignature(e.seq, sig, key_id(concur_key.public_key()),
                                 head, e.seq)
    return {"ok": True, "head_hash": head, "seq": chain.entries[-1].seq,
            "count": len(chain.entries), "reason": "witness head read"}


def show(chain, op_pub, label):
    r = verify_chain_report(chain.entries, op_pub)
    verdict = "VERIFIED" if r.ok else f"BROKEN at sequence {r.broken_seq}"
    print(f"  {label:<34} {verdict}")
    if not r.ok:
        print(f"  {'':34} reason: {r.reason}")
    return r


def main() -> int:
    op_key = Ed25519PrivateKey.generate()
    concur_key = Ed25519PrivateKey.generate()
    op_pub = op_key.public_key()

    banner("AKHANDA - unbroken chain of custody")
    chain = build_chain(op_key)
    witness_state = simulate_witness(chain, concur_key)
    print(f"  chain id       : {chain.chain_id}")
    print(f"  entries        : {len(chain.entries)}, all dual-signed")
    print(f"  workstation head: {chain.head_hash()}")
    print(f"  witness head    : {witness_state['head_hash']}")

    # ------------------------------------------------------------------- ACT 1
    banner("ACT 1 - someone edits an entry after the fact")
    show(chain, op_pub, "before tampering:")
    chain.entries[2].method = "Purge"          # the exact overclaim this tool prevents
    print("\n  operator quietly upgrades entry 2 from 'Clear' to 'Purge'...\n")
    show(chain, op_pub, "after tampering:")
    chain.entries[2].method = "Clear"          # restore for the next act

    # ------------------------------------------------------------------- ACT 2
    banner("ACT 2 - someone deletes an entry from the middle")
    print("  This is what independently-signed certificates cannot catch: every")
    print("  remaining document still has a perfectly valid signature.\n")
    removed = chain.entries.pop(1)
    print(f"  removed entry 1 ({removed.op_type} {removed.target_ref})\n")
    show(chain, op_pub, "after deletion:")
    chain.entries.insert(1, removed)

    # ------------------------------------------------------------------- ACT 3
    banner("ACT 3 - the operator rebuilds the ENTIRE chain, minus one operation")
    print("  They control the workstation. They re-sign everything. Locally, the")
    print("  result is flawless - and this is where every single-machine ledger stops.\n")

    rewritten = Chain(chain_id=chain.chain_id)
    keep = [chain.entries[i] for i in (0, 1, 3)]     # entry 2 never happened
    for e in keep:
        rewritten.append(e.op_type, e.target_ref, e.timestamp, e.method,
                         e.result_hash, e.operator_decl, e.concur_decl,
                         e.custody_tier, op_key)
    for new, old in zip(rewritten.entries, keep):
        rewritten.attach_cosignature(new.seq, old.concur_sig, old.concur_key_id,
                                     old.witness_head_hash, old.witness_seq)

    show(rewritten, op_pub, "rewritten chain, local check:")
    print(f"  {'':34} 3 entries, every hash links, every signature valid\n")

    result = compare_witness_head(rewritten, witness_state)
    verdict = "DIVERGED" if result["diverged"] else "agrees"
    print(f"  {'now compare against the witness:':<34} {verdict}")
    print(f"  {'':34} {result['reason']}")
    if result["diverged"]:
        print(f"  {'':34} first divergence at sequence {result['at_seq']}")

    banner("WHAT THIS DOES AND DOES NOT PROVE")
    print("  Proven : nothing in this record was altered, reordered, or removed after")
    print("           it was written, and a second party on a separate machine agrees.")
    print("  NOT proven: that no operation was withheld from the record entirely.")
    print("           No single-operator ledger can prove that, and we do not claim it.")
    print()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
