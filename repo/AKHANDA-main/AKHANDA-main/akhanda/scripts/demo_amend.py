"""AMEND on stage: correct a forensic record without touching what it corrects.

Run:  set PYTHONPATH=src && python scripts/demo_amend.py

The scene it plays out is the one an examiner recognises. An operator records an erasure
against a device, and mistypes the serial number. The record is signed. It is linked. It
is correct in every respect except the one that matters.

Without a sanctioned correction path there are exactly two options, and both are bad:
leave a known-wrong record standing, or edit the JSON -- at which point the tool's own
verifier reports an honest correction as tampering. The absence of AMEND does not prevent
corrections. It just makes them look like forgery.
"""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from attestation import tiers
from attestation.core import AMEND_REASONS, Chain, verify_chain_report

# ASCII on purpose. Box-drawing characters garble on a console that is not UTF-8, and a
# demo that looks broken on someone else's machine is a demo that failed.
RULE = "=" * 78


def say(title: str) -> None:
    print(f"\n{RULE}\n{title}\n{RULE}")


def show(chain: Chain, pub) -> None:
    r = verify_chain_report(chain.entries, operator_pub=pub)
    for e in chain.entries:
        mark = "  <- superseded" if e.seq in r.amended_seqs else ""
        extra = ""
        if e.op_type == "AMEND":
            extra = f"  supersedes seq {e.amends_seq} ({e.amend_reason})"
        print(f"  seq {e.seq}  {e.op_type:<8} {e.outcome:<14} "
              f"{e.entry_hash[:16]}...{extra}{mark}")
    verdict = "VERIFIED" if r.ok else f"BROKEN at seq {r.broken_seq}: {r.reason}"
    print(f"\n  chain: {verdict}   signatures re-verified: {r.verified}/{r.total}")
    return r


def main() -> int:
    key = Ed25519PrivateKey.generate()
    pub = key.public_key()
    chain = Chain()

    say("1. The operator records an erasure -- and mistypes the serial number")
    wrong = {"device_serial": "WD-WX41A59K2P07", "method": "Clear", "passes": 1}
    chain.append(
        op_type="ERASE",
        target_ref="/dev/sdb",
        timestamp="2026-09-04T09:15:00Z",
        method="Clear",
        result_hash=hashlib.sha256(json.dumps(wrong, sort_keys=True).encode()).hexdigest(),
        operator_decl="Erasure of seized drive, single pass, read-back sampled",
        concur_decl="",
        custody_tier=tiers.SOFTWARE_KEY,
        operator_key=key,
        outcome="VERIFIED",
        place_ref="FSL Hyderabad, Room 3",
    )
    show(chain, pub)
    print(f"\n  the serial recorded was {wrong['device_serial']!r}")
    print("  the drive in the evidence bag reads  WD-WX41A59K2P97")

    say("2. What a tool WITHOUT an amendment path forces: edit the record")
    saved = chain.entries[0].target_ref
    chain.entries[0].target_ref = "/dev/sdb  (serial corrected)"
    r = show(chain, pub)
    print("\n  An honest correction is now indistinguishable from tampering.")
    print("  This is the false positive the absence of AMEND manufactures.")
    chain.entries[0].target_ref = saved       # put it back
    assert verify_chain_report(chain.entries, operator_pub=pub).ok

    say("3. What Akhanda does instead: append a correction, touch nothing")
    corrected = dict(wrong, device_serial="WD-WX41A59K2P97")
    before = chain.entries[0].entry_hash
    chain.amend(
        amends_seq=0,
        reason="TRANSCRIPTION_ERROR",
        operator_decl="Serial number was transcribed as ...2P07; the device reads ...2P97",
        timestamp="2026-09-04T09:41:00Z",
        operator_key=key,
        result_hash=hashlib.sha256(
            json.dumps(corrected, sort_keys=True).encode()).hexdigest(),
        place_ref="FSL Hyderabad, Room 3",
    )
    r = show(chain, pub)

    print(f"\n  seq 0 is byte-for-byte unchanged: {chain.entries[0].entry_hash == before}")
    print(f"  the chain still verifies:          {r.ok}")
    print(f"  the correction is visible:         seq {sorted(r.amended_seqs)} superseded")
    print("\n  Nothing was hidden. A reader sees the original, the correction, when it")
    print("  happened and why -- which is more than an edited record could ever show.")

    say("4. The amendment is welded to ONE entry")
    chain.entries[1].amends_seq = "0"          # unchanged value, but re-touched
    chain.entries[1].amends_hash = "ff" * 32   # point it at content seq 0 never had
    r2 = verify_chain_report(chain.entries, operator_pub=pub)
    print(f"  redirected the amendment -> {'BROKEN: ' + r2.reason if not r2.ok else 'still ok?!'}")
    print("\n  Both the position AND the content-hash of the superseded entry are inside")
    print("  the amendment's signed preimage, so it cannot be re-pointed at a different")
    print("  entry later -- not even by whoever signed it.")

    say("5. The reason is a closed vocabulary")
    print("  " + ", ".join(AMEND_REASONS))
    try:
        chain.amend(amends_seq=0, reason="fixed it", operator_decl="x",
                    timestamp="2026-09-04T10:00:00Z", operator_key=key,
                    result_hash="00" * 32)
    except ValueError as exc:
        print(f"\n  rejected 'fixed it': {exc}")
    print("\n  A correction carrying free text is an edit wearing a label.")
    print(RULE)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
