"""
Witness client, the workstation side of the Pi witness node. OWNER: lead.

Contract (mirrors src/witness/node.py):
    cosign(seq, entry_hash) -> {"ok", "concur_sig", "witness_head_hash",
                                "witness_seq", "concur_key_id", "reason"}
    head()                  -> {"ok", "head_hash", "seq", "count", "reason"}
    pubkey()                -> Ed25519PublicKey | None
    compare_witness_head(chain, witness_head) -> divergence report

WHY THIS MODULE IS THE ARGUMENT. A chain on one machine proves nothing was altered
after being written. It cannot prove nothing was withheld, and it cannot detect an
operator who rewrites the WHOLE chain from entry zero, the rewrite is internally
consistent. The witness keeps its own head record on a machine the workstation cannot
write to. When the workstation's recomputed head no longer matches the witness's head
for the same sequence, the rewrite is visible. That divergence is the property no
single-machine ledger can offer, and detecting it is the entire job of this file.

WHAT IT STILL DOES NOT PROVE (docs/ENGINEERING_RULES.md section 6): the witness only knows about entries
it was ASKED to co-sign. An operator who never submits an entry leaves no trace of it
here. Integrity, not completeness.

Degrades cleanly: no Pi on the LAN is a lower custody tier, never a crash.
"""

from __future__ import annotations
import json
import urllib.error
import urllib.parse
import urllib.request
from typing import Optional

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

DEFAULT_BASE = "http://raspberrypi.local:8000"
TIMEOUT_S = 5.0

# THE WITNESS IS REACHED OVER HTTP AND NOTHING ELSE.
#
# `urlopen` honours every scheme urllib knows, `file://` included. The witness URL is
# configuration -- a CLI flag, an environment variable, a saved profile -- so a URL the
# operator does not control, or mistypes, decides what gets opened. Pointed at
# `file:///path/to/anything`, the client would read a local file and hand it back as a
# witness response: the operator could then supply their own co-signature record from a
# file they wrote, and the "independent second party" would be a path on their own disk.
#
# That is the exact failure the witness exists to prevent, reachable through the transport
# rather than the crypto. Found by bandit B310, and it was a real finding rather than
# noise.
ALLOWED_SCHEMES = ("http", "https")


class WitnessTransportRefused(Exception):
    """The witness URL is not something this client is willing to open."""


def _check_url(url: str) -> str:
    """Reject any scheme that is not HTTP(S), before urlopen ever sees it."""
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme not in ALLOWED_SCHEMES:
        raise WitnessTransportRefused(
            f"refusing to open {url!r}: scheme {parsed.scheme!r} is not one of "
            f"{ALLOWED_SCHEMES}. A witness is reached over the network; a witness read "
            "from a local file is the operator co-signing their own work.")
    if not parsed.netloc:
        raise WitnessTransportRefused(
            f"refusing to open {url!r}: no host. A witness with no host is not a second "
            "machine.")
    return url


def _post(url: str, payload: dict, timeout: float) -> dict:
    req = urllib.request.Request(
        _check_url(url), data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"}, method="POST",
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 - scheme checked
        return json.loads(resp.read().decode("utf-8"))


def _get(url: str, timeout: float) -> dict:
    with urllib.request.urlopen(_check_url(url),  # noqa: S310 - scheme checked above
                                timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8"))


class WitnessClient:
    """HTTP client for the witness node. Every method degrades instead of raising."""

    def __init__(self, base_url: str = DEFAULT_BASE, timeout: float = TIMEOUT_S):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout

    def cosign(self, seq: int, entry_hash: str) -> dict:
        """Ask the witness to counter-sign this entry hash and extend its own record."""
        try:
            data = _post(f"{self.base_url}/witness/cosign",
                         {"seq": seq, "entry_hash": entry_hash}, self.timeout)
        except (urllib.error.URLError, OSError, ValueError) as exc:
            return {"ok": False, "concur_sig": "", "witness_head_hash": "",
                    "witness_seq": -1, "concur_key_id": "",
                    "reason": f"witness unreachable at {self.base_url}: {exc}"}
        return {
            "ok": bool(data.get("concur_sig")),
            "concur_sig": data.get("concur_sig", ""),
            "witness_head_hash": data.get("witness_head_hash", ""),
            "witness_seq": int(data.get("witness_seq", -1)),
            "concur_key_id": data.get("concur_key_id", ""),
            "reason": "co-signed by the witness node",
        }

    def head(self) -> dict:
        try:
            data = _get(f"{self.base_url}/witness/head", self.timeout)
        except (urllib.error.URLError, OSError, ValueError) as exc:
            return {"ok": False, "head_hash": "", "seq": -1, "count": 0,
                    "reason": f"witness unreachable at {self.base_url}: {exc}"}
        return {"ok": True, "head_hash": data.get("head_hash", ""),
                "seq": int(data.get("seq", -1)), "count": int(data.get("count", 0)),
                "reason": "witness head read"}

    def pubkey(self) -> Optional[Ed25519PublicKey]:
        """The witness's concurring public key, or None if unreachable."""
        try:
            data = _get(f"{self.base_url}/witness/pubkey", self.timeout)
            return Ed25519PublicKey.from_public_bytes(bytes.fromhex(data["pubkey_hex"]))
        except Exception:
            return None


def witness_head_chain(entry_hashes: list[str]) -> str:
    """Recompute what the witness's head SHOULD be for this list of entry hashes.

    Must stay byte-identical to node.py's own head computation. It is deliberately a
    different construction from the entry chain, the witness is attesting to the
    sequence of hashes it was shown, not re-deriving the operator's records.
    """
    import hashlib
    head = "00" * 32
    for h in entry_hashes:
        head = hashlib.sha256((head + h).encode()).hexdigest()
    return head


def compare_witness_head(chain, witness: dict) -> dict:
    """Compare the workstation's chain against the witness's independent head.

    This is the check that catches a full-chain rewrite. The operator can regenerate
    every entry, every hash, and every one of their own signatures, and the head the
    witness recorded will no longer match, because the witness signed the ORIGINAL
    hashes on a machine the operator did not write to.

    Returns:
        {"checked": bool, "diverged": bool, "at_seq": int|None, "reason": str}

    `checked=False` means the witness was unreachable or has no record. That is
    reported as unchecked, never as agreement, an absent witness must not read as a
    passing check.
    """
    if not witness.get("ok"):
        return {"checked": False, "diverged": False, "at_seq": None,
                "reason": witness.get("reason", "witness unavailable")}

    cosigned = [e for e in chain.entries if e.concur_sig]
    witness_count = int(witness.get("count", 0))

    # TRUNCATION CHECK, AND IT RUNS FIRST.
    #
    # The witness counts what it signed. The workstation holds what it still shows. If
    # the witness counted more than the workstation shows, entries left the workstation
    # chain after the witness had already recorded them, and no amount of internal
    # consistency on this side can explain that away: a truncated chain re-hashes
    # perfectly, links perfectly, and verifies perfectly. Only an outside count catches
    # it. This is the whole reason the second machine exists.
    #
    # WHY IT COMES BEFORE THE `not cosigned` BRANCH. That branch used to be reached
    # first, and it reported checked=False, "no entry was ever co-signed", which is
    # indistinguishable from an honest chain that simply never used a witness. So an
    # operator who truncated back past the FIRST co-signature turned the strongest
    # tampering signal into silence, and did it by deleting MORE rather than less.
    # Deleting more must never produce a weaker verdict than deleting less.
    if witness_count > len(cosigned):
        missing = witness_count - len(cosigned)
        return {"checked": True, "diverged": True,
                "at_seq": cosigned[-1].seq if cosigned else None,
                "reason": (f"the witness independently counter-signed {witness_count} "
                           f"entries; this chain shows {len(cosigned)}. "
                           f"{missing} co-signed "
                           f"{'entry has' if missing == 1 else 'entries have'} been "
                           "removed from the workstation chain after co-signing")}

    if not cosigned:
        # witness_count is 0 here, so the witness agrees nothing was ever co-signed.
        # Genuinely unchecked, and reported as unchecked, never as agreement.
        return {"checked": False, "diverged": False, "at_seq": None,
                "reason": "no entry in this chain was ever co-signed"}

    # Recompute the witness head from the hashes the workstation now holds.
    expected = witness_head_chain([e.entry_hash for e in cosigned])
    actual = witness.get("head_hash", "")

    if expected == actual:
        return {"checked": True, "diverged": False, "at_seq": None,
                "reason": f"witness head agrees over {len(cosigned)} co-signed entries"}

    # Walk forward to name the first entry where the two records part company.
    for e in cosigned:
        if e.witness_head_hash:
            recomputed = witness_head_chain(
                [x.entry_hash for x in cosigned if x.witness_seq <= e.witness_seq])
            if recomputed != e.witness_head_hash:
                return {"checked": True, "diverged": True, "at_seq": e.seq,
                        "reason": ("workstation chain diverges from the witness record: "
                                   "these entries were rewritten after co-signing")}

    return {"checked": True, "diverged": True, "at_seq": cosigned[-1].seq,
            "reason": ("workstation head does not match the witness head; the witness "
                       "holds a record the workstation cannot reproduce")}
