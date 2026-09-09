"""Case-level Merkle root over many per-device chains, Gap 6.

THE PROBLEM THIS CLOSES. A chain covers one device. A real case does not: a seizure
produces a laptop, two phones, four USB sticks and a NAS, and each gets its own chain
because each is examined separately, possibly by different people on different days.
Chain-per-device is correct, merging them into one ledger would force a strict global
ordering on operations that genuinely happened in parallel, and would make one device's
verification depend on another's.

But it leaves a hole exactly one level up. Chaining proves nothing was removed from the
MIDDLE of a device's history. It says nothing about a whole device being removed from the
CASE. Delete `usb_3.json` from the evidence folder and every surviving chain still
verifies perfectly, because nothing in a chain knows how many siblings it had. That is the
same omission attack the project exists to close, moved up one level of aggregation, and
solved the same way: bind the set, then put the binding somewhere the operator cannot
rewrite.

    case_root(chains)            -> the root over every device's head
    device_proof(chains, id)     -> audit path for one device
    verify_device(...)           -> recompute the root from that path alone
    build_manifest(...)          -> the document a case commits to
    verify_manifest(...)         -> re-derive it from the chains on disk

WHAT THIS IS NOT. It is not a second chain and it adds no new trust assumption. The case
root is a pure function of the device heads, so it can be recomputed by anyone holding the
same chains, including a defence expert who was given the evidence and wants to check
that nothing was dropped before it reached them. It becomes evidence only once it is
anchored (`anchor.ots.submit`) or co-signed by the witness, which is the same rule that
makes a chain head evidence rather than an assertion.

ORDERING IS PART OF THE COMMITMENT. Devices are sorted by device_id before hashing, so the
root does not depend on directory listing order or on which machine assembled it. Two
examiners with the same evidence get the same root, or the root would be useless for
exactly the comparison it exists to support.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Iterable, Optional

from anchor.ots import inclusion_proof, merkle_root, verify_inclusion
from attestation.core import _lp  # the same length-prefixing the entries use

CASE_VERSION = "1"

# Domain separation. A case leaf must never be confusable with an entry hash or with a
# Merkle node, or a value from one tree could be replayed as a value in another. Same
# reasoning as LEAF_PREFIX/NODE_PREFIX in anchor.ots, one level up.
CASE_LEAF_TAG = b"akhanda.case.device.v1"
CASE_ROOT_TAG = b"akhanda.case.root.v1"


class CaseError(Exception):
    """Raised when a case cannot be assembled honestly. Never for a verification result , 
    a failed verification is a report, not an exception."""


@dataclass
class DeviceRef:
    """One device's place in a case: which chain, how long it was, where it ended.

    `count` is here for the same reason the witness publishes its own count (G25): a head
    hash alone cannot distinguish a chain that legitimately ended at seq 4 from one
    truncated to seq 4. Committing to the length makes tail truncation of a device chain a
    contradiction with the case root, not merely an unverifiable claim.
    """
    device_id: str
    chain_id: str
    head_hash: str
    count: int
    label: str = ""

    def leaf(self) -> bytes:
        """The bytes this device contributes to the case tree.

        Length-prefixed, like everything else that enters a hash in this codebase. Joining
        these with a delimiter would let a device_id containing that delimiter forge a
        different device's leaf, the exact non-injective encoding bug the project's first
        coding rule exists to prevent.
        """
        return hashlib.sha256(
            CASE_LEAF_TAG
            + _lp(CASE_VERSION.encode())
            + _lp(self.device_id.encode())
            + _lp(self.chain_id.encode())
            + _lp(self.head_hash.encode())
            + _lp(str(self.count).encode())
        ).digest()

    def to_dict(self) -> dict:
        return {"device_id": self.device_id, "chain_id": self.chain_id,
                "head_hash": self.head_hash, "count": self.count, "label": self.label}


def device_refs(chains: dict) -> list[DeviceRef]:
    """`{device_id: Chain}` -> sorted DeviceRefs. Sorting is the canonicalisation."""
    refs = []
    for device_id, chain in chains.items():
        refs.append(DeviceRef(
            device_id=str(device_id),
            chain_id=chain.chain_id,
            head_hash=chain.head_hash(),
            count=len(chain.entries),
        ))
    refs.sort(key=lambda r: r.device_id)
    return refs


def case_root(chains: dict) -> bytes:
    """The root binding every device in this case. Empty case is an error, not a zero.

    A zero root for an empty case would be a value that verifies against nothing and looks
    like a real commitment, which is worse than refusing.
    """
    refs = device_refs(chains)
    if not refs:
        raise CaseError("a case with no devices has nothing to commit to")
    seen = [r.device_id for r in refs]
    if len(set(seen)) != len(seen):
        raise CaseError(f"duplicate device_id in case: {sorted(set(x for x in seen if seen.count(x) > 1))}")
    return hashlib.sha256(CASE_ROOT_TAG + merkle_root([r.leaf() for r in refs])).digest()


def device_proof(chains: dict, device_id: str) -> dict:
    """Audit path proving one device belongs to this case, without revealing the others.

    THE PRIVACY PROPERTY IS REAL AND USEFUL. A device can be shown to belong to a case by
    handing over its chain plus O(log n) sibling hashes. The other devices' contents, and
    even their identifiers, stay out of the disclosure, which matters when one drive in a
    seizure is released to its owner while the rest of the case is live.
    """
    refs = device_refs(chains)
    ids = [r.device_id for r in refs]
    if device_id not in ids:
        raise CaseError(f"{device_id!r} is not in this case; have {ids}")
    idx = ids.index(device_id)
    path = inclusion_proof([r.leaf() for r in refs], idx)
    return {
        "case_version": CASE_VERSION,
        "device": refs[idx].to_dict(),
        "index": idx,
        "device_count": len(refs),
        "path": [[sib.hex(), is_left] for sib, is_left in path],
        "case_root": case_root(chains).hex(),
    }


def verify_device(proof: dict, expected_root: Optional[str] = None) -> dict:
    """Recompute the case root from one device and its path. Reports, never raises.

    Returns {ok, reason, computed_root, matches_expected}. `expected_root` is the root the
    verifier obtained INDEPENDENTLY, from an anchor receipt or the witness, not the one
    carried inside the proof. A proof that only checks against its own embedded root
    checks nothing: whoever forged the proof wrote that field too.
    """
    if proof.get("case_version") != CASE_VERSION:
        return {"ok": False, "computed_root": "", "matches_expected": False,
                "reason": (f"case_version {proof.get('case_version')!r} is not "
                           f"{CASE_VERSION!r}; refused rather than mis-verified")}
    try:
        d = proof["device"]
        ref = DeviceRef(device_id=d["device_id"], chain_id=d["chain_id"],
                        head_hash=d["head_hash"], count=int(d["count"]))
        path = [(bytes.fromhex(sib), bool(is_left)) for sib, is_left in proof["path"]]
    except (KeyError, TypeError, ValueError) as exc:
        return {"ok": False, "computed_root": "", "matches_expected": False,
                "reason": f"malformed proof: {type(exc).__name__}: {exc}"}

    # verify_inclusion rebuilds the plain Merkle root; the case root adds its own tag.
    node = ref.leaf()
    plain = _root_from_path(node, path)
    computed = hashlib.sha256(CASE_ROOT_TAG + plain).digest().hex()

    embedded = proof.get("case_root", "")
    ok = bool(embedded) and computed == embedded
    matches = (expected_root is not None and computed == expected_root)

    if not ok:
        reason = ("the audit path does not rebuild the root stated in this proof; the "
                  "device does not belong to this case as described")
    elif expected_root is None:
        reason = ("path is internally consistent, but no independent root was supplied "
                  "to check it against, this is UNVERIFIED, not verified")
    elif matches:
        reason = (f"device {ref.device_id} is provably one of {proof.get('device_count')} "
                  "in the case committed to by the independent root")
    else:
        reason = ("the path rebuilds this proof's own root but NOT the independent root; "
                  "this proof describes a different case than the one anchored")

    return {"ok": ok and (expected_root is None or matches),
            "computed_root": computed, "matches_expected": matches, "reason": reason}


def _root_from_path(leaf: bytes, path: list) -> bytes:
    from anchor.ots import merkle_leaf, merkle_node
    node = merkle_leaf(leaf)
    for sibling, sibling_is_left in path:
        node = merkle_node(sibling, node) if sibling_is_left else merkle_node(node, sibling)
    return node


def build_manifest(chains: dict, case_id: str, examiner: str = "",
                   note: str = "") -> dict:
    """The document a case commits to. This is what gets anchored or co-signed.

    It names every device and the case root over them. Anchoring THIS, rather than each
    chain separately, is what makes 'one of the drives is missing' detectable: the root
    changes if the set changes, and the anchor is dated before the drive went missing.
    """
    refs = device_refs(chains)
    root = case_root(chains)
    return {
        "case_version": CASE_VERSION,
        "case_id": case_id,
        "examiner": examiner,
        "device_count": len(refs),
        "devices": [r.to_dict() for r in refs],
        "case_root": root.hex(),
        "total_entries": sum(r.count for r in refs),
        "note": note,
        "meaning": ("This root binds the SET of devices in this case. A device removed "
                    "from the case after this root was fixed changes the root, so the "
                    "removal is detectable, which chaining alone cannot do, because no "
                    "chain knows how many sibling chains it had. It becomes evidence "
                    "once anchored or co-signed; on its own it is a claim the operator "
                    "made about their own case."),
    }


def verify_manifest(manifest: dict, chains: dict) -> dict:
    """Re-derive the manifest from the chains actually on disk. Reports, never raises.

    Answers the question a case-level omission attack is designed to make unanswerable:
    are these the devices the case said it had, ending where it said they ended?
    """
    out: dict = {"ok": False, "case_id": manifest.get("case_id", ""),
                 "missing_devices": [], "extra_devices": [], "changed_devices": [],
                 "root_matches": False, "reason": ""}

    if manifest.get("case_version") != CASE_VERSION:
        out["reason"] = (f"case_version {manifest.get('case_version')!r} is not "
                         f"{CASE_VERSION!r}; refused rather than mis-verified")
        return out

    stated = {d["device_id"]: d for d in manifest.get("devices", [])}
    present = {r.device_id: r.to_dict() for r in device_refs(chains)}

    out["missing_devices"] = sorted(set(stated) - set(present))
    out["extra_devices"] = sorted(set(present) - set(stated))
    for did in sorted(set(stated) & set(present)):
        s, p = stated[did], present[did]
        if s["head_hash"] != p["head_hash"] or int(s["count"]) != int(p["count"]):
            out["changed_devices"].append({
                "device_id": did,
                "stated": {"head_hash": s["head_hash"], "count": s["count"]},
                "found": {"head_hash": p["head_hash"], "count": p["count"]},
            })

    try:
        out["root_matches"] = case_root(chains).hex() == manifest.get("case_root", "")
    except CaseError as exc:
        out["reason"] = str(exc)
        return out

    if out["missing_devices"]:
        out["reason"] = (f"{len(out['missing_devices'])} device(s) named in the manifest "
                         f"are not present: {out['missing_devices']}. This is the "
                         "case-level omission the root exists to catch.")
    elif out["changed_devices"]:
        out["reason"] = (f"{len(out['changed_devices'])} device chain(s) no longer end "
                         "where the manifest says they ended, entries were added or "
                         "removed after the case root was fixed.")
    elif out["extra_devices"]:
        out["reason"] = (f"{len(out['extra_devices'])} device(s) present but not in the "
                         "manifest: {}. Not necessarily tampering, a device examined "
                         "after the root was fixed looks exactly like this, but the "
                         "root no longer covers the evidence set."
                         .format(out["extra_devices"]))
    elif out["root_matches"]:
        out["ok"] = True
        out["reason"] = (f"all {len(present)} devices present and unchanged; the case "
                         "root re-derives exactly")
    else:
        out["reason"] = ("device set and heads match but the root does not re-derive, "
                         "the manifest's root was not computed from these devices")
    return out
