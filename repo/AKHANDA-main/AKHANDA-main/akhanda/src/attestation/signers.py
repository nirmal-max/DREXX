"""Gap 7, key rotation, revocation, and unexplained signer changes.

THE GAP. `operator_key_id` is inside the preimage, so every entry states which key signed
it. Nothing anywhere said which keys were *supposed* to sign it. A chain in which entry 7
is signed by a key nobody recognises verifies perfectly, because each signature is checked
against whatever key the verifier was handed, and a verifier handed the attacker's key
confirms the attacker's signature with complete honesty.

Keys change for ordinary reasons. An examiner leaves. A laptop is reimaged. A token is
lost, or a passphrase is compromised and the right response is to rotate. Every one of
those is legitimate, and none of them should look identical to a silent substitution.

    The rule this module enforces: A SIGNER MAY CHANGE. A SIGNER MAY NOT CHANGE SILENTLY.

A rotation is announced by a SIGNER_CHANGE entry, signed by the OUTGOING key, naming the
incoming one. That ordering is the whole design, the outgoing key is the only party that
can still prove it was the legitimate holder, so it is the only party whose word means
anything about its own succession. An incoming key announcing itself proves nothing: that
is exactly what an attacker with a fresh keypair would do.

    build_roster(entries)                -> who signed what, in order
    detect_signer_changes(entries)       -> [SignerChange], each explained or not
    signer_change_record(...)            -> the document a SIGNER_CHANGE entry commits to
    verify_signer_continuity(entries, …) -> report; UNEXPLAINED is the finding that matters

WHAT THIS CANNOT DO, stated here rather than discovered later. It cannot detect a
compromise that happens before the first entry, because there is no earlier key to
contradict it. It cannot stop an attacker who holds the current private key from
announcing their own successor, a compromised key can sign a valid handover, and that
handover will verify. What it does is remove the SILENT path: after this, substituting a
signer requires either a signed announcement from the key being replaced, or a gap the
verifier names. Narrowing an attack to "you must compromise the current key and use it" is
the honest claim; "revocation prevents compromise" is not, and this module never says it.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterable, Optional

# The op_type that announces a rotation. It is a REFUSED-class entry in the sense that it
# performs no forensic work -- see tiers.is_performed -- but it is its own op_type because
# folding it into REFUSED would make "the signer changed" and "an operation was blocked"
# indistinguishable in the ledger, and they are different events.
SIGNER_CHANGE = "SIGNER_CHANGE"

# Why a key stopped being used. A closed vocabulary, for the same reason `outcome` is one:
# free text lets a compromise be recorded as a routine handover.
CHANGE_REASONS = (
    "ROTATION",      # planned, uneventful replacement
    "PERSONNEL",     # the examiner changed
    "COMPROMISE",    # the key is believed exposed -- the one nobody wants to write down
    "LOSS",          # the key is unrecoverable; no outgoing signature is possible
    "REISSUE",       # same holder, new key material (reimaged machine, new token)
)


@dataclass
class SignerChange:
    """One observed change of signing key, and whether the chain explains it."""
    at_seq: int
    from_key_id: str
    to_key_id: str
    explained: bool
    reason: str = ""
    announced_at_seq: Optional[int] = None
    detail: str = ""

    def to_dict(self) -> dict:
        return {"at_seq": self.at_seq, "from_key_id": self.from_key_id,
                "to_key_id": self.to_key_id, "explained": self.explained,
                "reason": self.reason, "announced_at_seq": self.announced_at_seq,
                "detail": self.detail}


def signer_change_record(*, from_key_id: str, to_key_id: str, reason: str,
                         declared_by: str, effective_from_seq: int,
                         note: str = "") -> dict:
    """The document a SIGNER_CHANGE entry commits to via its result_hash.

    `declared_by` is a human, not a key. A rotation is an administrative act with someone
    accountable for it, and recording only the key ids would produce a chain that can say
    a signer changed but not who decided that.
    """
    if reason not in CHANGE_REASONS:
        raise ValueError(f"reason must be one of {CHANGE_REASONS}; got {reason!r}. "
                         "Free text would let a compromise be filed as a routine handover.")
    if from_key_id == to_key_id:
        raise ValueError("a signer change must actually change the signer")
    return {
        "record_type": "SIGNER_CHANGE",
        "from_key_id": from_key_id,
        "to_key_id": to_key_id,
        "reason": reason,
        "declared_by": declared_by,
        "effective_from_seq": effective_from_seq,
        "note": note,
        "meaning": (
            "The key named in from_key_id stops being authoritative from "
            f"seq {effective_from_seq}. This entry is signed by the OUTGOING key, which "
            "is the only party that can still prove it was the legitimate holder. It does "
            "NOT prove the outgoing key was uncompromised when it signed: a compromised "
            "key can sign a valid handover. It proves the change was ANNOUNCED rather "
            "than made silently."
            if reason != "LOSS" else
            "The key named in from_key_id is unrecoverable, so this change CANNOT be "
            "signed by it. This record is therefore weaker than a normal rotation and is "
            "reported as an unexplained change unless corroborated out of band. Recording "
            "it is still better than the gap it replaces."
        ),
    }


def build_roster(entries: Iterable) -> dict:
    """Which key signed which entries, in the order they appear.

    Returns {key_id: {"first_seq", "last_seq", "count", "op_types"}}. Ordered by first
    appearance, because "which key came first" is the question every continuity check
    starts from.
    """
    roster: dict = {}
    for e in entries:
        kid = getattr(e, "operator_key_id", "") or ""
        rec = roster.setdefault(kid, {"first_seq": e.seq, "last_seq": e.seq,
                                      "count": 0, "op_types": set()})
        rec["last_seq"] = e.seq
        rec["count"] += 1
        rec["op_types"].add(e.op_type)
    for rec in roster.values():
        rec["op_types"] = sorted(rec["op_types"])
    return roster


def _announcements(entries: Iterable) -> dict:
    """SIGNER_CHANGE entries, keyed by the incoming key they authorise.

    An announcement is only counted when it is signed by the OUTGOING key. An entry that
    announces a handover while already being signed by the incoming key authorises
    nothing -- it is the attacker's own introduction letter, and accepting it would make
    the whole check decorative.
    """
    found: dict = {}
    for e in entries:
        if e.op_type != SIGNER_CHANGE:
            continue
        decl = getattr(e, "operator_decl", "") or ""
        signed_by = getattr(e, "operator_key_id", "") or ""
        to_key = ""
        for token in decl.replace(",", " ").split():
            if token.startswith("to="):
                to_key = token[3:]
        if not to_key or to_key == signed_by:
            continue
        found[to_key] = {"seq": e.seq, "signed_by": signed_by, "decl": decl}
    return found


def detect_signer_changes(entries: list) -> list:
    """Every point where the signing key changed, and whether the chain explains it."""
    changes: list = []
    announced = _announcements(entries)

    previous = ""
    for e in entries:
        kid = getattr(e, "operator_key_id", "") or ""
        if e.op_type == SIGNER_CHANGE:
            previous = previous or kid
            continue
        if previous and kid and kid != previous:
            ann = announced.get(kid)
            # An announcement explains the change only if it was signed by the key being
            # replaced and appeared BEFORE the new key started working. An announcement
            # that turns up afterwards is a retrospective note, not an authorisation.
            ok = bool(ann) and ann["signed_by"] == previous and ann["seq"] <= e.seq
            changes.append(SignerChange(
                at_seq=e.seq, from_key_id=previous, to_key_id=kid, explained=ok,
                reason=("announced" if ok else ""),
                announced_at_seq=(ann or {}).get("seq"),
                detail=("" if ok else _unexplained_detail(ann, previous)),
            ))
        if kid:
            previous = kid
    return changes


def _unexplained_detail(ann: Optional[dict], expected_signer: str) -> str:
    if ann is None:
        return ("no SIGNER_CHANGE entry authorises this key; the signer was substituted "
                "without announcement")
    if ann["signed_by"] != expected_signer:
        return (f"a SIGNER_CHANGE entry exists but was signed by {ann['signed_by']!r}, "
                f"not by the outgoing key {expected_signer!r}; a key cannot authorise "
                "its own succession")
    return ("the SIGNER_CHANGE entry appears after the new key had already signed; a "
            "retrospective note is not an authorisation")


def verify_signer_continuity(entries: list, expected_key_ids: Optional[set] = None) -> dict:
    """Full continuity report. Reports, never raises.

    `expected_key_ids`, when supplied, is the set the verifier obtained INDEPENDENTLY --
    from a witness, an anchor, or a case file. Checking a chain only against the keys the
    chain itself names is circular: it confirms the chain is consistent with itself, which
    a forged chain also is.
    """
    out: dict = {
        "ok": False, "entries": len(entries), "roster": {}, "changes": [],
        "unexplained": [], "unknown_keys": [], "checked_against_expected": False,
        "reason": "",
    }
    if not entries:
        out["reason"] = "empty chain: no signer to be continuous about"
        return out

    roster = build_roster(entries)
    out["roster"] = roster
    changes = detect_signer_changes(entries)
    out["changes"] = [c.to_dict() for c in changes]
    unexplained = [c for c in changes if not c.explained]
    out["unexplained"] = [c.to_dict() for c in unexplained]

    if expected_key_ids is not None:
        out["checked_against_expected"] = True
        out["unknown_keys"] = sorted(set(roster) - set(expected_key_ids) - {""})

    if unexplained:
        first = unexplained[0]
        out["reason"] = (
            f"{len(unexplained)} unexplained signer change(s); the first is at seq "
            f"{first.at_seq}, where signing moved from {first.from_key_id!r} to "
            f"{first.to_key_id!r}. {first.detail}. Every signature may still verify, "
            "that is the point: a verifier handed the substituted key confirms its "
            "signatures honestly, so the substitution is only visible as a change.")
    elif out["unknown_keys"]:
        out["reason"] = (
            f"all signer changes are announced, but {len(out['unknown_keys'])} key(s) in "
            f"this chain are not in the independently supplied set: {out['unknown_keys']}. "
            "The chain is internally consistent and still names a signer nobody else "
            "recognises.")
    elif len(roster) == 1:
        out["ok"] = True
        out["reason"] = f"one signer throughout, {len(entries)} entries"
    else:
        out["ok"] = True
        out["reason"] = (f"{len(roster)} signers, {len(changes)} change(s), all announced "
                         "by the outgoing key before the incoming key was used")

    if not out["checked_against_expected"] and out["ok"]:
        out["reason"] += (". NOTE: no independent key set was supplied, so this confirms "
                          "the chain is consistent with itself, which a forged chain "
                          "also would be.")
    return out
