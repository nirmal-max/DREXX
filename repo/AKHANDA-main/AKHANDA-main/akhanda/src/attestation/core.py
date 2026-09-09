"""
Akhanda, the append-only, dual-signable, tamper-evident ledger.

This is the heart of the project. Every field is length-prefixed before hashing so that
two different sets of fields can never produce the same signing bytes. Do not replace
the length-prefix encoding with delimiter joining. See docs/ENGINEERING_RULES.md section 3, rule 1.

PROVENANCE (docs/ENGINEERING_RULES.md section 8): the injective-encoding discipline, the domain
separation, and the "verified vs unverifiable" split in the report are carried over
from AetherProof (Apache-2.0, sole author Pulkit Kr Srivastava), where each was written
in response to a real defect found under adversarial testing. New to Akhanda: the
chain_id binding, the dual-signature structure, the custody tier, the presence
reference, and the witness head record.

FORMAT FREEZE. ENTRY_VERSION is inside the preimage. If the field list ever changes,
bump the version and keep the old builder byte-exact, a fix that invalidates entries
already signed is worse than the defect it fixes.
"""

from __future__ import annotations
import hashlib
import json
import secrets
from dataclasses import dataclass, field, asdict
from typing import Optional

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey, Ed25519PublicKey,
)
from cryptography.exceptions import InvalidSignature

# toolref does NOT import core, so there is no cycle: it reads source text, it does not
# use the chain. Keeping the dependency one-directional is deliberate -- the thing that
# identifies the build must not depend on the thing whose behaviour it is identifying.
from attestation.toolref import tool_ref


ZERO_HASH = b"\x00" * 32
ENTRY_VERSION = "4"   # 4 adds place_ref and the three AMEND fields (see FIELDS_BY_VERSION)

# Domain separation tag. Every entry preimage starts with it, so bytes produced by this
# encoder can never be replayed as bytes produced by another part of the system (a
# witness head record, a Merkle node) that happens to hash the same material.
ENTRY_DOMAIN = b"akhanda.entry.v2"

# REFUSED is an operation that was BLOCKED before it happened, recorded so the refusal
# leaves a trace. Without it, a blocked operation is indistinguishable from an operation
# nobody ever attempted, which is the silent-omission hole the whole design exists to
# close. Adding permitted VALUES to these fields does not change HASHED_FIELDS, so the
# entry format is untouched and ENTRY_VERSION stays where it is.
# SIGNER_CHANGE announces a key rotation (see attestation.signers). It is its own
# op_type rather than a flavour of REFUSED because folding the two together would make
# "the signer changed" and "an operation was blocked" indistinguishable in the ledger,
# and they are different events with different remedies.
# AMEND corrects an earlier entry WITHOUT touching it. The superseded entry stays in the
# chain, unchanged, still hashing to its recorded value, because append-only is the whole
# security model, and suspending it to allow an edit would disable the linkage, the
# signature and the witness head in one move.
#
# It exists as a security control, not a convenience. A record with no legitimate
# correction path is a record that gets corrected illegitimately: the examiner who
# mistyped a serial number at 2 a.m. has no sanctioned option, so they edit the JSON, and
# our own divergence check then reports an honest correction as tampering. The ABSENCE of
# AMEND actively manufactures false positives, which is a worse failure than the gap it
# was trying to avoid.
OP_TYPES = ("ERASE", "RECOVER", "REFUSED", "SIGNER_CHANGE", "AMEND")

# WHY THE REASON IS A CLOSED VOCABULARY, exactly like op_type, method and outcome.
# A correction carrying free text is an edit wearing a label: two amendments that changed
# the same field for opposite motives would be indistinguishable to anyone reading the
# ledger, and the field would drift into a place to write an excuse. A fixed set makes
# "why" answerable by a machine, and forces an amendment that fits none of these to be
# discussed rather than quietly filed.
AMEND_REASONS = (
    "TRANSCRIPTION_ERROR",   # a value was typed or read wrongly (serial, model, target)
    "WRONG_TARGET",          # the entry names a device or path that was not the one worked on
    "INCOMPLETE_RECORD",     # a field was left empty that should have been filled
    "SUPERSEDED_RESULT",     # later analysis changed the result the entry committed to
    "CLERICAL",              # spelling, formatting, or a declaration's wording
)

# NotPerformed is the method of a REFUSED entry: the operation reached no NIST level
# because it never ran. It is not a weaker Clear; it is the absence of an operation.
METHODS = ("Clear", "Purge", "Destroy", "NotPerformed")

# HOW WELL the operation went. A closed vocabulary, validated like op_type and method.
#
# This is the 15th signed field, and it is signed for a reason. `verified` used to live
# only in the result record: an erase whose read-back sampling FAILED produced a ledger
# entry indistinguishable from a clean one, so `cli show` printed the same "ERASE Clear"
# line either way and the certificate summarised it as a success. The result record was
# hash-committed and therefore tamper-evident, but the entry, the thing a human reads
# and the certificate quotes, carried no signal at all. A tool whose entire pitch is that
# it refuses to overclaim was quietly overclaiming in its own ledger.
OUTCOMES = (
    "VERIFIED",       # completed, and its own verification passed
    "UNVERIFIED",     # completed, but the read-back / integrity check did NOT pass
    "PARTIAL",        # completed with known incompleteness (a truncated carve, a
                      # copy-on-write filesystem that may not have reached the blocks)
    "NOT_PERFORMED",  # nothing ran: REFUSED entries
)


def _lp(value: bytes) -> bytes:
    """Length-prefix a single field: 4-byte big-endian length, then the bytes."""
    return len(value).to_bytes(4, "big") + value


def _as_bytes(v) -> bytes:
    if isinstance(v, bytes):
        return v
    if isinstance(v, str):
        return v.encode("utf-8")
    if isinstance(v, int):
        return str(v).encode("utf-8")
    raise TypeError(f"unsupported field type: {type(v)}")


# The exact ordered set of fields that are hashed, PER VERSION. Order is part of the
# contract, and so is the version key.
#
# WHY THIS IS A MAP AND NOT A LIST ANY MORE. It used to be one global list, which meant
# adding a field silently changed how EVERY entry hashed, including entries written years
# earlier under the old field set. Those chains would not merely warn, they would report
# "hash mismatch", the exact signature of tampering, for the crime of being old. A format
# migration that makes authentic history look forged is not a migration; it is data loss
# with extra steps.
#
# Keyed by version, an entry is re-hashed with the field list it was WRITTEN under, so a
# v3 chain verifies forever under a v4 verifier. What is NOT weakened is the refusal to
# guess: a version this table does not contain is still rejected outright (see
# verify_chain_report), because the alternative is quietly mis-verifying an entry whose
# field list we do not know.
FIELDS_V3 = [
    "entry_version", "chain_id", "seq", "prev_hash", "op_type", "target_ref",
    "timestamp", "method", "result_hash", "operator_decl", "concur_decl",
    "custody_tier", "outcome", "presence_ref", "operator_key_id", "tool_ref",
]

# v4 appends four fields to v3 rather than reordering it, so the two encodings stay easy
# to compare by eye and a reviewer can see that nothing about v3 moved.
FIELDS_V4 = FIELDS_V3 + [
    "place_ref",      # BSA 2023 s.63(4) Schedule asks for the PLACE of the operation
    "amends_seq",     # the seq this entry supersedes; "" when not an amendment
    "amends_hash",    # that entry's entry_hash; "" when not an amendment
    "amend_reason",   # one of AMEND_REASONS; "" when not an amendment
]

FIELDS_BY_VERSION = {
    "3": FIELDS_V3,
    "4": FIELDS_V4,
}

KNOWN_VERSIONS = tuple(FIELDS_BY_VERSION)

# Kept as the current version's list so existing callers and the three-implementation
# tests keep reading one name for "the fields this build writes".
HASHED_FIELDS = FIELDS_BY_VERSION[ENTRY_VERSION]


def fields_for(version: str) -> list:
    """The hashed field list for a given entry_version, or a loud failure.

    Never falls back to the current version: an entry whose field list we cannot name is
    an entry we cannot honestly verify, and guessing produces a confident wrong answer.
    """
    try:
        return FIELDS_BY_VERSION[version]
    except KeyError:
        raise ValueError(
            f"entry_version {version!r} has no known field list "
            f"(this build knows {KNOWN_VERSIONS}); refusing to guess at its encoding"
        ) from None


# place_ref, amends_seq, amends_hash and amend_reason, added in ENTRY_VERSION 4.
#
# ALL FOUR ARE INSIDE THE PREIMAGE, and for the amendment fields that is the entire point.
# An amendment that named its target outside the signature could be redirected afterwards:
# the same signed correction, re-pointed at a different entry, with every signature still
# valid. Binding the superseded seq AND that entry's hash into the preimage means an
# amendment is welded to exactly one entry, and moving it invalidates it.
#
# Committing to the hash as well as the seq is not redundancy. A seq alone says "entry 4",
# and entry 4's content is precisely what an attacker rewriting history would change; the
# hash says WHICH entry 4, so an amendment cannot be inherited by a substituted one.
#
# place_ref rides this version bump rather than getting its own, because two format
# migrations cost twice the compatibility risk of one and this field was already overdue.

# tool_ref, the 16th field, added in ENTRY_VERSION 3.
#
# Every entry said what was done. None said what DID it. That left the first question
# asked of any automated forensic result unanswerable from the record itself: which build
# produced this, and is it the build that was validated? "The tool" is not an answer, and
# it stops being one the moment the code changes -- which it does, between validation and
# the case, between the first drive and the fortieth.
#
# IT IS INSIDE THE PREIMAGE, NOT BESIDE IT, for the same reason `outcome` had to move
# there (G2): a field describing the operation that lives outside the signature can be
# edited afterwards to make one build's output look like another's. The build identity is
# a claim the entry makes and signs, exactly like the key id beside it.
#
# THIS IS NOT A VALIDATION CLAIM. Naming a build does not certify it. What it does is make
# validation MEAN something: a validation result is about a specific digest, and now an
# entry can be checked against that digest instead of against a hope.


def key_id(public_key: Ed25519PublicKey) -> str:
    """Stable short identifier for a key: first 16 hex of SHA-256 over its raw bytes.

    Lets a verifier pick the right public key in one lookup instead of trying every key
    it holds, and, because it is inside the preimage, makes "which key signed this" a
    signed claim rather than a guess.
    """
    raw = public_key.public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    return hashlib.sha256(raw).hexdigest()[:16]


def new_chain_id() -> str:
    """A fresh chain identifier, bound into every entry of that chain."""
    return secrets.token_hex(8)


def encode_entry(fields: dict, version: Optional[str] = None) -> bytes:
    """Canonical, length-prefixed encoding of the hashed fields. Injective by design.

    The field list is chosen by `version`, defaulting to the entry's own `entry_version`
    so that re-hashing an old entry uses the encoding it was written under. Passing a
    version explicitly is for tests that need to pin one.
    """
    if version is None:
        version = str(fields.get("entry_version", ENTRY_VERSION))
    out = bytearray(ENTRY_DOMAIN)
    for name in fields_for(version):
        if name not in fields:
            raise KeyError(f"missing required field: {name}")
        out += _lp(_as_bytes(fields[name]))
    return bytes(out)


def entry_hash(fields: dict, version: Optional[str] = None) -> bytes:
    """SHA-256 over the canonical encoding."""
    return hashlib.sha256(encode_entry(fields, version)).digest()


@dataclass
class Entry:
    # --- signed fields (inside the preimage, in HASHED_FIELDS order) ---
    seq: int
    prev_hash: str          # hex
    op_type: str            # ERASE | RECOVER
    target_ref: str
    timestamp: str          # ISO-8601 UTC, the operator's own clock (see limits)
    method: str             # Clear | Purge | Destroy, what was ACTUALLY achieved
    result_hash: str        # hex, digest of the operation's own result record
    operator_decl: str
    concur_decl: str
    custody_tier: str       # see attestation.tiers
    outcome: str = "VERIFIED"   # see OUTCOMES, how well the operation actually went
    presence_ref: str = ""  # "<device>:<nonce>:<pre_hash_prefix>", "" when absent
    operator_key_id: str = ""
    tool_ref: str = ""      # "akhanda/<version>+<code_digest[:16]>", see toolref.py
    # --- added in ENTRY_VERSION 4 ---
    place_ref: str = ""     # where the operation happened; "" means not recorded
    amends_seq: str = ""    # seq of the entry this supersedes; "" when not an amendment
    amends_hash: str = ""   # entry_hash of that entry; "" when not an amendment
    amend_reason: str = ""  # one of AMEND_REASONS; "" when not an amendment
    chain_id: str = ""
    entry_version: str = ENTRY_VERSION

    # --- attached after signing (NOT inside the preimage) ---
    entry_hash: str = ""         # hex
    operator_sig: str = ""       # hex
    concur_sig: str = ""         # hex, empty until the witness co-signs
    concur_key_id: str = ""      # which witness key produced concur_sig
    # Post-quantum signatures over the SAME entry hash. Attached after signing, exactly
    # like operator_sig and concur_sig, so they need no hashed field and no ENTRY_VERSION
    # bump -- an existing verifier reads a PQ-signed chain unchanged. pq_algorithm is
    # recorded SEPARATELY from the signature so that an entry naming an algorithm while
    # carrying no signature for it is detectable as STRIPPED rather than merely absent.
    pq_algorithm: str = ""       # e.g. "ML-DSA-65"; empty means no PQ layer
    operator_pq_sig: str = ""    # hex
    concur_pq_sig: str = ""      # hex, when the witness also signs post-quantum
    witness_head_hash: str = ""  # the witness's own head after co-signing this entry
    witness_seq: int = -1        # position in the witness's independent record
    anchor_ref: str = ""         # path of the .ots proof covering this entry, if any

    def hashed_fields(self) -> dict:
        """This entry's signed fields, under the field list of ITS OWN version.

        Reading the version off the entry rather than off the build is what lets a v4
        verifier re-hash a v3 entry correctly instead of appending four fields that were
        never signed and calling the mismatch tampering.
        """
        return {name: getattr(self, name) for name in fields_for(self.entry_version)}

    def recompute_hash(self) -> str:
        return entry_hash(self.hashed_fields(), self.entry_version).hex()

    def is_amendment(self) -> bool:
        return self.op_type == "AMEND"

    def pre_hash(self) -> str:
        """The entry's hash computed with `presence_ref` empty.

        This exists to break a genuine circularity. `presence_ref` is inside the preimage,
        so `entry_hash` cannot be known until the human has already confirmed, which means
        the final hash is exactly the one value we cannot show them. Showing them something
        else and calling it "the value being signed" was the defect.

        The pre-hash is the value they DO see, it is derivable by anyone holding the entry
        (set presence_ref to "" and re-hash), and the device binds its confirmation to it.
        So the chain commits to both: the pre-hash the human read, and the final hash that
        covers their token.
        """
        fields = self.hashed_fields()
        fields["presence_ref"] = ""
        return entry_hash(fields, self.entry_version).hex()

    def is_dual_signed(self) -> bool:
        return bool(self.operator_sig) and bool(self.concur_sig)


class Chain:
    """An append-only ledger of Entry objects."""

    def __init__(self, chain_id: Optional[str] = None) -> None:
        self.entries: list[Entry] = []
        self.chain_id = chain_id or new_chain_id()

    def head_hash(self) -> str:
        if not self.entries:
            return ZERO_HASH.hex()
        return self.entries[-1].entry_hash

    def append(
        self,
        op_type: str,
        target_ref: str,
        timestamp: str,
        method: str,
        result_hash: str,
        operator_decl: str,
        concur_decl: str,
        custody_tier: str,
        operator_key: Ed25519PrivateKey,
        presence_ref: str = "",
        outcome: str = "VERIFIED",
        presence_fn=None,
        place_ref: str = "",
        amends_seq: str = "",
        amends_hash: str = "",
        amend_reason: str = "",
    ) -> Entry:
        if method not in METHODS:
            raise ValueError(
                f"method must be one of {METHODS}; got {method!r}. Record what was "
                "achieved, never what sounds strongest (docs/ENGINEERING_RULES.md 3, rule 2)."
            )
        if op_type not in OP_TYPES:
            raise ValueError(f"op_type must be one of {OP_TYPES}; got {op_type!r}")
        if outcome not in OUTCOMES:
            raise ValueError(
                f"outcome must be one of {OUTCOMES}; got {outcome!r}. An operation whose "
                "verification failed must say so in the entry, not only in the result "
                "record (docs/ENGINEERING_RULES.md 3, rule 7)."
            )

        seq = len(self.entries)
        prev_hash = self.head_hash()

        # TWO-PHASE PRESENCE BINDING, and the ordering is the whole point.
        #
        # `presence_ref` is inside the preimage, so the final entry hash cannot exist
        # until the human has already pressed the button, which makes the final hash
        # precisely the one value we cannot show them. The old code dodged that by
        # displaying a prefix of the *result* digest, a value that is never signed, while
        # claiming in its own docstring that the operator was seeing the entry hash.
        #
        # Instead: build the entry with presence_ref empty, hash it, show the human THAT
        # (the pre-hash), and let the device bind its token to it. The final hash then
        # covers the token. Both values are recoverable from the stored entry, so
        # `verify_presence_binding` can check the human approved these bytes and not some
        # others.
        #
        # This lives here rather than in the CLI so there is one implementation of the
        # ordering, not one per caller.
        if presence_fn is not None:
            probe = Entry(
                seq=seq, prev_hash=prev_hash, op_type=op_type, target_ref=target_ref,
                timestamp=timestamp, method=method, result_hash=result_hash,
                operator_decl=operator_decl, concur_decl=concur_decl,
                custody_tier=custody_tier, outcome=outcome, presence_ref="",
                operator_key_id=key_id(operator_key.public_key()),
                chain_id=self.chain_id, tool_ref=tool_ref(),
                place_ref=place_ref, amends_seq=amends_seq,
                amends_hash=amends_hash, amend_reason=amend_reason,
            )
            presence_ref = presence_fn(probe.pre_hash()) or ""

        e = Entry(
            seq=seq, prev_hash=prev_hash, op_type=op_type, target_ref=target_ref,
            timestamp=timestamp, method=method, result_hash=result_hash,
            operator_decl=operator_decl, concur_decl=concur_decl,
            custody_tier=custody_tier, outcome=outcome, presence_ref=presence_ref,
            operator_key_id=key_id(operator_key.public_key()),
            chain_id=self.chain_id,
            place_ref=place_ref, amends_seq=amends_seq,
            amends_hash=amends_hash, amend_reason=amend_reason,
            # The build identity is read HERE, once, at the moment of signing. A caller
            # cannot supply it: a tool_ref passed in by the operator would be a claim
            # about the tool made by the party the tool exists to constrain.
            tool_ref=tool_ref(),
        )
        h = entry_hash(e.hashed_fields())
        e.entry_hash = h.hex()
        e.operator_sig = operator_key.sign(h).hex()
        self.entries.append(e)
        return e

    def amend(
        self,
        amends_seq: int,
        reason: str,
        operator_decl: str,
        timestamp: str,
        operator_key: Ed25519PrivateKey,
        result_hash: str,
        concur_decl: str = "",
        custody_tier: str = "SOFTWARE_KEY",
        place_ref: str = "",
        presence_ref: str = "",
        presence_fn=None,
    ) -> Entry:
        """Append an AMEND entry that supersedes an earlier one, without touching it.

        The superseded entry stays exactly as it was and keeps verifying. What changes is
        that the chain now also contains a signed statement that it was corrected, by whom,
        when, and for which of a fixed set of reasons, so a reader sees the correction
        happened rather than only its result.

        `result_hash` commits to the corrected values, held in the amendment's own result
        record. The corrected content is therefore hash-committed exactly like any other
        operation's result, instead of living as free text in the entry.

        method is always NotPerformed and outcome always NOT_PERFORMED: an amendment
        erases nothing and recovers nothing. Claiming otherwise would let a correction
        inflate the count of forensic work the chain records.
        """
        if reason not in AMEND_REASONS:
            raise ValueError(
                f"amend reason must be one of {AMEND_REASONS}; got {reason!r}. "
                "A correction with a free-text reason is an edit wearing a label."
            )
        if not 0 <= amends_seq < len(self.entries):
            raise ValueError(
                f"cannot amend seq {amends_seq}: this chain has "
                f"{len(self.entries)} entries (0..{len(self.entries) - 1})"
            )
        target = self.entries[amends_seq]
        if target.op_type == "AMEND":
            # Amending an amendment would build a correction chain whose meaning depends
            # on traversal order. Correct the ORIGINAL entry again instead: two
            # amendments of one entry are ordered by seq and unambiguous.
            raise ValueError(
                f"seq {amends_seq} is itself an AMEND. Amend the original entry "
                f"({target.amends_seq or 'the one it supersedes'}) again rather than "
                "chaining corrections."
            )
        return self.append(
            op_type="AMEND",
            target_ref=target.target_ref,
            timestamp=timestamp,
            method="NotPerformed",
            result_hash=result_hash,
            operator_decl=operator_decl,
            concur_decl=concur_decl,
            custody_tier=custody_tier,
            operator_key=operator_key,
            presence_ref=presence_ref,
            outcome="NOT_PERFORMED",
            presence_fn=presence_fn,
            place_ref=place_ref,
            # Both the position AND the content-hash of the superseded entry go inside the
            # preimage, welding this amendment to exactly one entry.
            amends_seq=str(amends_seq),
            amends_hash=target.entry_hash,
            amend_reason=reason,
        )

    def attach_cosignature(
        self,
        seq: int,
        concur_sig_hex: str,
        concur_key_id: str = "",
        witness_head_hash: str = "",
        witness_seq: int = -1,
    ) -> None:
        """Attach the witness node's signature over the same entry_hash, plus the
        witness's own head record, the part a single-machine ledger cannot produce."""
        e = self.entries[seq]
        e.concur_sig = concur_sig_hex
        e.concur_key_id = concur_key_id
        e.witness_head_hash = witness_head_hash
        e.witness_seq = witness_seq

    def entry_hashes(self) -> list[bytes]:
        return [bytes.fromhex(e.entry_hash) for e in self.entries]

    def to_json(self) -> str:
        return json.dumps(
            {"chain_id": self.chain_id, "entries": [asdict(e) for e in self.entries]},
            indent=2,
        )

    @classmethod
    def from_json(cls, text: str) -> "Chain":
        data = json.loads(text)
        c = cls(chain_id=data["chain_id"])
        known = set(Entry.__dataclass_fields__)
        for row in data["entries"]:
            clean = {k: v for k, v in row.items() if k in known}
            for num in ("seq", "witness_seq"):
                if num in clean and clean[num] is not None:
                    clean[num] = int(clean[num])
            c.entries.append(Entry(**clean))
        return c


@dataclass
class ChainReport:
    """Outcome of a verification walk.

    Separates "this entry is forged" from "I cannot check this entry", which a single
    bool cannot express. Conflating them makes an authentic chain look tampered after a
    routine key rotation, a false positive AetherProof hit and fixed.
    """
    total: int = 0
    verified: int = 0                                        # operator sig re-checked
    dual_signed: int = 0                                     # operator AND witness present
    concur_verified: int = 0                                 # witness sig re-checked
    unverifiable: list[tuple] = field(default_factory=list)  # [(seq, key_id, why)]
    # Sequence numbers that a later AMEND supersedes. Collected during the walk so a
    # certificate can mark a corrected entry as corrected. It is NOT a list of problems:
    # a superseded entry is still authentic and still verifies, that is the design.
    amended_seqs: set = field(default_factory=set)
    broken_seq: Optional[int] = None
    reason: str = ""

    # Which layers actually RAN. Without these a caller cannot tell "every signature
    # checked out" from "no key was available so nothing was checked", and the
    # certificate printed the first sentence for the second situation.
    operator_layer: bool = False
    concur_layer: bool = False

    @property
    def ok(self) -> bool:
        return self.broken_seq is None

    @property
    def signatures_checked(self) -> bool:
        """True only when at least one signature was actually re-verified."""
        return self.verified > 0 or self.concur_verified > 0

    def fail(self, seq: int, reason: str) -> "ChainReport":
        self.broken_seq = seq
        self.reason = reason
        return self

    def __bool__(self) -> bool:
        return self.ok

    def __repr__(self) -> str:
        if not self.ok:
            return f"ChainReport(BROKEN at seq {self.broken_seq}: {self.reason})"
        tail = f", {len(self.unverifiable)} unverifiable" if self.unverifiable else ""
        return (f"ChainReport(ok, {self.total} entries, {self.verified} verified, "
                f"{self.dual_signed} dual-signed{tail})")


PRESENCE_REF_PARTS = 3          # "<device_id>:<nonce>:<pre_hash_prefix>"


def verify_presence_binding(entry: "Entry") -> tuple[bool, str]:
    """Does this entry's presence claim actually bind to what the human was shown?

    Returns (ok, reason). An empty `presence_ref` is fine, it means no device confirmed,
    which is an honest lower tier, not a failure.

    A non-empty one must carry the prefix of the entry's own pre-hash. That is what makes
    the presence attestation checkable rather than decorative: before this, an entry could
    claim PRESENCE_CONFIRMED with any string at all in the field, and nothing in the
    verifier could tell that the human had been shown a completely different value.
    """
    if not entry.presence_ref:
        return True, "no presence device confirmed this entry"

    parts = entry.presence_ref.split(":")
    if len(parts) != PRESENCE_REF_PARTS:
        return False, ("presence_ref is not <device_id>:<nonce>:<pre_hash_prefix>; "
                       "the presence claim cannot be checked")

    _device, _nonce, shown = parts
    if not shown:
        return False, "presence_ref carries no pre-hash prefix"

    expected = entry.pre_hash()
    if not expected.startswith(shown):
        return False, ("the value confirmed on the presence device does not match this "
                       "entry's pre-hash: the human approved different bytes")
    return True, "presence confirmation binds to this entry's pre-hash"


def verify_chain_report(
    entries: list[Entry],
    operator_pub: Optional[Ed25519PublicKey] = None,
    concur_pub: Optional[Ed25519PublicKey] = None,
    *,
    require_dual: bool = False,
) -> ChainReport:
    """Walk the chain and report exactly what held and what did not.

    Key-free layer (always runs): seq contiguous from 0, chain_id constant, prev_hash
    links, and each entry re-hashes to its stated entry_hash. This catches edits,
    reordering, and deletion from the middle WITHOUT any key, so a key rotation never
    false-flags an authentic chain.

    Key-bound layer (when a public key is given): the Ed25519 signatures are
    re-verified. This is what catches a forger who rewrote the content AND recomputed
    every hash, they still cannot reproduce the signature.

    KNOWN LIMIT, stated because an unstated gap is a claim: dropping the TAIL leaves a
    shorter self-consistent chain that this walk cannot distinguish from a chain that
    was always that length. The witness node's independent head record is what closes
    it, see witness.client.compare_witness_head. docs/ENGINEERING_RULES.md section 6.
    """
    report = ChainReport(
        total=len(entries),
        operator_layer=operator_pub is not None,
        concur_layer=concur_pub is not None,
    )
    if not entries:
        return report

    chain_id = entries[0].chain_id
    expected_prev = ZERO_HASH.hex()

    for i, e in enumerate(entries):
        if e.seq != i:
            return report.fail(e.seq, f"seq out of order at index {i}")
        if e.chain_id != chain_id:
            return report.fail(e.seq, "entry belongs to a different chain_id")
        if e.entry_version not in FIELDS_BY_VERSION:
            # Loudly, not silently. A verifier that quietly mis-verifies an entry written
            # under a different field list is worse than one that stops and says so.
            #
            # The test is membership, not equality: a version we HOLD THE FIELD LIST FOR
            # can be verified exactly, so refusing it would discard authentic history for
            # no security gain. A version we do not know is still refused outright.
            return report.fail(
                e.seq,
                f"entry_version {e.entry_version!r} is not a version this verifier "
                f"understands ({KNOWN_VERSIONS!r}); refusing to guess at its field list")
        if e.prev_hash != expected_prev:
            return report.fail(e.seq, "prev_hash does not link to previous entry")

        if e.recompute_hash() != e.entry_hash:
            return report.fail(e.seq, "entry content altered: hash mismatch")

        # --- amendment integrity -------------------------------------------------
        # An AMEND must name a real, earlier entry AND that entry's hash. Both are inside
        # its preimage, so these checks cannot be satisfied by editing the entry after the
        # fact, they either held when it was signed or the hash check above already failed.
        if e.op_type == "AMEND":
            if not e.amends_seq or not e.amends_hash:
                return report.fail(
                    e.seq, "AMEND entry does not name the entry it supersedes")
            if e.amend_reason not in AMEND_REASONS:
                return report.fail(
                    e.seq,
                    f"AMEND reason {e.amend_reason!r} is not one of {AMEND_REASONS}")
            try:
                target = int(e.amends_seq)
            except ValueError:
                return report.fail(e.seq, f"AMEND amends_seq {e.amends_seq!r} is not an integer")
            if not 0 <= target < i:
                # Forward or self references would let an amendment describe an entry that
                # did not exist when it was signed, which is a claim about the future.
                return report.fail(
                    e.seq,
                    f"AMEND supersedes seq {target}, which is not an earlier entry in this chain")
            if entries[target].entry_hash != e.amends_hash:
                return report.fail(
                    e.seq,
                    f"AMEND names seq {target} but commits to a different entry_hash than "
                    "that entry actually has: the amendment has been redirected")
            report.amended_seqs.add(target)
        elif e.amends_seq or e.amends_hash or e.amend_reason:
            # Amendment fields on a non-AMEND entry would let a correction hide inside an
            # ordinary operation, where no reader would look for it.
            return report.fail(
                e.seq,
                f"{e.op_type} entry carries amendment fields; only AMEND may name a "
                "superseded entry")

        if operator_pub is not None:
            if key_id(operator_pub) != e.operator_key_id:
                report.unverifiable.append(
                    (e.seq, e.operator_key_id, "no operator key held for this entry"))
            else:
                try:
                    operator_pub.verify(
                        bytes.fromhex(e.operator_sig), bytes.fromhex(e.entry_hash))
                    report.verified += 1
                except (InvalidSignature, ValueError):
                    return report.fail(e.seq, "operator signature invalid")

        # A presence claim that does not bind to what the human saw is worse than no
        # presence claim, because it reads as stronger custody than was actually had.
        presence_ok, presence_why = verify_presence_binding(e)
        if not presence_ok:
            return report.fail(e.seq, presence_why)

        if e.is_dual_signed():
            report.dual_signed += 1
        elif require_dual:
            return report.fail(e.seq, "missing concurring signature")

        if concur_pub is not None and e.concur_sig:
            # Mirrors the operator branch: a witness key we were not given is reported
            # as unverifiable (the witness legitimately rotates its key), while a key we
            # DO hold that rejects the signature is a forgery and fails the chain.
            if e.concur_key_id and key_id(concur_pub) != e.concur_key_id:
                report.unverifiable.append(
                    (e.seq, e.concur_key_id, "no witness key held for this entry"))
            else:
                try:
                    concur_pub.verify(
                        bytes.fromhex(e.concur_sig), bytes.fromhex(e.entry_hash))
                    report.concur_verified += 1
                except (InvalidSignature, ValueError):
                    return report.fail(e.seq, "concurring signature invalid")

        expected_prev = e.entry_hash

    return report


def verify_chain(
    entries: list[Entry],
    operator_pub: Optional[Ed25519PublicKey] = None,
    concur_pub: Optional[Ed25519PublicKey] = None,
) -> tuple[bool, Optional[int], str]:
    """Compact form of verify_chain_report: (ok, broken_seq, reason).

    Kept because the demo script and the console read it. New code should prefer the
    report, it distinguishes unverifiable from forged.
    """
    require_dual = concur_pub is not None
    r = verify_chain_report(entries, operator_pub, concur_pub, require_dual=require_dual)
    return (r.ok, r.broken_seq, r.reason if not r.ok else "chain verified")
