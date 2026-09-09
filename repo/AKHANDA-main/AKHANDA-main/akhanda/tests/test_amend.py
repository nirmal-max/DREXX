"""AMEND, the correction operation, and the v3 -> v4 migration it required.

Two things are under test and the second matters more than the first:

  1. An amendment does what it claims: names one earlier entry, is welded to it, uses a
     closed reason vocabulary, and never mutates what it supersedes.
  2. Adding four signed fields did NOT break chains written under the old field list.
     A format migration that makes authentic history look forged is worse than the gap
     it closed, so the v3 fixture below is the real regression guard.
"""

from __future__ import annotations

import json

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from attestation import tiers
from attestation.core import (
    AMEND_REASONS,
    ENTRY_VERSION,
    FIELDS_BY_VERSION,
    FIELDS_V3,
    FIELDS_V4,
    Chain,
    encode_entry,
    fields_for,
    verify_chain_report,
)


def _key() -> Ed25519PrivateKey:
    return Ed25519PrivateKey.generate()


def _chain_with_one_op(key) -> Chain:
    c = Chain(chain_id="a1b2c3d4e5f60718")
    c.append(
        op_type="ERASE", target_ref="/dev/sdb", timestamp="2026-09-04T10:00:00Z",
        method="Clear", result_hash="aa" * 32, operator_decl="op", concur_decl="",
        custody_tier=tiers.SOFTWARE_KEY, operator_key=key, outcome="VERIFIED",
    )
    return c


# --------------------------------------------------------------------------------------
# The amendment itself
# --------------------------------------------------------------------------------------

def test_amend_appends_without_touching_the_superseded_entry():
    key = _key()
    c = _chain_with_one_op(key)
    before_hash = c.entries[0].entry_hash
    before_target = c.entries[0].target_ref

    c.amend(
        amends_seq=0, reason="TRANSCRIPTION_ERROR", operator_decl="serial was mistyped",
        timestamp="2026-09-04T10:05:00Z", operator_key=key, result_hash="bb" * 32,
    )

    # The superseded entry is byte-for-byte what it was.
    assert c.entries[0].entry_hash == before_hash
    assert c.entries[0].target_ref == before_target
    assert c.entries[0].recompute_hash() == before_hash
    assert len(c.entries) == 2
    assert c.entries[1].op_type == "AMEND"
    assert c.entries[1].is_amendment()


def test_amend_verifies_and_reports_which_entry_it_supersedes():
    key = _key()
    c = _chain_with_one_op(key)
    c.amend(amends_seq=0, reason="CLERICAL", operator_decl="spelling",
            timestamp="2026-09-04T10:05:00Z", operator_key=key, result_hash="bb" * 32)

    r = verify_chain_report(c.entries, operator_pub=key.public_key())
    assert r.ok, r.reason
    assert r.amended_seqs == {0}


def test_amend_performs_no_forensic_work():
    key = _key()
    c = _chain_with_one_op(key)
    e = c.amend(amends_seq=0, reason="CLERICAL", operator_decl="x",
                timestamp="2026-09-04T10:05:00Z", operator_key=key, result_hash="bb" * 32)
    assert e.method == "NotPerformed"
    assert e.outcome == "NOT_PERFORMED"
    assert not tiers.is_performed("AMEND")

    # It must not drag the quoted custody tier of real work down, nor count as work.
    quoted = tiers.lowest(
        [x.custody_tier for x in c.entries], op_types=[x.op_type for x in c.entries]
    )
    assert quoted == tiers.SOFTWARE_KEY  # from the ERASE, not from the AMEND


def test_amend_rejects_a_reason_outside_the_vocabulary():
    key = _key()
    c = _chain_with_one_op(key)
    with pytest.raises(ValueError, match="edit wearing a label"):
        c.amend(amends_seq=0, reason="because I said so", operator_decl="x",
                timestamp="2026-09-04T10:05:00Z", operator_key=key, result_hash="bb" * 32)


def test_amend_rejects_a_target_that_does_not_exist():
    key = _key()
    c = _chain_with_one_op(key)
    with pytest.raises(ValueError, match="cannot amend seq"):
        c.amend(amends_seq=7, reason="CLERICAL", operator_decl="x",
                timestamp="2026-09-04T10:05:00Z", operator_key=key, result_hash="bb" * 32)


def test_amendments_do_not_chain():
    key = _key()
    c = _chain_with_one_op(key)
    c.amend(amends_seq=0, reason="CLERICAL", operator_decl="x",
            timestamp="2026-09-04T10:05:00Z", operator_key=key, result_hash="bb" * 32)
    with pytest.raises(ValueError, match="itself an AMEND"):
        c.amend(amends_seq=1, reason="CLERICAL", operator_decl="y",
                timestamp="2026-09-04T10:06:00Z", operator_key=key, result_hash="cc" * 32)


# --------------------------------------------------------------------------------------
# The welding: an amendment cannot be redirected at a different entry
# --------------------------------------------------------------------------------------

def test_redirecting_an_amendment_to_another_entry_is_caught():
    key = _key()
    c = _chain_with_one_op(key)
    c.append(op_type="RECOVER", target_ref="/dev/sdc", timestamp="2026-09-04T10:01:00Z",
             method="Clear", result_hash="cc" * 32, operator_decl="op", concur_decl="",
             custody_tier=tiers.SOFTWARE_KEY, operator_key=key, outcome="PARTIAL")
    c.amend(amends_seq=0, reason="WRONG_TARGET", operator_decl="x",
            timestamp="2026-09-04T10:05:00Z", operator_key=key, result_hash="dd" * 32)
    assert verify_chain_report(c.entries, operator_pub=key.public_key()).ok

    # Repoint it at entry 1, leaving everything else alone. Because amends_seq is inside
    # the preimage this breaks the entry's own hash first.
    c.entries[2].amends_seq = "1"
    r = verify_chain_report(c.entries, operator_pub=key.public_key())
    assert not r.ok
    assert r.broken_seq == 2


def test_amendment_naming_the_right_seq_but_the_wrong_hash_is_caught():
    """The hash check is not redundant with the seq check.

    Constructed by hand so the entry still hashes correctly, this is the case a seq-only
    binding would miss, where the amendment points at the right position but commits to
    content that position never had.
    """
    key = _key()
    c = _chain_with_one_op(key)
    c.amend(amends_seq=0, reason="CLERICAL", operator_decl="x",
            timestamp="2026-09-04T10:05:00Z", operator_key=key, result_hash="bb" * 32)

    e = c.entries[1]
    e.amends_hash = "ff" * 32                  # a hash entry 0 never had
    e.entry_hash = e.recompute_hash()          # re-hash so the content check passes
    e.operator_sig = key.sign(bytes.fromhex(e.entry_hash)).hex()   # and re-sign it

    r = verify_chain_report(c.entries, operator_pub=key.public_key())
    assert not r.ok
    assert "redirected" in r.reason


def test_amendment_fields_on_an_ordinary_entry_are_rejected():
    key = _key()
    c = _chain_with_one_op(key)
    e = c.entries[0]
    e.amends_seq = "0"
    e.amend_reason = "CLERICAL"
    e.entry_hash = e.recompute_hash()
    e.operator_sig = key.sign(bytes.fromhex(e.entry_hash)).hex()

    r = verify_chain_report(c.entries, operator_pub=key.public_key())
    assert not r.ok
    assert "only AMEND" in r.reason


def test_an_amendment_cannot_name_a_later_entry():
    key = _key()
    c = _chain_with_one_op(key)
    c.amend(amends_seq=0, reason="CLERICAL", operator_decl="x",
            timestamp="2026-09-04T10:05:00Z", operator_key=key, result_hash="bb" * 32)
    c.append(op_type="RECOVER", target_ref="/dev/sdc", timestamp="2026-09-04T10:06:00Z",
             method="Clear", result_hash="cc" * 32, operator_decl="op", concur_decl="",
             custody_tier=tiers.SOFTWARE_KEY, operator_key=key, outcome="VERIFIED")

    e = c.entries[1]
    e.amends_seq = "2"                        # forward reference: a claim about the future
    e.amends_hash = c.entries[2].entry_hash
    e.entry_hash = e.recompute_hash()
    e.operator_sig = key.sign(bytes.fromhex(e.entry_hash)).hex()

    r = verify_chain_report(c.entries, operator_pub=key.public_key())
    assert not r.ok
    assert "not an earlier entry" in r.reason


# --------------------------------------------------------------------------------------
# The migration. These are the regression guards for v3 chains.
# --------------------------------------------------------------------------------------

def test_v4_appends_to_v3_and_never_reorders_it():
    assert FIELDS_V4[:len(FIELDS_V3)] == FIELDS_V3
    assert FIELDS_V4[len(FIELDS_V3):] == [
        "place_ref", "amends_seq", "amends_hash", "amend_reason"]
    assert ENTRY_VERSION == "4"
    assert set(FIELDS_BY_VERSION) == {"3", "4"}


def test_a_v3_entry_is_rehashed_with_the_v3_field_list():
    """The core of the migration: an old entry must hash as it did when written."""
    v3_fields = {name: "x" for name in FIELDS_V3}
    v3_fields["entry_version"] = "3"

    # Encoding it under v3 must not include the four v4 fields...
    as_v3 = encode_entry(v3_fields, "3")
    # ...and asking for v4 with the same dict must fail loudly rather than pad with blanks.
    with pytest.raises(KeyError):
        encode_entry(v3_fields, "4")

    # The version is read off the entry when not passed explicitly.
    assert encode_entry(v3_fields) == as_v3


def test_a_real_v3_chain_still_verifies_under_this_build(tmp_path):
    """Write a chain as v3 would have been written, then verify it with the v4 verifier.

    Built by hashing with the v3 field list explicitly, which is what the previous build
    did, so this is a genuine old chain rather than a v4 chain wearing a v3 label.
    """
    key = _key()
    c = Chain(chain_id="0011223344556677")
    c.append(op_type="ERASE", target_ref="/dev/sdb", timestamp="2026-09-03T10:00:00Z",
             method="Clear", result_hash="aa" * 32, operator_decl="op", concur_decl="",
             custody_tier=tiers.SOFTWARE_KEY, operator_key=key, outcome="VERIFIED")

    # Rewrite it as a v3 entry: drop the v4 fields, re-hash under v3, re-sign.
    e = c.entries[0]
    e.entry_version = "3"
    e.place_ref = e.amends_seq = e.amends_hash = e.amend_reason = ""
    e.entry_hash = e.recompute_hash()
    e.operator_sig = key.sign(bytes.fromhex(e.entry_hash)).hex()

    assert fields_for(e.entry_version) is FIELDS_V3

    r = verify_chain_report(c.entries, operator_pub=key.public_key())
    assert r.ok, f"a v3 chain must still verify under a v4 verifier: {r.reason}"
    assert r.verified == 1

    # And it survives a round trip through disk, which is how a real old chain arrives.
    p = tmp_path / "v3_chain.json"
    p.write_text(c.to_json(), encoding="utf-8")
    reloaded = Chain.from_json(p.read_text(encoding="utf-8"))
    assert reloaded.entries[0].entry_version == "3"
    assert verify_chain_report(reloaded.entries, operator_pub=key.public_key()).ok


def test_an_unknown_version_is_still_refused_outright():
    """Widening the check to "known versions" must not weaken it to "any version"."""
    key = _key()
    c = _chain_with_one_op(key)
    c.entries[0].entry_version = "99"

    r = verify_chain_report(c.entries)
    assert not r.ok
    assert "refusing to guess" in r.reason

    with pytest.raises(ValueError, match="refusing to guess"):
        fields_for("99")


def test_place_ref_is_signed():
    """The BSA Schedule asks for the place; a place outside the signature is a label."""
    key = _key()
    c = Chain(chain_id="beefbeefbeefbeef")
    c.append(op_type="ERASE", target_ref="/dev/sdb", timestamp="2026-09-04T10:00:00Z",
             method="Clear", result_hash="aa" * 32, operator_decl="op", concur_decl="",
             custody_tier=tiers.SOFTWARE_KEY, operator_key=key, outcome="VERIFIED",
             place_ref="FSL Hyderabad, Room 3")
    assert verify_chain_report(c.entries, operator_pub=key.public_key()).ok

    c.entries[0].place_ref = "somewhere else"
    r = verify_chain_report(c.entries, operator_pub=key.public_key())
    assert not r.ok
    assert "hash mismatch" in r.reason


def test_amend_reasons_are_a_closed_set():
    assert "TRANSCRIPTION_ERROR" in AMEND_REASONS
    assert all(r.isupper() for r in AMEND_REASONS)
    key = _key()
    c = _chain_with_one_op(key)
    for reason in AMEND_REASONS:
        c2 = _chain_with_one_op(key)
        c2.amend(amends_seq=0, reason=reason, operator_decl="x",
                 timestamp="2026-09-04T10:05:00Z", operator_key=key,
                 result_hash="bb" * 32)
        assert verify_chain_report(c2.entries, operator_pub=key.public_key()).ok
    assert json.loads(c.to_json())["chain_id"] == "a1b2c3d4e5f60718"
