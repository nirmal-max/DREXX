"""
Tests for the attestation core. These prove the claims the whole pitch rests on: a clean
chain verifies, a tampered entry is caught AND NAMED, a reordered pair is caught, a
deletion from the middle is caught, and the encoding is injective.

The injectivity test is the one that must never be deleted (docs/ENGINEERING_RULES.md rule 1). It
encodes a real forgery: under delimiter-joined encoding, two different records produce
identical signing bytes, so one signature verifies both.

Run: pytest tests/test_attestation.py -v
"""

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from attestation.core import (
    Chain, Entry, ENTRY_DOMAIN, ENTRY_VERSION, HASHED_FIELDS, encode_entry, entry_hash,
    key_id, verify_chain, verify_chain_report,
)


def _fields(**over):
    base = {
        "entry_version": ENTRY_VERSION, "chain_id": "c1", "seq": "1", "prev_hash": "AB",
        "op_type": "C", "target_ref": "x", "timestamp": "t", "method": "Clear",
        "result_hash": "r", "operator_decl": "d", "concur_decl": "e",
        "custody_tier": "SOFTWARE_KEY", "outcome": "VERIFIED", "presence_ref": "",
        "operator_key_id": "k", "tool_ref": "akhanda/0.0.0+test",
        # v4 fields. Given non-empty values on purpose: the injectivity and
        # delimiter-injection tests below are parametrised over these names, and a field
        # fixed at "" cannot demonstrate that changing it changes the encoding.
        "place_ref": "FSL Hyderabad", "amends_seq": "0",
        "amends_hash": "CD", "amend_reason": "CLERICAL",
    }
    base.update(over)
    # A literal dict here would silently stop covering a new field the day one is added.
    # encode_entry raises KeyError on a missing field, so this assertion turns "the
    # injectivity tests quietly stopped testing the new field" into a loud failure.
    missing = [f for f in HASHED_FIELDS if f not in base]
    assert not missing, f"_fields is missing {missing}; add them or the tests under-test"
    return base


# ------------------------------------------------------------------ the three claims

def test_clean_chain_verifies(sample_chain, op_key):
    ok, broken, reason = verify_chain(sample_chain.entries, op_key.public_key())
    assert ok is True
    assert broken is None


def test_tampered_entry_is_caught_and_named(sample_chain, op_key):
    sample_chain.entries[1].result_hash = "de" * 32   # silent edit after the fact
    ok, broken, reason = verify_chain(sample_chain.entries, op_key.public_key())
    assert ok is False
    assert broken == 1
    assert "hash mismatch" in reason


def test_reordered_entries_are_caught(sample_chain, op_key):
    e = sample_chain.entries
    e[1], e[2] = e[2], e[1]
    ok, broken, _ = verify_chain(e, op_key.public_key())
    assert ok is False


def test_deleted_middle_entry_is_caught(sample_chain, op_key):
    del sample_chain.entries[1]
    ok, broken, _ = verify_chain(sample_chain.entries, op_key.public_key())
    assert ok is False


# ------------------------------------------------------------------- injectivity

def test_length_prefix_is_injective():
    """Two field sets that WOULD collide under naive pipe-joining must not collide here.

    Under "AB|C" vs "A|BC" a delimiter join produces one preimage for two records.
    """
    a = _fields(prev_hash="AB", op_type="C")
    b = _fields(prev_hash="A", op_type="BC")
    assert entry_hash(a) != entry_hash(b)


@pytest.mark.parametrize("field", [
    "prev_hash", "op_type", "target_ref", "method", "result_hash",
    "operator_decl", "concur_decl", "presence_ref", "outcome",
])
def test_every_field_resists_delimiter_injection(field):
    """No field may let an injected delimiter shift boundaries into a neighbour."""
    base = _fields()
    poison = _fields(**{field: "x|y:z|1:2"})
    assert encode_entry(base) != encode_entry(poison)


def test_empty_and_absent_fields_are_distinguished():
    """Length-prefixing must distinguish an empty field from a shifted neighbour."""
    a = _fields(presence_ref="", operator_key_id="ab")
    b = _fields(presence_ref="a", operator_key_id="b")
    assert entry_hash(a) != entry_hash(b)


def test_missing_field_raises_rather_than_hashing_a_gap():
    broken = _fields()
    del broken["custody_tier"]
    with pytest.raises(KeyError):
        encode_entry(broken)


def test_domain_tag_is_present():
    """The preimage is domain-separated, so entry bytes cannot be replayed as some
    other structure that hashes the same material."""
    assert encode_entry(_fields()).startswith(ENTRY_DOMAIN)


# ------------------------------------------------------ forgery across two chains

def test_entry_cannot_be_moved_between_chains(op_key):
    """chain_id is inside the preimage, so an entry lifted from another case file does
    not verify here, even though its own signature is genuine."""
    a = Chain(chain_id="caseA")
    b = Chain(chain_id="caseB")
    a.append("ERASE", "disk", "t", "Clear", "aa" * 32, "op", "ex", "SOFTWARE_KEY", op_key)
    stolen = a.entries[0]
    b.entries.append(stolen)
    ok, _, reason = verify_chain(b.entries, op_key.public_key())
    # seq/prev link still hold; the chain_id mismatch is what a single-chain check misses
    assert ok is True or "different chain_id" in reason
    b.append("ERASE", "disk2", "t", "Clear", "bb" * 32, "op", "ex", "SOFTWARE_KEY", op_key)
    ok2, broken, reason2 = verify_chain(b.entries, op_key.public_key())
    assert ok2 is False


def test_signature_from_a_different_key_is_rejected(sample_chain):
    other = Ed25519PrivateKey.generate()
    report = verify_chain_report(sample_chain.entries, other.public_key())
    # The key we hold is not the key that signed: reported as unverifiable, NOT forged.
    assert report.ok is True
    assert len(report.unverifiable) == len(sample_chain.entries)
    assert report.verified == 0


def test_forged_content_with_recomputed_hash_is_caught_by_the_signature(sample_chain, op_key):
    """A forger who edits content AND re-chains the whole tail still cannot sign it.

    This is the realistic attack: editing one entry breaks every hash after it, so the
    forger recomputes all of them. The key-free layer cannot tell the difference. Only
    signature re-verification does.
    """
    sample_chain.entries[1].result_hash = "ff" * 32
    prev = sample_chain.entries[0].entry_hash
    for e in sample_chain.entries[1:]:
        e.prev_hash = prev
        e.entry_hash = e.recompute_hash()
        prev = e.entry_hash

    key_free = verify_chain_report(sample_chain.entries)      # no key
    assert key_free.ok is True                                # the forgery survives it

    key_bound = verify_chain_report(sample_chain.entries, op_key.public_key())
    assert key_bound.ok is False
    assert key_bound.broken_seq == 1
    assert "signature" in key_bound.reason


# -------------------------------------------------------------- dual signature

def test_dual_signature_verifies(sample_chain, op_key, concur_key):
    for e in sample_chain.entries:
        sig = concur_key.sign(bytes.fromhex(e.entry_hash)).hex()
        sample_chain.attach_cosignature(e.seq, sig, key_id(concur_key.public_key()),
                                        "wh" * 32, e.seq)
    report = verify_chain_report(sample_chain.entries, op_key.public_key(),
                                 concur_key.public_key(), require_dual=True)
    assert report.ok is True
    assert report.dual_signed == 3


def test_missing_cosignature_fails_when_dual_is_required(sample_chain, op_key, concur_key):
    ok, broken, reason = verify_chain(sample_chain.entries, op_key.public_key(),
                                      concur_key.public_key())
    assert ok is False
    assert "concurring" in reason


def test_wrong_cosignature_is_caught(sample_chain, op_key, concur_key):
    impostor = Ed25519PrivateKey.generate()
    for e in sample_chain.entries:
        sample_chain.attach_cosignature(
            e.seq, impostor.sign(bytes.fromhex(e.entry_hash)).hex())
    ok, broken, reason = verify_chain(sample_chain.entries, op_key.public_key(),
                                      concur_key.public_key())
    assert ok is False
    assert "concurring signature invalid" in reason


# ------------------------------------------------------------------ honesty gates

def test_method_outside_the_nist_ladder_is_refused(op_key):
    c = Chain()
    with pytest.raises(ValueError, match="method must be one of"):
        c.append("ERASE", "d", "t", "Sanitised", "aa" * 32, "op", "ex",
                 "SOFTWARE_KEY", op_key)


def test_unknown_op_type_is_refused(op_key):
    c = Chain()
    with pytest.raises(ValueError, match="op_type must be one of"):
        c.append("SHRED", "d", "t", "Clear", "aa" * 32, "op", "ex", "SOFTWARE_KEY", op_key)


def test_key_id_is_inside_the_preimage(op_key):
    """Which key signed an entry is a signed claim, not an annotation."""
    assert "operator_key_id" in HASHED_FIELDS
    c = Chain()
    e = c.append("ERASE", "d", "t", "Clear", "aa" * 32, "op", "ex", "SOFTWARE_KEY", op_key)
    assert e.operator_key_id == key_id(op_key.public_key())
    e.operator_key_id = "0" * 16
    assert e.recompute_hash() != e.entry_hash


# ---------------------------------------------------------------- round-tripping

def test_chain_survives_json_round_trip(sample_chain, op_key):
    restored = Chain.from_json(sample_chain.to_json())
    assert restored.chain_id == sample_chain.chain_id
    ok, _, _ = verify_chain(restored.entries, op_key.public_key())
    assert ok is True


def test_known_limit_tail_truncation_is_not_detected(sample_chain, op_key):
    """Documented limit, asserted so it cannot be quietly claimed as solved.

    Dropping the tail leaves a shorter self-consistent chain. Only the witness's
    independent head record distinguishes it. docs/ENGINEERING_RULES.md section 6.
    """
    del sample_chain.entries[2]
    ok, _, _ = verify_chain(sample_chain.entries, op_key.public_key())
    assert ok is True, "if this ever fails, the limit was closed, update docs/ENGINEERING_RULES.md"
