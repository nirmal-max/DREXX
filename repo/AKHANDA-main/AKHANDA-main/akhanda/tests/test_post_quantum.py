"""Post-quantum signatures, a chain signed in 2026, still provable in 2040.

Ed25519 is elliptic-curve. NIST deprecates ECC P-256 by 2030 and removes quantum-vulnerable
algorithms from its standards by 2035; Indian criminal proceedings routinely run 10-20 years
through appeal. A chain signed today may be read after the algorithm that signed it has left
the standards.

Two properties carry most of these tests:

    ADDITIVE, NOT A FORMAT BREAK. The post-quantum signature is attached after signing,
    like operator_sig and concur_sig, so it needs no hashed field and no ENTRY_VERSION
    bump. Existing verifiers, including the Rust and JavaScript ones, read a PQ-signed
    chain unchanged.

    STRIPPING IS DETECTABLE. An adversary who cannot forge either signature can still
    DELETE the post-quantum one and downgrade the chain to the algorithm they expect to
    break. `pq_algorithm` is recorded separately from the signature, so an entry that names
    an algorithm and carries no signature for it is a finding rather than an absence.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from attestation import pq, tiers  # noqa: E402
from attestation.core import ENTRY_VERSION, HASHED_FIELDS, Chain, verify_chain_report  # noqa: E402
from attestation.keys import load_or_create_operator_key  # noqa: E402


@pytest.fixture(scope="module")
def ed_key():
    return load_or_create_operator_key()


@pytest.fixture(scope="module")
def pq_key():
    return pq.generate()


def _chain(ed_key, pq_key, n=3, protect=None):
    """A chain of n entries; `protect` names which seqs get a PQ signature."""
    protect = range(n) if protect is None else protect
    c = Chain(chain_id="pq")
    for i in range(n):
        e = c.append(op_type="ERASE", target_ref=f"/dev/d{i}",
                     timestamp=f"2026-09-01T00:0{i}:00Z", method="Clear",
                     result_hash=f"{i:064x}", operator_decl=f"op {i}", concur_decl="",
                     custody_tier=tiers.SOFTWARE_KEY, operator_key=ed_key,
                     outcome="VERIFIED")
        if i in protect:
            pq.dual_sign(e, pq_key)
    return c


# ───────────────────────────────────────── additive, not a break

def test_the_pq_layer_still_adds_no_hashed_field():
    """THE PROPERTY THAT MAKES THIS SHIPPABLE: the post-quantum layer is ATTACHED, never
    hashed, so adding it never forces a version bump.

    That property is unchanged. The version is now 4 and the field list is 20 because
    place_ref and the three AMEND fields were added, a deliberate bump, synchronised
    across the Python, JavaScript and Rust verifiers in one commit, which is exactly the
    cost this test was written to make visible. What must stay true regardless of the
    version is that NO pq_* field is in the preimage.
    """
    assert ENTRY_VERSION == "4"
    assert len(HASHED_FIELDS) == 20
    assert "pq_algorithm" not in HASHED_FIELDS
    assert "operator_pq_sig" not in HASHED_FIELDS
    assert "concur_pq_sig" not in HASHED_FIELDS
    assert not any(f.startswith("pq_") or f.endswith("_pq_sig") for f in HASHED_FIELDS)


def test_a_pq_signature_does_not_change_the_entry_hash(ed_key, pq_key):
    """So an existing verifier reads a PQ-signed chain unchanged rather than failing it."""
    c = _chain(ed_key, pq_key, n=2)
    for e in c.entries:
        assert e.entry_hash == e.recompute_hash()


def test_the_classical_verification_still_passes(ed_key, pq_key):
    c = _chain(ed_key, pq_key, n=3)
    assert verify_chain_report(c.entries, operator_pub=ed_key.public_key()).ok


def test_both_signatures_cover_the_same_bytes(ed_key, pq_key):
    """Not two unrelated attestations: a verifier holding either key checks the same claim
    about the same entry."""
    from cryptography.exceptions import InvalidSignature

    c = _chain(ed_key, pq_key, n=1)
    e = c.entries[0]

    def verifies(pub, sig_hex, msg_hex) -> bool:
        try:
            pub.verify(bytes.fromhex(sig_hex), bytes.fromhex(msg_hex))
            return True
        except (InvalidSignature, ValueError):
            return False

    # Both verify over the entry hash...
    assert verifies(ed_key.public_key(), e.operator_sig, e.entry_hash)
    assert verifies(pq_key.public_key(), e.operator_pq_sig, e.entry_hash)

    # ...and NEITHER verifies over different bytes, which is what makes the first two
    # assertions mean something. A bare .verify() call relies on an exception nobody can
    # see; the adversarial audit flagged exactly that shape here and it was right.
    other = "ff" * 32
    assert not verifies(ed_key.public_key(), e.operator_sig, other)
    assert not verifies(pq_key.public_key(), e.operator_pq_sig, other)


# ───────────────────────────────────────── stripping

def test_a_stripped_signature_is_detected(ed_key, pq_key):
    """THE ATTACK. Deleting the PQ signature downgrades the chain to the algorithm the
    adversary expects to break."""
    c = _chain(ed_key, pq_key, n=3)
    c.entries[1].operator_pq_sig = ""

    v = pq.verify_entry(c.entries[1], pq_key.public_key())
    assert v.state == pq.STRIPPED
    assert "downgrade" in v.reason

    a = pq.assess_chain(c.entries, pq_key.public_key())
    assert a.stripped == [1]


def test_stripping_the_algorithm_name_is_also_detected(ed_key, pq_key):
    """The mirror attack: remove the label instead of the signature, so nothing can be
    checked against a key."""
    c = _chain(ed_key, pq_key, n=1)
    c.entries[0].pq_algorithm = ""
    v = pq.verify_entry(c.entries[0], pq_key.public_key())
    assert v.state == pq.STRIPPED
    assert "names no algorithm" in v.reason


def test_stripping_does_not_break_the_classical_chain(ed_key, pq_key):
    """Which is exactly why it needs its own detection: the ordinary verifier is happy."""
    c = _chain(ed_key, pq_key, n=3)
    c.entries[1].operator_pq_sig = ""
    assert verify_chain_report(c.entries, operator_pub=ed_key.public_key()).ok


def test_a_forged_pq_signature_is_rejected(ed_key, pq_key):
    c = _chain(ed_key, pq_key, n=1)
    other = pq.generate()
    c.entries[0].operator_pq_sig = pq.sign(other, c.entries[0].entry_hash)
    v = pq.verify_entry(c.entries[0], pq_key.public_key())
    assert v.state == pq.FORGED


# ───────────────────────────────────────── the four states stay distinct

def test_no_pq_signature_is_not_a_failure(ed_key, pq_key):
    """A chain written before the migration is normal, not broken."""
    c = _chain(ed_key, pq_key, n=1, protect=[])
    v = pq.verify_entry(c.entries[0], pq_key.public_key())
    assert v.state == pq.UNPROTECTED
    assert "Not a defect" in v.reason


def test_unverified_is_reported_as_unverified_not_valid(ed_key, pq_key):
    """No public key supplied means the signature was not checked. That must never read
    as protected."""
    c = _chain(ed_key, pq_key, n=1)
    v = pq.verify_entry(c.entries[0], pq_pub=None)
    assert v.state == pq.UNPROTECTED
    assert "no public key was supplied" in v.reason


def test_an_unknown_algorithm_is_refused_not_mis_verified(ed_key, pq_key):
    c = _chain(ed_key, pq_key, n=1)
    c.entries[0].pq_algorithm = "ML-DSA-999"
    v = pq.verify_entry(c.entries[0], pq_key.public_key())
    assert v.state == pq.UNKNOWN_ALG
    assert "unreadable here, not broken" in v.reason


# ───────────────────────────────────────── a migration is a mixture

def test_a_partial_migration_is_reported_as_a_mixture(ed_key, pq_key):
    """A chain that is 2/3 protected must say so, not round to whichever end is convenient."""
    c = _chain(ed_key, pq_key, n=3, protect=[0, 1])
    a = pq.assess_chain(c.entries, pq_key.public_key())
    assert (a.protected, a.unprotected) == (2, 1)
    assert a.fully_protected is False
    assert "migration in progress" in a.reason


def test_a_fully_protected_chain_says_so(ed_key, pq_key):
    a = pq.assess_chain(_chain(ed_key, pq_key, n=3).entries, pq_key.public_key())
    assert a.fully_protected is True
    assert a.protected == 3
    assert a.algorithms == [pq.ALGORITHM]


def test_a_chain_with_no_pq_at_all_names_the_2035_deadline(ed_key, pq_key):
    a = pq.assess_chain(_chain(ed_key, pq_key, n=2, protect=[]).entries)
    assert a.protected == 0
    assert "2035" in a.reason


def test_an_empty_chain_is_not_fully_protected():
    a = pq.assess_chain([])
    assert a.fully_protected is False
    assert a.reason == "empty chain"


# ───────────────────────────────────────── keys

def test_a_key_round_trips_through_pem(tmp_path):
    p = tmp_path / "pq.pem"
    k1 = pq.load_or_create(p)
    k2 = pq.load_or_create(p)
    assert pq.public_bytes(k1.public_key()) == pq.public_bytes(k2.public_key())


def test_a_wrong_key_type_is_refused_rather_than_used(tmp_path):
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ed25519
    p = tmp_path / "wrong.pem"
    p.write_bytes(ed25519.Ed25519PrivateKey.generate().private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption()))
    with pytest.raises(TypeError, match="wrong type"):
        pq.load_or_create(p)


def test_loading_a_public_key_needs_the_algorithm_named():
    """A 1,952-byte blob is ML-DSA-65 and a 1,312-byte blob is ML-DSA-44. Guessing from
    length would make verification depend on a coincidence of sizes."""
    k = pq.generate()
    raw = pq.public_bytes(k.public_key())
    assert pq.load_public(raw, "ML-DSA-65")
    with pytest.raises(ValueError, match="unknown post-quantum algorithm"):
        pq.load_public(raw, "Dilithium3")


def test_dual_sign_refuses_an_unsigned_entry(pq_key):
    from attestation.core import Entry
    with pytest.raises(ValueError, match="after the entry is signed"):
        pq.dual_sign(Entry(seq=0, prev_hash="", op_type="ERASE", target_ref="x",
                           timestamp="t", method="Clear", result_hash="r",
                           operator_decl="d", concur_decl="",
                           custody_tier="SOFTWARE_KEY"), pq_key)


# ───────────────────────────────────────── the claim stays honest

def test_the_module_states_what_it_does_not_claim():
    d = pq.describe()
    assert "first implementer, not first thinker" in d["not_claimed"]
    assert "unknowable" in d["not_claimed"]
    assert "FIPS 204" in d["standard"]
