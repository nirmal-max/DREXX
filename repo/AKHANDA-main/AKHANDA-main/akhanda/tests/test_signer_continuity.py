"""Gap 7, a signer may change; a signer may not change SILENTLY.

The attack: substitute the signing key mid-chain. Every signature still verifies, because
a verifier handed the substituted key confirms its signatures with complete honesty. The
chain is internally perfect. Nothing inside it says which key was SUPPOSED to be there.

These tests are written against that, and against the two ways a naive fix would fail:
accepting an announcement signed by the incoming key (the attacker's own introduction
letter), and accepting one that arrives after the fact (a retrospective note is not an
authorisation).
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from attestation import tiers  # noqa: E402
from attestation.core import Chain, key_id, verify_chain_report  # noqa: E402
from attestation.signers import (  # noqa: E402
    CHANGE_REASONS, SIGNER_CHANGE, build_roster, detect_signer_changes,
    signer_change_record, verify_signer_continuity,
)


@pytest.fixture
def alice():
    return Ed25519PrivateKey.generate()


@pytest.fixture
def mallory():
    return Ed25519PrivateKey.generate()


def _op(chain, key, i, op_type="ERASE"):
    return chain.append(
        op_type=op_type, target_ref=f"/dev/d{i}", timestamp=f"2026-09-01T10:{i:02d}:00Z",
        method="Clear" if op_type != SIGNER_CHANGE else "NotPerformed",
        result_hash=f"{i:064x}", operator_decl=f"operation {i}", concur_decl="",
        custody_tier=tiers.SOFTWARE_KEY, operator_key=key,
        outcome="VERIFIED" if op_type != SIGNER_CHANGE else "NOT_PERFORMED")


def _announce(chain, outgoing_key, incoming_key, i, reason="ROTATION"):
    """A correctly formed handover: signed by the OUTGOING key, naming the incoming one."""
    return chain.append(
        op_type=SIGNER_CHANGE, target_ref="signer", timestamp=f"2026-09-01T10:{i:02d}:00Z",
        method="NotPerformed", result_hash=f"{i:064x}",
        operator_decl=f"reason={reason} to={key_id(incoming_key.public_key())}",
        concur_decl="", custody_tier=tiers.SOFTWARE_KEY, operator_key=outgoing_key,
        outcome="NOT_PERFORMED")


# --------------------------------------------------------------------------- the attack

def test_a_silent_signer_substitution_is_detected(alice, mallory):
    """THE POINT OF THE FILE."""
    c = Chain(chain_id="sub")
    _op(c, alice, 0)
    _op(c, alice, 1)
    _op(c, mallory, 2)          # no announcement

    report = verify_signer_continuity(c.entries)
    assert report["ok"] is False
    assert len(report["unexplained"]) == 1
    assert report["unexplained"][0]["at_seq"] == 2
    assert "without announcement" in report["unexplained"][0]["detail"]


def test_the_substituted_chain_still_verifies_which_is_why_this_exists(alice, mallory):
    """Stated as a test because it is the argument for the module.

    If the chain broke on its own, no continuity check would be needed. The key-free layer
    passes -- hashes and links are all intact -- and only the signer changed.
    """
    c = Chain(chain_id="sub")
    _op(c, alice, 0)
    _op(c, mallory, 1)

    report = verify_chain_report(c.entries)      # key-free layer, no keys supplied
    assert report.ok, "structure is intact; only the signer changed"


def test_an_announced_rotation_is_accepted(alice, mallory):
    c = Chain(chain_id="rot")
    _op(c, alice, 0)
    _announce(c, alice, mallory, 1)
    _op(c, mallory, 2)

    report = verify_signer_continuity(c.entries)
    assert report["ok"] is True
    assert report["unexplained"] == []
    assert "announced by the outgoing key" in report["reason"]


# ------------------------------------------------- the two ways a naive fix would fail

def test_a_key_cannot_authorise_its_own_succession(alice, mallory):
    """The attacker's own introduction letter. Mallory announces Mallory."""
    c = Chain(chain_id="self")
    _op(c, alice, 0)
    c.append(op_type=SIGNER_CHANGE, target_ref="signer", timestamp="2026-09-01T10:01:00Z",
             method="NotPerformed", result_hash="01" * 32,
             operator_decl=f"reason=ROTATION to={key_id(mallory.public_key())}",
             concur_decl="", custody_tier=tiers.SOFTWARE_KEY,
             operator_key=mallory,                       # signed by the INCOMING key
             outcome="NOT_PERFORMED")
    _op(c, mallory, 2)

    report = verify_signer_continuity(c.entries)
    assert report["ok"] is False
    assert report["unexplained"], "a self-announced handover must not be accepted"


def test_a_retrospective_announcement_does_not_authorise(alice, mallory):
    """The new key signs first, and the paperwork turns up afterwards."""
    c = Chain(chain_id="late")
    _op(c, alice, 0)
    _op(c, mallory, 1)                  # already working
    _announce(c, alice, mallory, 2)     # announced after the fact

    report = verify_signer_continuity(c.entries)
    assert report["ok"] is False
    assert "retrospective" in report["unexplained"][0]["detail"]


# ------------------------------------------------------------------ independent key set

def test_a_key_nobody_recognises_is_reported(alice, mallory):
    """Even a properly announced rotation can introduce a key no one else knows."""
    c = Chain(chain_id="unknown")
    _op(c, alice, 0)
    _announce(c, alice, mallory, 1)
    _op(c, mallory, 2)

    report = verify_signer_continuity(
        c.entries, expected_key_ids={key_id(alice.public_key())})
    assert report["ok"] is False
    assert report["unknown_keys"] == [key_id(mallory.public_key())]


def test_without_an_independent_key_set_the_result_says_so(alice):
    """Checking a chain only against the keys it names is circular, and the report has to
    admit that rather than returning a bare pass."""
    c = Chain(chain_id="circular")
    _op(c, alice, 0)
    report = verify_signer_continuity(c.entries)
    assert report["ok"] is True
    assert "consistent with itself" in report["reason"]
    assert report["checked_against_expected"] is False


def test_supplying_the_expected_set_removes_the_caveat(alice):
    c = Chain(chain_id="known")
    _op(c, alice, 0)
    report = verify_signer_continuity(
        c.entries, expected_key_ids={key_id(alice.public_key())})
    assert report["ok"] is True
    assert "consistent with itself" not in report["reason"]


# ------------------------------------------------------------------------- the record

def test_the_reason_vocabulary_is_closed():
    """Free text would let a compromise be filed as a routine handover."""
    with pytest.raises(ValueError):
        signer_change_record(from_key_id="a" * 16, to_key_id="b" * 16,
                             reason="routine maintenance, nothing to see",
                             declared_by="P. Srivastava", effective_from_seq=3)


def test_compromise_is_a_word_the_vocabulary_actually_has():
    """The one nobody wants to write down must be available, or it gets written as
    ROTATION."""
    assert "COMPROMISE" in CHANGE_REASONS
    rec = signer_change_record(from_key_id="a" * 16, to_key_id="b" * 16,
                               reason="COMPROMISE", declared_by="P. Srivastava",
                               effective_from_seq=3)
    assert rec["reason"] == "COMPROMISE"


def test_a_change_must_actually_change_the_signer():
    with pytest.raises(ValueError):
        signer_change_record(from_key_id="a" * 16, to_key_id="a" * 16, reason="ROTATION",
                             declared_by="x", effective_from_seq=1)


def test_the_record_names_a_human_not_only_keys():
    """A rotation is an administrative act with someone accountable for it."""
    rec = signer_change_record(from_key_id="a" * 16, to_key_id="b" * 16, reason="PERSONNEL",
                               declared_by="Lab Supervisor, GITAM", effective_from_seq=4)
    assert rec["declared_by"] == "Lab Supervisor, GITAM"


def test_the_record_refuses_to_claim_the_outgoing_key_was_clean():
    """A compromised key can sign a valid handover. The record must say so itself."""
    rec = signer_change_record(from_key_id="a" * 16, to_key_id="b" * 16, reason="ROTATION",
                               declared_by="x", effective_from_seq=2)
    assert "does not prove" in rec["meaning"].lower()
    assert "announced rather than made silently" in rec["meaning"].lower()


def test_a_lost_key_is_described_as_weaker_not_equivalent():
    """LOSS cannot be signed by the outgoing key, so it is genuinely weaker evidence and
    the record says that rather than presenting it as an ordinary rotation."""
    rec = signer_change_record(from_key_id="a" * 16, to_key_id="b" * 16, reason="LOSS",
                               declared_by="x", effective_from_seq=2)
    assert "cannot be signed by it" in rec["meaning"].lower()
    assert "weaker" in rec["meaning"].lower()


# ---------------------------------------------------------------------------- roster

def test_the_roster_reports_who_signed_what(alice, mallory):
    c = Chain(chain_id="roster")
    _op(c, alice, 0)
    _op(c, alice, 1)
    _announce(c, alice, mallory, 2)
    _op(c, mallory, 3)

    roster = build_roster(c.entries)
    a, m = key_id(alice.public_key()), key_id(mallory.public_key())
    assert roster[a]["count"] == 3          # two ops plus the announcement
    assert roster[m]["count"] == 1
    assert roster[m]["first_seq"] == 3


def test_multiple_announced_rotations_all_pass(alice, mallory):
    carol = Ed25519PrivateKey.generate()
    c = Chain(chain_id="chainofcustody")
    _op(c, alice, 0)
    _announce(c, alice, mallory, 1)
    _op(c, mallory, 2)
    _announce(c, mallory, carol, 3)
    _op(c, carol, 4)

    report = verify_signer_continuity(c.entries)
    assert report["ok"] is True
    assert len(report["changes"]) == 2


def test_one_bad_rotation_among_good_ones_is_still_caught(alice, mallory):
    carol = Ed25519PrivateKey.generate()
    c = Chain(chain_id="mixed")
    _op(c, alice, 0)
    _announce(c, alice, mallory, 1)
    _op(c, mallory, 2)
    _op(c, carol, 3)            # never announced

    report = verify_signer_continuity(c.entries)
    assert report["ok"] is False
    assert [u["to_key_id"] for u in report["unexplained"]] == [key_id(carol.public_key())]


# ------------------------------------------------------- it does not distort the tiers

def test_a_signer_change_does_not_drag_the_quoted_custody_tier_down():
    """Same reasoning as G1 for REFUSED: an administrative entry has no witness to
    co-sign it, and must not make a fully-custodied case look weak."""
    assert tiers.is_performed(SIGNER_CHANGE) is False
    quoted = tiers.lowest([tiers.FULL_CUSTODY, tiers.SOFTWARE_KEY],
                          op_types=["ERASE", SIGNER_CHANGE])
    assert quoted == tiers.FULL_CUSTODY


def test_an_empty_chain_reports_rather_than_raising():
    report = verify_signer_continuity([])
    assert report["ok"] is False
    assert "empty chain" in report["reason"]
