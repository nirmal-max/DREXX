"""
GAP-1, a refusal must not weaken the certificate for work that actually happened.

The bug, in one sentence: the fail-closed policy exists to STRENGTHEN custody, and as
written it WEAKENED the certificate. A REFUSED entry has no co-signature and no presence
by construction, that is why it was refused, so its tier is SOFTWARE_KEY, and
`tiers.lowest()` over every entry dragged the whole case down to SOFTWARE_KEY even when
every real operation reached FULL_CUSTODY. Demonstrating the safety feature damaged the
evidence.

Three parts, all confirmed against the real code before being fixed:

  1. the quoted custody tier collapsed
  2. the BSA Part B ratio denominator counted refusals it was never eligible for
  3. the certificate did not mention the refusal AT ALL, so fixing only (1) would have
     left refusals both hidden and uncounted, which is the opposite error
"""

import json

import pytest

from attestation import tiers
from attestation.core import Chain, key_id, verify_chain_report
from certificate.generator import MediaInfo, Party, build_certificate, render_text


def _full_custody_op(chain, op_key, concur_key, i):
    e = chain.append("ERASE", f"/dev/sd{chr(98 + i)}", f"2026-01-01T1{i}:00:00Z",
                     "Clear", f"{i:02x}" * 32, "op", "ex",
                     tiers.FULL_CUSTODY, op_key,
                     presence_fn=lambda ph, i=i: f"COM9:aa{i}:{ph[:16]}")
    chain.attach_cosignature(e.seq, concur_key.sign(bytes.fromhex(e.entry_hash)).hex(),
                             key_id(concur_key.public_key()), "wh" * 32, e.seq)
    return e


def _refusal(chain, op_key, i=9):
    return chain.append("REFUSED", "/dev/sdz", f"2026-01-01T1{i}:00:00Z",
                        "NotPerformed", "ff" * 32, "op", "ex",
                        tiers.SOFTWARE_KEY, op_key)


@pytest.fixture()
def mixed(op_key, concur_key):
    """Two real FULL_CUSTODY erases and one blocked attempt, the reported scenario."""
    c = Chain(chain_id="gap1")
    _full_custody_op(c, op_key, concur_key, 0)
    _full_custody_op(c, op_key, concur_key, 1)
    _refusal(c, op_key)
    return c


def _cert(chain, op_key=None, concur_key=None, entries=None):
    entries = entries if entries is not None else chain.entries
    report = verify_chain_report(
        chain.entries,
        op_key.public_key() if op_key else None,
        concur_key.public_key() if concur_key else None,
    )
    return build_certificate(chain, entries, Party(name="J. Rao"), Party(name="K. Singh"),
                             MediaInfo(), chain_report=report)


# ─────────────────────────────────────────── part 1: the tier no longer collapses

def test_a_refusal_no_longer_drags_the_quoted_tier_down(mixed, op_key, concur_key):
    ct = _cert(mixed, op_key, concur_key)["chain"]["custody_tier"]
    assert ct["weakest_tier_covered"] == tiers.FULL_CUSTODY


def test_lowest_ignores_refusals_when_given_op_types():
    t = [tiers.FULL_CUSTODY, tiers.FULL_CUSTODY, tiers.SOFTWARE_KEY]
    ops = ["ERASE", "ERASE", "REFUSED"]
    assert tiers.lowest(t) == tiers.SOFTWARE_KEY                 # unfiltered, unchanged
    assert tiers.lowest(t, op_types=ops) == tiers.FULL_CUSTODY   # filtered


def test_a_genuinely_weak_performed_entry_still_lowers_the_tier(op_key, concur_key):
    """The filter must not become a way to hide real weakness."""
    c = Chain(chain_id="gap1b")
    _full_custody_op(c, op_key, concur_key, 0)
    c.append("ERASE", "/dev/sdc", "t", "Clear", "cc" * 32, "op", "ex",
             tiers.SOFTWARE_KEY, op_key)          # performed, and genuinely weak
    _refusal(c, op_key)
    ct = _cert(c, op_key, concur_key)["chain"]["custody_tier"]
    assert ct["weakest_tier_covered"] == tiers.SOFTWARE_KEY


def test_is_performed_classifies_the_op_types():
    assert tiers.is_performed("ERASE") is True
    assert tiers.is_performed("RECOVER") is True
    assert tiers.is_performed("REFUSED") is False


def test_mismatched_parallel_lists_are_refused():
    with pytest.raises(ValueError, match="parallel"):
        tiers.lowest([tiers.FULL_CUSTODY], op_types=["ERASE", "REFUSED"])


# ────────────────────────────── part 2: the Part B denominator excludes refusals

def test_the_dual_signature_denominator_counts_performed_operations_only(mixed, op_key,
                                                                         concur_key):
    ct = _cert(mixed, op_key, concur_key)["chain"]["custody_tier"]
    assert ct["of_entries"] == 2               # not 3
    assert ct["dual_signed_entries"] == 2
    assert ct["dual_verified_entries"] == 2


def test_the_ratio_is_not_deflated_by_a_refusal(mixed, op_key, concur_key):
    """2 of 2 is the true statutory ratio. 2 of 3 was the bug."""
    cert = _cert(mixed, op_key, concur_key)
    ct = cert["chain"]["custody_tier"]
    assert ct["dual_signed_entries"] == ct["of_entries"]
    assert not any("PARTIAL DUAL SIGNATURE" in l for l in cert["limits"])


def test_the_basis_of_the_count_is_stated(mixed, op_key, concur_key):
    ct = _cert(mixed, op_key, concur_key)["chain"]["custody_tier"]
    assert "performed operations only" in ct["basis"]


# ──────────────────────────────── part 3: refusals are reported, never suppressed

def test_refusals_appear_on_their_own_line(mixed, op_key, concur_key):
    ra = _cert(mixed, op_key, concur_key)["refused_attempts"]
    assert ra["count"] == 1
    assert ra["entries"][0]["seq"] == 2
    assert ra["entries"][0]["target"] == "/dev/sdz"


def test_the_refusal_meaning_states_that_nothing_happened(mixed, op_key, concur_key):
    ra = _cert(mixed, op_key, concur_key)["refused_attempts"]
    assert "BLOCKED before running" in ra["meaning"]
    assert "read, written, or destroyed" in ra["meaning"]


def test_a_refusal_adds_a_limits_line(mixed, op_key, concur_key):
    limits = _cert(mixed, op_key, concur_key)["limits"]
    line = next((l for l in limits if "BLOCKED ATTEMPTS" in l), None)
    assert line is not None
    assert "do not bound the custody tier" in line
    assert "indistinguishable from an attempt never made" in line


def test_a_clean_chain_says_nothing_was_blocked(op_key, concur_key):
    c = Chain(chain_id="gap1c")
    _full_custody_op(c, op_key, concur_key, 0)
    cert = _cert(c, op_key, concur_key)
    assert cert["refused_attempts"]["count"] == 0
    assert "no operation was blocked" in cert["refused_attempts"]["meaning"]
    assert not any("BLOCKED ATTEMPTS" in l for l in cert["limits"])


def test_the_text_certificate_prints_the_blocked_count(mixed, op_key, concur_key):
    text = render_text(_cert(mixed, op_key, concur_key))
    flat = " ".join(text.split())
    assert "Blocked attempts : 1" in flat
    assert "/dev/sdz" in text


def test_refusals_are_visible_in_the_serialised_certificate(mixed, op_key, concur_key):
    """The original bug: 'REFUSED' did not appear anywhere in the certificate."""
    blob = json.dumps(_cert(mixed, op_key, concur_key))
    assert "refused_attempts" in blob
    assert "/dev/sdz" in blob


# ───────────────────────────────────── §7.1: no default tier for a chain of refusals

def test_a_chain_of_only_refusals_refuses_to_certify(op_key):
    """It must not quote a default tier for a chain in which nothing was performed."""
    c = Chain(chain_id="gap1d")
    _refusal(c, op_key, 0)
    _refusal(c, op_key, 1)
    with pytest.raises(ValueError, match="refusal report, not a certificate"):
        _cert(c, op_key)


def test_lowest_over_nothing_raises_rather_than_defaulting():
    with pytest.raises(ValueError, match="no performed operations"):
        tiers.lowest([])
    with pytest.raises(ValueError, match="no performed operations"):
        tiers.lowest([tiers.SOFTWARE_KEY], op_types=["REFUSED"])


# ─────────────────────────────────────────────── refusals stay in the chain itself

def test_refusals_are_still_real_signed_entries(mixed, op_key):
    """Excluding them from the tier must not exclude them from verification."""
    report = verify_chain_report(mixed.entries, op_key.public_key())
    assert report.ok is True
    assert report.total == 3
    assert report.verified == 3
