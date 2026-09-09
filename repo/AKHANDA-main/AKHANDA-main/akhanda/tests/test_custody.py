"""
Custody tier, key handling, presence fallback, and chain persistence.

These test docs/ENGINEERING_RULES.md rule 3, "additive, never substitutive", as a mechanism rather
than a habit. Every optional component is removed in turn and the system must still
complete the operation while recording the tier it actually reached.
"""

import json
import os

import pytest

from attestation import keys, store, tiers
from attestation.core import Chain, key_id, verify_chain
from presence import client as presence


# ------------------------------------------------------------------ tier ladder

def test_tier_resolution_is_a_function_of_what_answered():
    assert tiers.resolve(False, False) == tiers.SOFTWARE_KEY
    assert tiers.resolve(True, False) == tiers.PRESENCE_CONFIRMED
    assert tiers.resolve(False, True) == tiers.WITNESS_COSIGNED
    assert tiers.resolve(True, True) == tiers.FULL_CUSTODY


def test_a_chain_is_quoted_at_its_weakest_tier():
    """Quoting the best tier would let one strong entry launder a weak one."""
    mixed = [tiers.FULL_CUSTODY, tiers.SOFTWARE_KEY, tiers.WITNESS_COSIGNED]
    assert tiers.lowest(mixed) == tiers.SOFTWARE_KEY


def test_every_tier_has_an_honest_description():
    for t in tiers.TIERS:
        d = tiers.describe(t)
        assert d and not d.startswith("unknown")
    # the presence tiers must never describe the device as protecting a key
    for t in (tiers.PRESENCE_CONFIRMED, tiers.FULL_CUSTODY):
        text = tiers.describe(t).lower()
        assert "secure element" not in text
        assert "protect" not in text or "does NOT protect" in tiers.describe(t)


def test_presence_predicates_match_the_ladder():
    assert tiers.has_presence(tiers.PRESENCE_CONFIRMED)
    assert tiers.has_presence(tiers.FULL_CUSTODY)
    assert not tiers.has_presence(tiers.WITNESS_COSIGNED)
    assert tiers.has_witness(tiers.WITNESS_COSIGNED)
    assert tiers.has_witness(tiers.FULL_CUSTODY)
    assert not tiers.has_witness(tiers.PRESENCE_CONFIRMED)


# ----------------------------------------------------------- presence degradation

def test_missing_pyserial_degrades_instead_of_crashing(monkeypatch):
    monkeypatch.setattr(presence, "serial", None)
    res = presence.request_presence("abcdef0123456789")
    assert res["confirmed"] is False
    assert "SOFTWARE_KEY" in res["reason"]
    assert presence.presence_ref(res) == ""


def test_no_device_found_degrades_instead_of_crashing(monkeypatch):
    monkeypatch.setattr(presence, "serial", object())
    monkeypatch.setattr(presence, "find_device", lambda: None)
    res = presence.request_presence("abcdef0123456789")
    assert res["confirmed"] is False
    assert "no serial device" in res["reason"]


def test_a_serial_error_is_a_tier_not_an_exception(monkeypatch):
    class Boom:
        def Serial(self, *a, **k):
            raise OSError("port busy")
    monkeypatch.setattr(presence, "serial", Boom())
    monkeypatch.setattr(presence, "find_device", lambda: "COM9")
    res = presence.request_presence("abcdef0123456789", port="COM9")
    assert res["confirmed"] is False
    assert "serial error" in res["reason"]


def test_presence_ref_is_empty_unless_confirmed():
    assert presence.presence_ref({"confirmed": False}) == ""
    ref = presence.presence_ref(
        {"confirmed": True, "device_id": "COM3", "nonce": "abc123",
         "shown": "deadbeefcafe0123"})
    assert ref == "COM3:abc123:deadbeefcafe0123"


def test_presence_ref_records_which_value_the_human_saw():
    """The third component is what makes the claim falsifiable. Without it any entry
    could assert PRESENCE_CONFIRMED and no verifier could contradict it."""
    ref = presence.presence_ref(
        {"confirmed": True, "device_id": "COM9", "nonce": "n1", "shown": "abc123"})
    assert ref.split(":") == ["COM9", "n1", "abc123"]


def test_a_device_id_containing_a_colon_cannot_add_a_field():
    """A port like host:8000 must not break the three-part format."""
    ref = presence.presence_ref(
        {"confirmed": True, "device_id": "host:8000", "nonce": "n", "shown": "ab"})
    assert len(ref.split(":")) == 3


def test_presence_ref_is_inside_the_signed_preimage(op_key):
    """A presence claim cannot be bolted onto an entry after it was signed."""
    c = Chain()
    e = c.append("ERASE", "d", "t", "Clear", "aa" * 32, "op", "ex",
                 tiers.PRESENCE_CONFIRMED, op_key, presence_ref="COM3:abc:00")
    e.presence_ref = "COM3:forged:00"
    assert e.recompute_hash() != e.entry_hash


def test_custody_tier_is_inside_the_signed_preimage(op_key):
    """Upgrading the tier on a stored entry must break its hash."""
    c = Chain()
    e = c.append("ERASE", "d", "t", "Clear", "aa" * 32, "op", "ex",
                 tiers.SOFTWARE_KEY, op_key)
    e.custody_tier = tiers.FULL_CUSTODY
    assert e.recompute_hash() != e.entry_hash


# --------------------------------------------------------------- keys on disk

def test_operator_key_is_created_once_and_reused(akhanda_home):
    k1 = keys.load_or_create_operator_key()
    k2 = keys.load_or_create_operator_key()
    assert key_id(k1.public_key()) == key_id(k2.public_key())
    assert keys.operator_key_path().exists()
    assert keys.operator_pub_path().exists()


def test_home_follows_the_environment_at_call_time(tmp_path, monkeypatch):
    """A home captured at import time silently ignores the env var for half the tool."""
    monkeypatch.setenv("AKHANDA_HOME", str(tmp_path / "one"))
    first = keys.home()
    monkeypatch.setenv("AKHANDA_HOME", str(tmp_path / "two"))
    assert keys.home() != first


def test_home_is_always_absolute(tmp_path, monkeypatch):
    monkeypatch.setenv("AKHANDA_HOME", "relative-dir")
    assert keys.home().is_absolute()


def test_passphrase_encrypts_the_key_at_rest(akhanda_home, monkeypatch):
    monkeypatch.setenv("AKHANDA_KEY_PASSPHRASE", "correct horse battery staple")
    keys.load_or_create_operator_key()
    pem = keys.operator_key_path().read_bytes()
    assert b"ENCRYPTED" in pem


def test_public_key_hex_round_trips(akhanda_home):
    k = keys.load_or_create_operator_key()
    hexed = keys.public_key_hex(k.public_key())
    restored = keys.public_key_from_hex(hexed)
    assert key_id(restored) == key_id(k.public_key())


# ------------------------------------------------------------------ persistence

def test_chain_survives_save_and_load(akhanda_home, op_key):
    c = Chain()
    c.append("ERASE", "disk-A", "t", "Clear", "aa" * 32, "op", "ex",
             tiers.SOFTWARE_KEY, op_key)
    path = store.save_chain(c)
    loaded = store.load_chain(path)
    assert loaded.chain_id == c.chain_id
    ok, _, _ = verify_chain(loaded.entries, op_key.public_key())
    assert ok is True


def test_loading_a_missing_chain_returns_a_fresh_one(akhanda_home):
    c = store.load_chain(akhanda_home / "nothing-here.json")
    assert c.entries == []
    assert c.chain_id


def test_chain_path_is_never_cwd_relative(akhanda_home):
    assert store.chain_path().is_absolute()
    assert store.chain_path("some/relative/chain.json").is_absolute()


def test_save_is_atomic_and_leaves_no_temp_file(akhanda_home, op_key):
    c = Chain()
    c.append("ERASE", "d", "t", "Clear", "aa" * 32, "op", "ex",
             tiers.SOFTWARE_KEY, op_key)
    path = store.save_chain(c)
    leftovers = list(path.parent.glob("*.tmp"))
    assert leftovers == []


def test_console_state_is_readable_without_the_backend(akhanda_home, op_key):
    """Role 4's acceptance test: render from this file alone."""
    c = Chain()
    c.append("RECOVER", "img.dd", "t", "Clear", "aa" * 32, "op", "ex",
             tiers.SOFTWARE_KEY, op_key)
    path = store.export_console_state(c, akhanda_home / "console" / "chain.json")
    data = json.loads(path.read_text(encoding="utf-8"))
    assert data["chain_id"] == c.chain_id
    assert data["entries"][0]["entry_hash"]
    assert data["entries"][0]["custody_tier"] == tiers.SOFTWARE_KEY
