"""
Witness client tests, the divergence detection that is the project's actual argument.

`test_full_chain_rewrite_is_detected_by_the_witness` is the centrepiece. It performs the
attack no single-machine ledger can catch: the operator regenerates every entry, every
hash, and every one of their own signatures, producing a chain that verifies perfectly
on its own terms. The witness's independent head record is what exposes it.

`test_witness_head_construction_matches_the_node` guards a contract that spans two
machines. If the Pi's head construction and the workstation's ever drift apart, the tool
reports a rewrite that never happened, a false accusation, which is worse than a miss.
"""

import hashlib

import pytest

from attestation.core import Chain, key_id
from attestation import tiers
from witness import client as wc
from witness.client import WitnessClient, compare_witness_head, witness_head_chain


def _cosign_all(chain, concur_key):
    """Simulate the Pi co-signing every entry and extending its own head record."""
    head = "00" * 32
    records = []
    for e in chain.entries:
        sig = concur_key.sign(bytes.fromhex(e.entry_hash)).hex()
        head = hashlib.sha256((head + e.entry_hash).encode()).hexdigest()
        chain.attach_cosignature(e.seq, sig, key_id(concur_key.public_key()),
                                 head, len(records))
        records.append(head)
    return {"ok": True, "head_hash": head, "seq": chain.entries[-1].seq,
            "count": len(records), "reason": "witness head read"}


# --------------------------------------------------------------- head construction

def test_witness_head_construction_matches_the_node():
    """Contract shared with src/witness/node.py. Both sides must agree byte for byte."""
    hashes = ["aa" * 32, "bb" * 32, "cc" * 32]
    expected = "00" * 32
    for h in hashes:
        expected = hashlib.sha256((expected + h).encode()).hexdigest()
    assert witness_head_chain(hashes) == expected


def test_witness_head_is_order_sensitive():
    a = witness_head_chain(["aa" * 32, "bb" * 32])
    b = witness_head_chain(["bb" * 32, "aa" * 32])
    assert a != b


def test_empty_witness_head_is_genesis():
    assert witness_head_chain([]) == "00" * 32


# ------------------------------------------------------------ divergence detection

def test_agreeing_chain_and_witness_report_agreement(sample_chain, concur_key):
    state = _cosign_all(sample_chain, concur_key)
    result = compare_witness_head(sample_chain, state)
    assert result["checked"] is True
    assert result["diverged"] is False


def test_full_chain_rewrite_is_detected_by_the_witness(op_key, concur_key):
    """THE centrepiece. A rewrite that passes every local check still fails here."""
    original = Chain(chain_id="case-1")
    for i in range(3):
        original.append("ERASE", f"disk-{i}", f"2026-01-01T10:0{i}:00Z", "Clear",
                        f"{i:02x}" * 32, "op", "ex", tiers.WITNESS_COSIGNED, op_key)
    witness_state = _cosign_all(original, concur_key)

    # The operator now rebuilds the whole chain with one operation removed from history,
    # re-signing everything. Locally this chain is flawless.
    rewritten = Chain(chain_id="case-1")
    for i in (0, 2):
        rewritten.append("ERASE", f"disk-{i}", f"2026-01-01T10:0{i}:00Z", "Clear",
                         f"{i:02x}" * 32, "op", "ex", tiers.WITNESS_COSIGNED, op_key)
    for e, src in zip(rewritten.entries, [original.entries[0], original.entries[2]]):
        rewritten.attach_cosignature(e.seq, src.concur_sig, src.concur_key_id,
                                     src.witness_head_hash, src.witness_seq)

    result = compare_witness_head(rewritten, witness_state)
    assert result["checked"] is True
    assert result["diverged"] is True
    assert result["at_seq"] is not None


def test_edited_entry_after_cosigning_is_detected(sample_chain, concur_key):
    state = _cosign_all(sample_chain, concur_key)
    e = sample_chain.entries[1]
    e.result_hash = "ff" * 32
    e.entry_hash = e.recompute_hash()
    result = compare_witness_head(sample_chain, state)
    assert result["diverged"] is True


# -------------------------------------------------------------- honest unknowns

def test_unreachable_witness_is_unchecked_not_agreement(sample_chain):
    """An absent witness must never read as a passing check."""
    result = compare_witness_head(
        sample_chain, {"ok": False, "reason": "witness unreachable at http://pi:8000"})
    assert result["checked"] is False
    assert result["diverged"] is False
    assert "unreachable" in result["reason"]


def test_chain_with_no_cosignatures_is_unchecked(sample_chain):
    result = compare_witness_head(
        sample_chain, {"ok": True, "head_hash": "00" * 32, "seq": -1, "count": 0})
    assert result["checked"] is False
    assert "ever co-signed" in result["reason"]


# ------------------------------------------------------------- tail truncation (G25)
#
# A truncated chain is the one attack that passes EVERY local check. Cut the tail off and
# seq is still contiguous from 0, every prev_hash still links, every entry still re-hashes
# to its stated hash, and every signature still verifies. There is nothing inside a chain
# that knows how long the chain was supposed to be. Only the witness's independent count
# knows, which is the argument for the second machine stated as a test.


def test_truncating_cosigned_entries_is_detected_not_reported_as_agreement(
        sample_chain, concur_key):
    """Drop the tail after co-signing; the witness still counts what it signed."""
    state = _cosign_all(sample_chain, concur_key)
    assert state["count"] >= 2, "fixture must have enough entries to truncate"

    sample_chain.entries = sample_chain.entries[:-1]

    result = compare_witness_head(sample_chain, state)
    assert result["checked"] is True
    assert result["diverged"] is True
    assert "removed from the workstation chain after co-signing" in result["reason"]


def test_truncating_every_cosignature_does_not_go_quiet(sample_chain, concur_key):
    """THE REGRESSION THIS EXISTS FOR. Deleting MORE must not produce a WEAKER verdict.

    The old code selected the co-signed entries first and, finding none, returned
    checked=False / "no entry was ever co-signed", a verdict indistinguishable from an
    honest chain that never used a witness at all. So truncating back past the FIRST
    co-signature was strictly safer for an attacker than truncating back to just after
    it: delete some entries and you are caught, delete all of them and the verifier
    reports nothing to see. The witness's own count is what closes that.
    """
    state = _cosign_all(sample_chain, concur_key)
    signed_count = state["count"]

    # Remove every co-signature the workstation holds, as a rewrite would.
    for e in sample_chain.entries:
        e.concur_sig = ""

    result = compare_witness_head(sample_chain, state)
    assert result["checked"] is True, "must not degrade to unchecked"
    assert result["diverged"] is True, "deleting more must not be quieter than deleting less"
    assert str(signed_count) in result["reason"]


def test_a_chain_shorter_than_the_witness_names_how_many_are_missing(
        sample_chain, concur_key):
    state = _cosign_all(sample_chain, concur_key)
    kept = 1
    missing = state["count"] - kept
    sample_chain.entries = sample_chain.entries[:kept]

    result = compare_witness_head(sample_chain, state)
    assert result["diverged"] is True
    assert str(missing) in result["reason"]


def test_a_witness_that_counted_nothing_still_reads_as_unchecked(sample_chain):
    """The fix must not turn an honest never-used-a-witness chain into a divergence."""
    result = compare_witness_head(
        sample_chain, {"ok": True, "head_hash": "00" * 32, "seq": -1, "count": 0})
    assert result["checked"] is False
    assert result["diverged"] is False


# ------------------------------------------------------------------- client I/O

def test_cosign_degrades_when_the_node_is_down(monkeypatch):
    def boom(*a, **k):
        raise OSError("no route to host")
    monkeypatch.setattr(wc, "_post", boom)
    res = WitnessClient("http://10.0.0.99:8000").cosign(0, "aa" * 32)
    assert res["ok"] is False
    assert res["concur_sig"] == ""
    assert "unreachable" in res["reason"]


def test_head_degrades_when_the_node_is_down(monkeypatch):
    def boom(*a, **k):
        raise OSError("timed out")
    monkeypatch.setattr(wc, "_get", boom)
    res = WitnessClient("http://10.0.0.99:8000").head()
    assert res["ok"] is False
    assert res["count"] == 0


def test_pubkey_returns_none_when_the_node_is_down(monkeypatch):
    def boom(*a, **k):
        raise OSError("timed out")
    monkeypatch.setattr(wc, "_get", boom)
    assert WitnessClient("http://10.0.0.99:8000").pubkey() is None


def test_cosign_attaches_the_witness_record_to_the_entry(monkeypatch, sample_chain,
                                                         concur_key):
    e = sample_chain.entries[0]
    sig = concur_key.sign(bytes.fromhex(e.entry_hash)).hex()
    monkeypatch.setattr(wc, "_post", lambda *a, **k: {
        "concur_sig": sig, "witness_head_hash": "wh" * 32, "witness_seq": 0,
        "concur_key_id": key_id(concur_key.public_key()),
    })
    res = WitnessClient().cosign(0, e.entry_hash)
    assert res["ok"] is True
    sample_chain.attach_cosignature(0, res["concur_sig"], res["concur_key_id"],
                                    res["witness_head_hash"], res["witness_seq"])
    assert sample_chain.entries[0].is_dual_signed()
    assert sample_chain.entries[0].witness_head_hash == "wh" * 32
