"""
FIX #1, the concurring signature is actually verified.

Pre-mortem finding (launch-blocking): `cli verify` passed only the operator key to
verify_chain_report, so every concurring signature went unchecked. A forged expert
signature returned ok=True. The dual signature is the entire BSA s.63(4) argument, and
the command that claims to verify it did not.

Each test below is one sentence of the fix, stated as an assertion.
"""

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import cli
from attestation import keys, store, tiers
from attestation.core import Chain, key_id, verify_chain_report


def _cosign(chain, k):
    for e in chain.entries:
        chain.attach_cosignature(e.seq, k.sign(bytes.fromhex(e.entry_hash)).hex(),
                                 key_id(k.public_key()), "wh" * 32, e.seq)
    return chain


# ------------------------------------------------- the forgery that used to pass

def test_forgery_claiming_the_real_expert_key_is_caught(sample_chain, op_key, concur_key):
    """The dangerous forgery: an impostor signs but labels it with the expert's key id,
    so the record LOOKS like the expert signed. This must fail the chain."""
    _cosign(sample_chain, Ed25519PrivateKey.generate())
    for e in sample_chain.entries:
        e.concur_key_id = key_id(concur_key.public_key())
    r = verify_chain_report(sample_chain.entries, op_key.public_key(),
                            concur_key.public_key())
    assert r.ok is False
    assert "concurring signature invalid" in r.reason


def test_forgery_under_its_own_key_id_is_unverifiable_and_earns_no_credit(
        sample_chain, op_key, concur_key):
    """An impostor honest about whose key it is cannot be called forgery, we simply do
    not hold that key. What matters is that it earns NO verified credit, so nothing
    downstream can count it as an expert signature."""
    _cosign(sample_chain, Ed25519PrivateKey.generate())
    r = verify_chain_report(sample_chain.entries, op_key.public_key(),
                            concur_key.public_key())
    assert r.ok is True
    assert r.concur_verified == 0
    assert len(r.unverifiable) == 3


def test_the_old_call_still_misses_it_which_is_why_the_key_must_be_passed(
        sample_chain, op_key):
    """Regression anchor: the operator-key-only call cannot see the forgery. This test
    exists so nobody 'simplifies' the CLI back to it."""
    _cosign(sample_chain, Ed25519PrivateKey.generate())
    r = verify_chain_report(sample_chain.entries, op_key.public_key())
    assert r.ok is True
    assert r.concur_layer is False


def test_genuine_concurring_signatures_verify_and_are_counted(sample_chain, op_key,
                                                              concur_key):
    _cosign(sample_chain, concur_key)
    r = verify_chain_report(sample_chain.entries, op_key.public_key(),
                            concur_key.public_key())
    assert r.ok is True
    assert r.concur_verified == 3
    assert r.concur_layer is True


# ------------------------------------- rotation is not forgery (no false accusation)

def test_a_witness_key_we_do_not_hold_is_unverifiable_not_forged(sample_chain, op_key,
                                                                 concur_key):
    """The witness may legitimately rotate its key. That must not read as tampering."""
    _cosign(sample_chain, concur_key)
    other = Ed25519PrivateKey.generate()
    r = verify_chain_report(sample_chain.entries, op_key.public_key(), other.public_key())
    assert r.ok is True                       # not accused
    assert r.concur_verified == 0             # and not credited either
    assert len(r.unverifiable) == 3
    assert all("no witness key held" in u[2] for u in r.unverifiable)


def test_a_key_we_hold_that_rejects_the_signature_still_fails(sample_chain, op_key,
                                                              concur_key):
    """Same key_id, bad signature = forgery, not rotation."""
    _cosign(sample_chain, concur_key)
    sample_chain.entries[1].concur_sig = "00" * 64
    r = verify_chain_report(sample_chain.entries, op_key.public_key(),
                            concur_key.public_key())
    assert r.ok is False
    assert r.broken_seq == 1


def test_entries_without_a_concurring_signature_are_skipped_not_failed(sample_chain,
                                                                       op_key, concur_key):
    _cosign(sample_chain, concur_key)
    sample_chain.entries[2].concur_sig = ""
    r = verify_chain_report(sample_chain.entries, op_key.public_key(),
                            concur_key.public_key())
    assert r.ok is True
    assert r.concur_verified == 2


# ------------------------------------------------------- the key cache

def test_witness_key_round_trips_through_the_cache(akhanda_home, concur_key):
    assert keys.load_witness_key() is None
    keys.cache_witness_key(concur_key.public_key())
    loaded = keys.load_witness_key()
    assert loaded is not None
    assert key_id(loaded) == key_id(concur_key.public_key())


def test_absent_cache_returns_none_not_an_exception(akhanda_home):
    assert keys.load_witness_key() is None


def test_corrupt_cache_returns_none_rather_than_crashing_verify(akhanda_home):
    keys.witness_pub_path().parent.mkdir(parents=True, exist_ok=True)
    keys.witness_pub_path().write_bytes(b"not a pem")
    assert keys.load_witness_key() is None


def test_cached_key_is_used_without_touching_the_network(akhanda_home, concur_key,
                                                         monkeypatch):
    """Verification must work with the Pi switched off."""
    keys.cache_witness_key(concur_key.public_key())

    def boom(*a, **k):
        raise AssertionError("verify must not contact the witness when a key is cached")
    monkeypatch.setattr("witness.client.WitnessClient.pubkey", boom)

    args = cli.build_parser().parse_args(["--witness", "http://unused", "verify"])
    assert key_id(cli._witness_pubkey(args)) == key_id(concur_key.public_key())


def test_no_witness_flag_means_no_fetch_and_no_key(akhanda_home, monkeypatch):
    monkeypatch.setattr("witness.client.WitnessClient.pubkey",
                        lambda self: pytest.fail("must not fetch with --no-witness"))
    args = cli.build_parser().parse_args(["--no-witness", "verify"])
    assert cli._witness_pubkey(args) is None


# ------------------------------------------------------------ end to end via the CLI

@pytest.fixture()
def chain_file(akhanda_home, op_key, concur_key):
    keys.save_private_key(op_key)
    keys.save_public_key(op_key.public_key())
    c = Chain(chain_id="case-fix1")
    c.append("ERASE", "d0", "t0", "Clear", "00" * 32, "op", "ex",
             tiers.WITNESS_COSIGNED, op_key)
    _cosign(c, concur_key)
    store.save_chain(c, akhanda_home / "chain.json")
    return akhanda_home / "chain.json"


def test_cli_verify_reports_unverified_when_no_witness_key_is_held(chain_file,
                                                                   akhanda_home, capsys):
    rc = cli.main(["--no-witness", "--chain", str(chain_file), "verify"])
    out = capsys.readouterr().out
    assert rc == 0
    assert "NOT verified" in out
    assert "no witness public key held" in out


def test_cli_verify_confirms_the_expert_signature_when_the_key_is_cached(
        chain_file, akhanda_home, concur_key, capsys):
    keys.cache_witness_key(concur_key.public_key())
    rc = cli.main(["--no-witness", "--chain", str(chain_file), "verify"])
    out = capsys.readouterr().out
    assert rc == 0
    assert "1 of 1 concurring signature(s) re-verified" in out


def test_cli_verify_fails_loudly_on_a_forged_expert_signature(akhanda_home, op_key,
                                                              concur_key, capsys):
    keys.save_private_key(op_key)
    keys.save_public_key(op_key.public_key())
    keys.cache_witness_key(concur_key.public_key())

    c = Chain(chain_id="case-fix1")
    c.append("ERASE", "d0", "t0", "Clear", "00" * 32, "op", "ex",
             tiers.WITNESS_COSIGNED, op_key)
    _cosign(c, Ed25519PrivateKey.generate())          # impostor, same shape
    c.entries[0].concur_key_id = key_id(concur_key.public_key())   # and claims the real id
    path = akhanda_home / "chain.json"
    store.save_chain(c, path)

    rc = cli.main(["--no-witness", "--chain", str(path), "verify"])
    assert rc == 1
    assert "concurring signature invalid" in capsys.readouterr().out
