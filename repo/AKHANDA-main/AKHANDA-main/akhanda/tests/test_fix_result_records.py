"""
FIX #3, the chain commits to a record that is actually kept.

Pre-mortem finding (launch-blocking): `result_hash` covers the full operation record , 
sample offsets, read-back digests, the `verified` flag, every carved artefact. Writing
it was opt-in via `--result-out`, so by default the ledger held a hash of a file that had
been discarded. "What does this hash commit to?" had the answer "a record we didn't
keep", which is an evidence gap wearing a cryptography costume.

Also covers the canonicalisation consolidation: three call sites, one digest rule.
"""

import json

import pytest

import cli
from attestation import canonical, keys, store, tiers
from attestation.canonical import RESULT_DOMAIN, canonical_bytes, result_digest
from attestation.core import Chain
from erasure import engine as erasure
from recovery import engine as recovery


from conftest import real_image_bytes  # noqa: E402


@pytest.fixture()
def image(tmp_path):
    """A real encoded JPEG, not a byte pattern that resembles one. The carver's
    structural validators reject hand-faked headers, and correctly so."""
    p = tmp_path / "evidence.dd"
    p.write_bytes(b"\x00" * 256 + real_image_bytes("JPEG") + b"\x00" * 256)
    return p


@pytest.fixture()
def base_args(akhanda_home):
    return ["--no-witness", "--no-presence", "--chain", str(akhanda_home / "chain.json")]


# ------------------------------------------------- one canonicalisation, not three

def test_all_three_call_sites_share_one_digest_rule():
    obj = {"b": 2, "a": [1, {"z": 0, "y": 1}]}
    assert erasure.result_hash(obj) == result_digest(obj)
    assert recovery.result_hash(obj) == result_digest(obj)


def test_digest_is_key_order_independent():
    assert result_digest({"a": 1, "b": 2}) == result_digest({"b": 2, "a": 1})


def test_digest_changes_when_any_value_changes():
    base = {"verified": True, "method_used": "Clear"}
    assert result_digest(base) != result_digest({**base, "verified": False})
    assert result_digest(base) != result_digest({**base, "method_used": "Purge"})


def test_digest_is_domain_separated_from_entry_preimages():
    """A result digest must not be replayable as an entry hash."""
    assert canonical_bytes({}) != RESULT_DOMAIN + canonical_bytes({})
    import hashlib
    naive = hashlib.sha256(canonical_bytes({"a": 1})).hexdigest()
    assert result_digest({"a": 1}) != naive


def test_non_ascii_is_stored_as_itself_not_escaped():
    """The digest is over the text a human reads in the file."""
    assert "दिल्ली".encode("utf-8") in canonical_bytes({"op": "दिल्ली"})


# --------------------------------------------------------- the store round-trips

def test_result_is_stored_and_reloaded(akhanda_home):
    result = {"method_used": "Clear", "verified": True, "sample_results": []}
    path = store.save_result("ab" * 32, result)
    assert path.exists()
    assert store.load_result("ab" * 32) == result


def test_record_is_named_by_entry_hash_so_it_can_be_found(akhanda_home):
    """An investigator holding an entry must find its evidence without computing."""
    store.save_result("cd" * 32, {"x": 1})
    assert store.result_path("cd" * 32).name == "cd" * 32 + ".json"


def test_missing_record_returns_none_not_an_exception(akhanda_home):
    assert store.load_result("ff" * 32) is None


def test_corrupt_record_returns_none(akhanda_home):
    store.results_dir().mkdir(parents=True, exist_ok=True)
    store.result_path("ee" * 32).write_text("{not json", encoding="utf-8")
    assert store.load_result("ee" * 32) is None


def test_save_leaves_no_temp_file(akhanda_home):
    store.save_result("ab" * 32, {"x": 1})
    assert list(store.results_dir().glob("*.tmp")) == []


# ----------------------------------------------- the three verification outcomes

def _entry_with(result, op_key, akhanda_home, store_it=True):
    c = Chain(chain_id="case-fix3")
    e = c.append("ERASE", "d", "t", "Clear", result_digest(result), "op", "ex",
                 tiers.SOFTWARE_KEY, op_key)
    if store_it:
        store.save_result(e.entry_hash, result)
    return c, e


def test_present_and_matching_is_reported_as_ok(akhanda_home, op_key):
    c, e = _entry_with({"verified": True}, op_key, akhanda_home)
    r = store.verify_result(e)
    assert r["present"] is True and r["ok"] is True


def test_missing_record_is_present_false_not_ok_true(akhanda_home, op_key):
    """Absence must never read as agreement."""
    c, e = _entry_with({"verified": True}, op_key, akhanda_home, store_it=False)
    r = store.verify_result(e)
    assert r["present"] is False
    assert r["ok"] is False
    assert "no result record stored" in r["reason"]


def test_altered_record_is_detected(akhanda_home, op_key):
    """The entry's own signature stays valid, so ONLY this check catches it."""
    result = {"verified": False, "method_used": "Clear"}
    c, e = _entry_with(result, op_key, akhanda_home)
    store.save_result(e.entry_hash, {**result, "verified": True})   # flip the flag
    r = store.verify_result(e)
    assert r["present"] is True
    assert r["ok"] is False
    assert "altered after signing" in r["reason"]


def test_chain_rollup_separates_missing_from_altered(akhanda_home, op_key):
    c = Chain(chain_id="case-fix3")
    good = {"n": 1}
    e0 = c.append("ERASE", "d0", "t", "Clear", result_digest(good), "op", "ex",
                  tiers.SOFTWARE_KEY, op_key)
    e1 = c.append("ERASE", "d1", "t", "Clear", result_digest({"n": 2}), "op", "ex",
                  tiers.SOFTWARE_KEY, op_key)
    e2 = c.append("ERASE", "d2", "t", "Clear", result_digest({"n": 3}), "op", "ex",
                  tiers.SOFTWARE_KEY, op_key)
    store.save_result(e0.entry_hash, good)
    store.save_result(e2.entry_hash, {"n": 99})          # altered
    # e1 never stored -> missing

    roll = store.verify_all_results(c)
    assert roll["matched"] == 1
    assert roll["missing"] == [1]
    assert roll["altered"] == [2]


# ------------------------------------------------------------- end to end via CLI

def test_recover_persists_its_record_by_default(akhanda_home, base_args, image):
    cli.main(base_args + ["init"])
    cli.main(base_args + ["recover", str(image)])
    chain = store.load_chain(akhanda_home / "chain.json")
    stored = store.load_result(chain.entries[0].entry_hash)
    assert stored is not None
    assert stored[0]["type"] == "jpg"
    assert result_digest(stored) == chain.entries[0].result_hash


def test_erase_persists_its_record_by_default(akhanda_home, base_args, tmp_path):
    target = tmp_path / "wipe.img"
    target.write_bytes(b"SECRET" * 1000)
    cli.main(base_args + ["init"])
    cli.main(base_args + ["erase", str(target)])
    chain = store.load_chain(akhanda_home / "chain.json")
    stored = store.load_result(chain.entries[0].entry_hash)
    assert stored["method_used"] == "Clear"
    assert stored["sample_results"]                       # the actual evidence
    assert result_digest(stored) == chain.entries[0].result_hash


def test_verify_reports_records_present_and_matching(akhanda_home, base_args, image,
                                                     capsys):
    cli.main(base_args + ["init"])
    cli.main(base_args + ["recover", str(image)])
    cli.main(base_args + ["verify"])
    assert "1 of 1 result record(s) present and matching" in capsys.readouterr().out


def test_verify_flags_a_deleted_record_but_does_not_fail(akhanda_home, base_args,
                                                         image, capsys):
    """A missing record is an evidence problem, not a forgery. Report, do not fail."""
    cli.main(base_args + ["init"])
    cli.main(base_args + ["recover", str(image)])
    chain = store.load_chain(akhanda_home / "chain.json")
    store.result_path(chain.entries[0].entry_hash).unlink()

    rc = cli.main(base_args + ["verify"])
    out = capsys.readouterr().out
    assert rc == 0
    assert "MISSING for entries [0]" in out
    assert "commits to evidence that is not on disk" in out


def test_verify_fails_on_an_altered_record(akhanda_home, base_args, tmp_path, capsys):
    """The exact laundering attack: flip verified=False to True in the stored record."""
    target = tmp_path / "wipe.img"
    target.write_bytes(b"SECRET" * 1000)
    cli.main(base_args + ["init"])
    cli.main(base_args + ["erase", str(target)])

    chain = store.load_chain(akhanda_home / "chain.json")
    path = store.result_path(chain.entries[0].entry_hash)
    doctored = json.loads(path.read_text(encoding="utf-8"))
    doctored["method_used"] = "Purge"                     # the overclaim
    path.write_text(json.dumps(doctored, indent=2), encoding="utf-8")

    rc = cli.main(base_args + ["verify"])
    out = capsys.readouterr().out
    assert rc == 1
    assert "ALTERED for entries [0]" in out
    assert "no longer matches the hash the entry signed" in out


def test_the_entry_signature_alone_would_not_have_caught_that(akhanda_home, base_args,
                                                              tmp_path):
    """Proves the previous test is testing something new: the chain still verifies."""
    from attestation.core import verify_chain_report
    target = tmp_path / "wipe.img"
    target.write_bytes(b"SECRET" * 1000)
    cli.main(base_args + ["init"])
    cli.main(base_args + ["erase", str(target)])

    chain = store.load_chain(akhanda_home / "chain.json")
    path = store.result_path(chain.entries[0].entry_hash)
    doctored = json.loads(path.read_text(encoding="utf-8"))
    doctored["method_used"] = "Purge"
    path.write_text(json.dumps(doctored), encoding="utf-8")

    assert verify_chain_report(chain.entries, keys.load_public_key()).ok is True
    assert store.verify_all_results(chain)["altered"] == [0]


def test_result_out_still_works_as_an_extra_copy(akhanda_home, base_args, image,
                                                 tmp_path):
    cli.main(base_args + ["init"])
    extra = tmp_path / "copy.json"
    cli.main(base_args + ["recover", str(image), "--result-out", str(extra)])
    chain = store.load_chain(akhanda_home / "chain.json")
    assert extra.exists()
    assert store.load_result(chain.entries[0].entry_hash) is not None
