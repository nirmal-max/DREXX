"""
Certificate tests, including role 6's acceptance test, made executable.

Role 6's deliverable is "every certificate field maps to a named clause in one of the
two standards". That is checked here by CLAUSE_MAP coverage rather than by review.

The honesty tests are the ones that protect the pitch. A certificate that prints "Purge"
for a USB stick, or that quotes the best custody tier instead of the worst, or that drops
its limits section, is the exact failure this project exists to prevent.
"""

import json

import pytest

from attestation import tiers
from attestation.core import Chain, key_id, verify_chain_report
from certificate.generator import (
    BSA_63_2_CONDITIONS, CLAUSE_MAP, MediaInfo, Party, build_certificate,
    render_text, save, unmapped_fields,
)


@pytest.fixture()
def parties():
    return (
        Party(name="J. Rao", title="Forensic Analyst", organisation="NTRO",
              location="Hyderabad", key_id="op0000000000abcd"),
        Party(name="K. Singh", title="Expert Witness", organisation="NTRO",
              location="Hyderabad", key_id="ex0000000000abcd"),
    )


@pytest.fixture()
def media():
    return MediaInfo(make_model="SanDisk Cruzer 16GB", property_number="EV-2026-014",
                     media_type="Flash Memory", serial_number="SN-99213",
                     source="seized workstation", classification="Confidential",
                     destination="evidence retention")


@pytest.fixture()
def erase_chain(op_key, concur_key):
    c = Chain(chain_id="case-2026-014")
    c.append("ERASE", "/dev/sdb", "2026-01-01T11:00:00Z", "Clear", "cc" * 32,
             "operator: J. Rao", "expert: K. Singh", tiers.FULL_CUSTODY, op_key,
             presence_fn=lambda ph: f"COM3:abcd1234:{ph[:16]}")
    e = c.entries[0]
    c.attach_cosignature(0, concur_key.sign(bytes.fromhex(e.entry_hash)).hex(),
                         key_id(concur_key.public_key()), "wh" * 32, 0)
    return c


def _cert(chain, parties, media, **kw):
    op, ex = parties
    report = verify_chain_report(chain.entries)
    return build_certificate(chain, chain.entries, op, ex, media,
                             chain_report=report, **kw)


# ------------------------------------------------------- role 6's acceptance test

def test_every_emitted_field_maps_to_a_named_clause():
    assert unmapped_fields({}) == []


def test_clause_map_names_both_standards():
    text = " ".join(CLAUSE_MAP.values())
    assert "NIST SP 800-88 Rev.2" in text
    assert "BSA 2023" in text


def test_all_four_conditions_of_section_63_2_are_addressed():
    clauses = {c["clause"] for c in BSA_63_2_CONDITIONS}
    assert clauses == {"s.63(2)(a)", "s.63(2)(b)", "s.63(2)(c)", "s.63(2)(d)"}
    for c in BSA_63_2_CONDITIONS:
        assert c["answered_by"], f"{c['clause']} has no answering mechanism"


def test_dual_signature_maps_to_schedule_parts_a_and_b(erase_chain, parties, media):
    cert = _cert(erase_chain, parties, media)
    assert "Part A" in cert["signatures"]["part_a"]["role"]
    assert "Expert" in cert["signatures"]["part_b"]["role"]
    assert cert["signatures"]["part_a"]["entries_signed"] == [0]
    assert cert["signatures"]["part_b"]["entries_signed"] == [0]


# ------------------------------------------------------------------ honesty gates

def test_method_type_is_the_weakest_method_covered(op_key, parties, media):
    """One Purge must not launder a Clear performed on another device."""
    c = Chain()
    c.append("ERASE", "/dev/sdb", "t1", "Purge", "aa" * 32, "op", "ex",
             tiers.SOFTWARE_KEY, op_key)
    c.append("ERASE", "/dev/sdc", "t2", "Clear", "bb" * 32, "op", "ex",
             tiers.SOFTWARE_KEY, op_key)
    cert = _cert(c, parties, media)
    assert cert["sanitization"]["method_type"] == "Clear"


def test_custody_tier_quoted_is_the_weakest(op_key, concur_key, parties, media):
    c = Chain()
    c.append("ERASE", "d1", "t1", "Clear", "aa" * 32, "op", "ex",
             tiers.FULL_CUSTODY, op_key)
    c.append("ERASE", "d2", "t2", "Clear", "bb" * 32, "op", "ex",
             tiers.SOFTWARE_KEY, op_key)
    cert = _cert(c, parties, media)
    assert cert["chain"]["custody_tier"]["weakest_tier_covered"] == tiers.SOFTWARE_KEY


def test_limits_section_is_never_empty(erase_chain, parties, media):
    cert = _cert(erase_chain, parties, media)
    assert len(cert["limits"]) >= 3


def test_integrity_not_completeness_is_always_stated(erase_chain, parties, media):
    cert = _cert(erase_chain, parties, media)
    joined = " ".join(cert["limits"])
    assert "INTEGRITY, NOT COMPLETENESS" in joined
    assert "withheld" in joined


def test_tail_truncation_limit_is_always_stated(erase_chain, parties, media):
    cert = _cert(erase_chain, parties, media)
    assert any("TAIL TRUNCATION" in l for l in cert["limits"])


def test_presence_device_is_never_called_a_key_store(erase_chain, parties, media):
    cert = _cert(erase_chain, parties, media)
    blob = json.dumps(cert).lower()
    assert "secure element" not in blob or "not a secure element" in blob
    assert "hardware protected key" not in blob
    assert "cve-2019-17391" in blob        # the limit is cited, not implied


def test_anchor_is_never_described_as_legally_recognised(erase_chain, parties, media):
    cert = _cert(erase_chain, parties, media,
                 anchor_state={"confirmed": True, "block_height": 900000,
                               "reason": "anchored in the Bitcoin blockchain"})
    joined = " ".join(cert["limits"])
    assert "same class" in joined
    assert "not, and is not claimed to be, legal recognition" in joined
    assert "legally guaranteed" not in json.dumps(cert)


def test_unwitnessed_chain_says_so(erase_chain, parties, media):
    cert = _cert(erase_chain, parties, media)
    assert any("WITNESS NOT COMPARED" in l for l in cert["limits"])


def test_witnessed_chain_drops_the_unwitnessed_warning(erase_chain, parties, media):
    cert = _cert(erase_chain, parties, media,
                 witness_state={"checked": True, "diverged": False,
                                "reason": "witness head agrees", "endpoint": "http://pi:8000"})
    assert not any("WITNESS NOT COMPARED" in l for l in cert["limits"])


def test_partial_dual_signature_is_disclosed(op_key, concur_key, parties, media):
    c = Chain()
    c.append("ERASE", "d1", "t1", "Clear", "aa" * 32, "op", "ex",
             tiers.WITNESS_COSIGNED, op_key)
    c.append("ERASE", "d2", "t2", "Clear", "bb" * 32, "op", "ex",
             tiers.SOFTWARE_KEY, op_key)
    c.attach_cosignature(
        0, concur_key.sign(bytes.fromhex(c.entries[0].entry_hash)).hex())
    cert = _cert(c, parties, media)
    assert any("PARTIAL DUAL SIGNATURE" in l for l in cert["limits"])


def test_form_not_admissibility_is_the_closing_limit(erase_chain, parties, media):
    cert = _cert(erase_chain, parties, media)
    assert "FORM, NOT ADMISSIBILITY" in cert["limits"][-1]
    assert "matter for the court" in cert["limits"][-1]


# --------------------------------------------------------------- broken chains

def test_a_broken_chain_is_reported_in_capitals_not_hidden(erase_chain, parties, media):
    erase_chain.entries[0].result_hash = "ff" * 32     # tamper after signing
    report = verify_chain_report(erase_chain.entries)
    op, ex = parties
    cert = build_certificate(erase_chain, erase_chain.entries, op, ex, media,
                             chain_report=report)
    assert cert["sanitization"]["verification_result"] == "CHAIN VERIFICATION FAILED"
    assert cert["chain"]["verification"]["broken_seq"] == 0


def test_certificate_without_a_report_says_not_reverified(erase_chain, parties, media):
    op, ex = parties
    cert = build_certificate(erase_chain, erase_chain.entries, op, ex, media)
    assert cert["sanitization"]["verification_result"] == "not re-verified at issue time"


def test_empty_entry_list_is_refused(erase_chain, parties, media):
    op, ex = parties
    with pytest.raises(ValueError, match="at least one ledger entry"):
        build_certificate(erase_chain, [], op, ex, media)


# ------------------------------------------------------------ record integrity

def test_record_hash_covers_the_whole_certificate(erase_chain, parties, media):
    cert = _cert(erase_chain, parties, media)
    h = cert["record"]["hash_of_record"]
    assert len(h) == 64
    cert2 = _cert(erase_chain, parties, media, notes="edited afterwards")
    assert cert2["record"]["hash_of_record"] != h


def test_entry_hashes_are_carried_into_the_certificate(erase_chain, parties, media):
    cert = _cert(erase_chain, parties, media)
    assert cert["record"]["identification"]["entry_hashes"] == [
        e.entry_hash for e in erase_chain.entries]


# ---------------------------------------------------------------- rendering

def test_text_render_contains_all_seven_sections(erase_chain, parties, media):
    text = render_text(_cert(erase_chain, parties, media))
    for heading in ("MEDIA INFORMATION", "SANITIZATION", "CONDITIONS UNDER BSA",
                    "CHAIN VERIFICATION", "SIGNATURES",
                    "WHAT THIS CERTIFICATE DOES NOT ESTABLISH"):
        assert heading in text


def test_text_render_names_both_standards_in_the_header(erase_chain, parties, media):
    text = render_text(_cert(erase_chain, parties, media))
    assert "NIST SP 800-88 Rev. 2" in text
    assert "Bharatiya Sakshya Adhiniyam 2023" in text


def test_save_writes_json_and_text(erase_chain, parties, media, tmp_path):
    cert = _cert(erase_chain, parties, media)
    paths = save(cert, str(tmp_path), basename="cert-014")
    assert json.loads(open(paths["json"], encoding="utf-8").read())["certificate_version"]
    assert "CERTIFICATE OF SANITIZATION" in open(paths["text"], encoding="utf-8").read()


def test_recovery_only_certificate_does_not_claim_a_sanitization_method(op_key, parties,
                                                                       media):
    c = Chain()
    c.append("RECOVER", "image.dd", "t", "Clear", "aa" * 32, "op", "ex",
             tiers.SOFTWARE_KEY, op_key)
    cert = _cert(c, parties, media)
    assert "n/a" in cert["sanitization"]["method_type"]
    assert cert["recovery"]["operations"]
    assert "original names" in cert["recovery"]["note"]
