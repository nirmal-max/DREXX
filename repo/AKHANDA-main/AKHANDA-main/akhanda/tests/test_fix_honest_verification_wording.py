"""
FIX #2, the certificate names the layer that ran, and counts only verified signatures.

Pre-mortem finding (launch-blocking), two halves of one defect:

  (a) With no public key on disk, `cmd_certify` swallowed the error, ran the key-free
      layer, and printed "chain verified" with signatures_verified=0. Three evidentially
      different states, structure only / structure+operator / structure+both, all
      collapsed into one sentence, and it was the strongest of the three.

  (b) The BSA s.63(4) Part B claim was made on `dual_signed`, which counts entries that
      CARRY a second signature. An unverified or forged expert signature inflated a
      statutory claim.

Each test is one sentence of the fix.
"""

import json

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from attestation import tiers
from attestation.core import Chain, key_id, verify_chain_report
from certificate.generator import MediaInfo, Party, build_certificate, render_text


@pytest.fixture()
def signed_chain(op_key, concur_key):
    c = Chain(chain_id="case-fix2")
    c.append("ERASE", "/dev/sdb", "t0", "Clear", "cc" * 32, "op", "ex",
             tiers.WITNESS_COSIGNED, op_key)
    e = c.entries[0]
    c.attach_cosignature(0, concur_key.sign(bytes.fromhex(e.entry_hash)).hex(),
                         key_id(concur_key.public_key()), "wh" * 32, 0)
    return c


def _cert(chain, report):
    return build_certificate(chain, chain.entries, Party(name="A"), Party(name="B"),
                             MediaInfo(), chain_report=report)


# --------------------------------------------------------- (a) the three layer states

def test_structure_only_never_says_chain_verified(signed_chain):
    """The exact defect: no key available must NOT print 'chain verified'."""
    cert = _cert(signed_chain, verify_chain_report(signed_chain.entries))
    result = cert["sanitization"]["verification_result"]
    assert "structure verified only" in result
    assert "NO signature was re-checked" in result
    assert not result.startswith("chain verified")


def test_operator_only_says_which_half_was_skipped(signed_chain, op_key):
    report = verify_chain_report(signed_chain.entries, op_key.public_key())
    result = _cert(signed_chain, report)["sanitization"]["verification_result"]
    assert "operator signatures re-checked" in result
    assert "concurring signatures NOT checked" in result


def test_both_layers_earns_the_strongest_wording(signed_chain, op_key, concur_key):
    report = verify_chain_report(signed_chain.entries, op_key.public_key(),
                                 concur_key.public_key())
    result = _cert(signed_chain, report)["sanitization"]["verification_result"]
    assert "operator signatures, and concurring signatures all re-checked" in result


def test_a_broken_chain_still_shouts_regardless_of_layer(signed_chain, op_key):
    signed_chain.entries[0].result_hash = "ff" * 32
    report = verify_chain_report(signed_chain.entries, op_key.public_key())
    result = _cert(signed_chain, report)["sanitization"]["verification_result"]
    assert result == "CHAIN VERIFICATION FAILED"


def test_no_report_at_all_says_not_reverified(signed_chain):
    cert = build_certificate(signed_chain, signed_chain.entries, Party(), Party(),
                             MediaInfo())
    assert cert["sanitization"]["verification_result"] == "not re-verified at issue time"


# ------------------------------------------- (a) the limits must disclose the gap

def test_structure_only_adds_an_explicit_limit(signed_chain):
    cert = _cert(signed_chain, verify_chain_report(signed_chain.entries))
    assert any("NO SIGNATURE WAS RE-VERIFIED" in l for l in cert["limits"])


def test_operator_only_discloses_the_unchecked_expert_signatures(signed_chain, op_key):
    report = verify_chain_report(signed_chain.entries, op_key.public_key())
    cert = _cert(signed_chain, report)
    assert any("CONCURRING SIGNATURES NOT RE-VERIFIED" in l for l in cert["limits"])


def test_full_verification_drops_both_warnings(signed_chain, op_key, concur_key):
    report = verify_chain_report(signed_chain.entries, op_key.public_key(),
                                 concur_key.public_key())
    limits = _cert(signed_chain, report)["limits"]
    assert not any("NO SIGNATURE WAS RE-VERIFIED" in l for l in limits)
    assert not any("CONCURRING SIGNATURES NOT RE-VERIFIED" in l for l in limits)
    assert not any("UNVERIFIED SECOND SIGNATURES" in l for l in limits)


# ------------------------------- (b) the BSA Part B claim rests on VERIFIED signatures

def test_unverified_expert_signature_earns_no_part_b_credit(signed_chain, op_key):
    """A second signature nobody checked must not count toward the statutory claim."""
    report = verify_chain_report(signed_chain.entries, op_key.public_key())
    cert = _cert(signed_chain, report)
    ct = cert["chain"]["custody_tier"]
    assert ct["dual_signed_entries"] == 1        # recorded
    assert ct["dual_verified_entries"] == 0      # but not verified


def test_forged_expert_signature_under_its_own_key_id_earns_no_credit(signed_chain,
                                                                      op_key, concur_key):
    impostor = Ed25519PrivateKey.generate()
    e = signed_chain.entries[0]
    e.concur_sig = impostor.sign(bytes.fromhex(e.entry_hash)).hex()
    e.concur_key_id = key_id(impostor.public_key())

    report = verify_chain_report(signed_chain.entries, op_key.public_key(),
                                 concur_key.public_key())
    cert = _cert(signed_chain, report)
    assert report.ok is True                                   # unverifiable, not forged
    assert cert["chain"]["custody_tier"]["dual_verified_entries"] == 0
    assert any("UNVERIFIED SECOND SIGNATURES" in l for l in cert["limits"])


def test_verified_expert_signature_does_earn_credit(signed_chain, op_key, concur_key):
    report = verify_chain_report(signed_chain.entries, op_key.public_key(),
                                 concur_key.public_key())
    cert = _cert(signed_chain, report)
    assert cert["chain"]["custody_tier"]["dual_verified_entries"] == 1


def test_the_limit_names_the_verified_count_as_the_basis_of_the_claim(signed_chain,
                                                                     op_key):
    report = verify_chain_report(signed_chain.entries, op_key.public_key())
    cert = _cert(signed_chain, report)
    line = next(l for l in cert["limits"] if "UNVERIFIED SECOND SIGNATURES" in l)
    assert "made on the verified count (0)" in line


def test_part_b_block_reports_reverification_explicitly(signed_chain, op_key,
                                                        concur_key):
    report = verify_chain_report(signed_chain.entries, op_key.public_key(),
                                 concur_key.public_key())
    cert = _cert(signed_chain, report)
    note = cert["signatures"]["part_b"]["reverification_note"]
    assert "1 of 1 recorded expert signature(s) re-verified" in note
    assert cert["signatures"]["part_b"]["signatures_reverified"] == 1


def test_part_b_block_says_so_when_no_key_was_held(signed_chain, op_key):
    report = verify_chain_report(signed_chain.entries, op_key.public_key())
    note = _cert(signed_chain, report)["signatures"]["part_b"]["reverification_note"]
    assert "reported as recorded, not as verified" in note


# -------------------------------------------------------------------- rendering

def test_text_render_shows_recorded_and_reverified_separately(signed_chain, op_key):
    report = verify_chain_report(signed_chain.entries, op_key.public_key())
    text = render_text(_cert(signed_chain, report))
    flat = " ".join(text.split())
    assert "1 of 1 performed operation(s) recorded; 0 re-verified" in flat


def test_text_render_carries_the_part_b_note(signed_chain, op_key, concur_key):
    report = verify_chain_report(signed_chain.entries, op_key.public_key(),
                                 concur_key.public_key())
    text = render_text(_cert(signed_chain, report))
    flat = " ".join(text.split())          # the renderer wraps to 78 columns
    assert "1 of 1 recorded expert signature(s) re-verified against a held public key" in flat


def test_no_certificate_state_prints_the_bare_words_chain_verified(signed_chain, op_key,
                                                                   concur_key):
    """Belt and braces: the ambiguous string must not survive anywhere in any state."""
    for report in (
        verify_chain_report(signed_chain.entries),
        verify_chain_report(signed_chain.entries, op_key.public_key()),
        verify_chain_report(signed_chain.entries, op_key.public_key(),
                            concur_key.public_key()),
    ):
        result = _cert(signed_chain, report)["sanitization"]["verification_result"]
        assert result != "chain verified"
