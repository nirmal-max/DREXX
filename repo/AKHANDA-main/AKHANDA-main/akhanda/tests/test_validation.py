"""Sanitization validation, NIST SP 800-88 Rev. 2 §4.5.2.

Rev. 2 splits sanitization assurance into VERIFICATION (inspect the outcome) and VALIDATION
(a decision to approve or reject). The Appendix C certificate carries both as separate
fields. AKHANDA implemented verification and called it done; `verified` and `outcome` are
verification outputs and **nobody decided anything**.

The property most of these tests defend is the one that is tempting to break: **the tool
must never decide.** §4.5.2 weighs "the sanitization outcomes and the sensitivity of the
target data" and turns on whether "the organization accepts any residual risks". Software
knows the outcomes and nothing else. A tool that auto-approves has not implemented
validation, it has renamed verification and buried a human judgement in a boolean.
"""
from __future__ import annotations

import sys
import tempfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from attestation import validation as v  # noqa: E402
from erasure.engine import CONFIRM_TOKEN, erase  # noqa: E402


@pytest.fixture(scope="module")
def clean_result():
    img = Path(tempfile.mkdtemp()) / "clean.img"
    img.write_bytes(b"\xAB" * (1 << 20))
    return erase(str(img), confirm=CONFIRM_TOKEN)


@pytest.fixture
def flash_result(clean_result):
    """A Clear on flash, the standard's own overprovisioning example."""
    return dict(clean_result, media_kind="block", method_used="Clear",
                media_note="removable flash: no ATA Secure Erase and no NVMe Sanitize")


@pytest.fixture
def bad_sector_result(clean_result):
    return dict(clean_result,
                bad_ranges=[{"offset": 1 << 20, "length": 4096, "phase": "write",
                             "errno": 5, "strerror": "Input/output error"}],
                bytes_skipped=4096, verified=False)


# ───────────────────────────────────────── the tool must not decide

def test_the_tool_never_auto_approves(clean_result):
    """THE PROPERTY THIS MODULE EXISTS FOR. A perfect run is still AWAITING_DECISION."""
    assert clean_result["verified"] is True
    assert not clean_result["bad_ranges"]

    record = v.pending(clean_result)
    assert record.decision == v.UNDECIDED
    assert record.decided_by == ""


def test_assess_returns_evidence_not_a_verdict(clean_result):
    a = v.assess(clean_result)
    assert a.requires_human is True
    assert not hasattr(a, "decision")


def test_awaiting_decision_is_a_state_not_a_choice(clean_result):
    """decide() refuses to be handed UNDECIDED: pending() is how you get there."""
    with pytest.raises(ValueError, match="state, not a choice"):
        v.decide(clean_result, decision=v.UNDECIDED, decided_by="X", role="r",
                 rationale="y", data_sensitivity="z")


def test_the_certificate_says_so_before_anyone_has_decided(clean_result):
    """A certificate printed before validation is ordinary, not broken. Blank would be the
    overclaim; defaulting to approved would be worse."""
    field = v.certificate_field(v.pending(clean_result))
    assert "AWAITING DECISION" in field
    assert "4.5.2" in field


# ───────────────────────────────────────── NIST's five grounds

def test_all_five_grounds_are_assessed(clean_result):
    got = {g.ground for g in v.assess(clean_result).grounds}
    assert got == set(v.GROUNDS)


def test_skipped_regions_trigger_the_inaccessibility_ground(bad_sector_result):
    """G1, the standard's first consideration, and one AKHANDA measures exactly."""
    a = v.assess(bad_sector_result)
    g1 = next(g for g in a.grounds if g.ground == "G1_INACCESSIBLE_REGIONS")
    assert g1.triggered is True
    assert "4096 bytes" in g1.evidence
    assert "G1_INACCESSIBLE_REGIONS" in a.triggered


def test_clearing_flash_triggers_the_overprovisioning_ground(flash_result):
    """G5, the standard's own example, and AKHANDA's normal case. Not a defect: a fact
    the validator has to weigh."""
    a = v.assess(flash_result)
    g5 = next(g for g in a.grounds if g.ground == "G5_SCOPE_TOO_NARROW")
    assert g5.triggered is True
    assert "overprovisioning" in g5.evidence


def test_a_clean_run_triggers_nothing(clean_result):
    assert v.assess(clean_result).triggered == []


def test_what_software_cannot_determine_is_reported_undetermined_not_clear(clean_result):
    """The failure mode that would hide a rejection ground: treating "we cannot tell" as
    "no problem"."""
    a = v.assess(clean_result)
    undetermined = [g for g in a.grounds if not g.machine_determinable]
    assert {g.ground for g in undetermined} == {
        "G2_METHOD_INAPPROPRIATE", "G3_UNQUALIFIED_OR_UNCALIBRATED", "G4_BELOW_MINIMUM"}
    for g in undetermined:
        assert "undetermined" in g.evidence or "not machine-determinable" in g.evidence
    assert "undetermined rather than clear" in a.summary


def test_tool_ref_identifies_but_does_not_qualify(clean_result):
    """G3, the chain names the build and the signer. Naming is not qualifying."""
    g3 = next(g for g in v.assess(clean_result).grounds
              if g.ground == "G3_UNQUALIFIED_OR_UNCALIBRATED")
    assert "IDENTIFIES" in g3.evidence
    assert "does not establish" in g3.evidence


# ───────────────────────────────────────── the decision, when a human makes it

def test_an_approval_names_the_human_and_the_sensitivity(clean_result):
    r = v.decide(clean_result, decision=v.APPROVED, decided_by="Dr A. Rao",
                 role="Lab Supervisor", rationale="Read-back matched at every sample point.",
                 data_sensitivity="Internal / non-classified")
    assert r.decision == v.APPROVED
    assert "Dr A. Rao" in v.certificate_field(r)
    assert "Internal / non-classified" in r.meaning


def test_a_validation_without_a_validator_is_refused(clean_result):
    with pytest.raises(ValueError, match="no validator is not a decision"):
        v.decide(clean_result, decision=v.APPROVED, decided_by="  ", role="r",
                 rationale="y", data_sensitivity="z")


def test_a_validation_without_a_rationale_is_refused(clean_result):
    """§4.5.2 asks that errors and anomalies be ANALYSED. An unexplained verdict records
    none of that analysis."""
    with pytest.raises(ValueError, match="ANALYSED"):
        v.decide(clean_result, decision=v.APPROVED, decided_by="X", role="r",
                 rationale="", data_sensitivity="z")


def test_a_validation_without_data_sensitivity_is_refused(clean_result):
    """The decision is a FUNCTION of sensitivity. Recording one without it is not the
    decision the standard describes."""
    with pytest.raises(ValueError, match="how sensitive"):
        v.decide(clean_result, decision=v.APPROVED, decided_by="X", role="r",
                 rationale="y", data_sensitivity="")


def test_a_rejection_must_name_a_remedy(clean_result):
    """§4.5.2: rejection "would require repeating... or escalating". A rejection with no
    remedy is a complaint."""
    with pytest.raises(ValueError, match="complaint"):
        v.decide(clean_result, decision=v.REJECTED, decided_by="X", role="r",
                 rationale="y", data_sensitivity="z")


def test_a_rejection_with_a_remedy_records_it(flash_result):
    r = v.decide(flash_result, decision=v.REJECTED, decided_by="Dr A. Rao",
                 role="Lab Supervisor",
                 rationale="Overprovisioning residue unacceptable at this classification.",
                 data_sensitivity="Classified", remedy="ESCALATE_METHOD")
    assert r.remedy == "ESCALATE_METHOD"
    assert "must not be released" in r.meaning
    assert "ESCALATE_METHOD" in v.certificate_field(r)


def test_a_remedy_on_an_approval_is_refused(clean_result):
    with pytest.raises(ValueError, match="only to a rejection"):
        v.decide(clean_result, decision=v.APPROVED, decided_by="X", role="r",
                 rationale="y", data_sensitivity="z", remedy="ESCALATE_METHOD")


def test_approving_over_a_triggered_ground_is_recorded_as_such(flash_result):
    """A supervisor may accept overprovisioning residue, that is their call. The
    certificate must show it was accepted rather than absent."""
    r = v.decide(flash_result, decision=v.APPROVED, decided_by="Dr A. Rao",
                 role="Lab Supervisor",
                 rationale="Non-sensitive media; residual flash risk accepted.",
                 data_sensitivity="Public")
    assert "Approved despite 1 triggered ground" in r.meaning
    assert "G5_SCOPE_TOO_NARROW" in r.meaning


def test_the_decision_carries_the_assessment_with_it(clean_result):
    """So a reader can see the evidence the decision was made against, not just the verdict."""
    r = v.decide(clean_result, decision=v.APPROVED, decided_by="X", role="r",
                 rationale="y", data_sensitivity="z")
    assert r.assessment["grounds"]
    assert len(r.assessment["grounds"]) == 5


def test_the_record_names_the_standard(clean_result):
    assert v.pending(clean_result).standard == "NIST SP 800-88 Rev. 2 §4.5.2"
