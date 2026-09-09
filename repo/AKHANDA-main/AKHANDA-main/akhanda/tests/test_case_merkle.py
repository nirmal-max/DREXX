"""Gap 6, case-level Merkle root over many device chains.

The attack under test is one level up from the one the chain already stops. A chain proves
nothing was removed from the middle of ONE device's history. It cannot notice a whole
device being removed from the case, because no chain knows how many siblings it had , 
delete a drive's chain file and every surviving chain still verifies perfectly.

These tests are written against that specific attack, not against the Merkle mechanics:
the mechanics are already covered in test_anchor.py, and re-testing them here would spend
the file's attention on the part that was already proven.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from attestation import tiers  # noqa: E402
from attestation.case import (  # noqa: E402
    CASE_VERSION, CaseError, build_manifest, case_root, device_proof, device_refs,
    verify_device, verify_manifest,
)
from attestation.core import Chain  # noqa: E402
from attestation.keys import load_or_create_operator_key  # noqa: E402


@pytest.fixture(scope="module")
def op_key():
    return load_or_create_operator_key()


def _chain(op_key, device: str, n: int = 2) -> Chain:
    c = Chain(chain_id=f"case-test-{device}")
    for i in range(n):
        c.append(
            op_type="ERASE" if i % 2 == 0 else "RECOVER",
            target_ref=f"/dev/{device}",
            timestamp=f"2026-09-01T10:{i:02d}:00Z",
            method="Clear",
            result_hash=f"{i:064x}",
            operator_decl=f"{device} operation {i}",
            concur_decl="",
            custody_tier=tiers.SOFTWARE_KEY,
            operator_key=op_key,
            outcome="VERIFIED",
        )
    return c


@pytest.fixture
def seizure(op_key):
    """One case: a laptop, two phones, a USB stick. The realistic shape."""
    return {
        "laptop_01": _chain(op_key, "laptop_01", 3),
        "phone_01": _chain(op_key, "phone_01", 2),
        "phone_02": _chain(op_key, "phone_02", 2),
        "usb_01": _chain(op_key, "usb_01", 1),
    }


# ------------------------------------------------------------------ canonical ordering

def test_the_root_does_not_depend_on_insertion_order(op_key, seizure):
    """Two examiners with the same evidence must compute the same root.

    A root that depended on directory listing order would be useless for the one
    comparison it exists to support.
    """
    reversed_case = dict(reversed(list(seizure.items())))
    assert case_root(seizure) == case_root(reversed_case)


def test_devices_are_reported_in_a_stable_order(seizure):
    ids = [r.device_id for r in device_refs(seizure)]
    assert ids == sorted(ids)


def test_an_empty_case_is_refused_not_rooted():
    """A zero root would verify against nothing while looking like a commitment."""
    with pytest.raises(CaseError):
        case_root({})


def test_duplicate_device_ids_are_refused(op_key):
    """Dict keys make this unreachable here, but device_refs is fed from disk elsewhere."""
    from attestation.case import DeviceRef
    import attestation.case as mod

    dupes = [DeviceRef("d1", "c1", "aa" * 32, 1), DeviceRef("d1", "c2", "bb" * 32, 1)]
    original = mod.device_refs
    mod.device_refs = lambda _chains: dupes
    try:
        with pytest.raises(CaseError):
            case_root({"ignored": None})
    finally:
        mod.device_refs = original


# ------------------------------------------------------- THE ATTACK: a device disappears

def test_removing_a_whole_device_changes_the_root(seizure):
    """THE POINT OF THE FILE. Each surviving chain still verifies; the root does not."""
    before = case_root(seizure)
    del seizure["usb_01"]
    assert case_root(seizure) != before


def test_a_removed_device_is_named_by_the_manifest_check(seizure):
    manifest = build_manifest(seizure, case_id="CASE-2026-0001", examiner="P. Srivastava")
    del seizure["usb_01"]

    report = verify_manifest(manifest, seizure)
    assert report["ok"] is False
    assert report["missing_devices"] == ["usb_01"]
    assert "omission" in report["reason"].lower()


def test_the_surviving_chains_still_verify_which_is_why_this_is_needed(seizure, op_key):
    """Stated as a test because it is the argument for the whole module.

    If the surviving chains broke on their own, no case root would be necessary. They do
    not break -- deletion of a sibling is invisible from inside a chain -- so the binding
    has to exist one level up.
    """
    from attestation.core import verify_chain_report

    del seizure["usb_01"]
    for device, chain in seizure.items():
        report = verify_chain_report(chain.entries, operator_pub=op_key.public_key())
        assert report.ok, f"{device} should still verify perfectly on its own"


# --------------------------------------------------- tail truncation of a device chain

def test_truncating_one_device_chain_is_caught_by_the_committed_count(seizure):
    """count is in the leaf for the same reason the witness publishes its own count.

    A head hash alone cannot tell a chain that legitimately ended at seq 1 from one
    truncated to seq 1.
    """
    manifest = build_manifest(seizure, case_id="CASE-2026-0001")
    seizure["laptop_01"].entries = seizure["laptop_01"].entries[:1]

    report = verify_manifest(manifest, seizure)
    assert report["ok"] is False
    assert [c["device_id"] for c in report["changed_devices"]] == ["laptop_01"]
    assert report["changed_devices"][0]["stated"]["count"] == 3
    assert report["changed_devices"][0]["found"]["count"] == 1


def test_appending_to_a_device_after_the_root_is_fixed_is_visible(seizure, op_key):
    manifest = build_manifest(seizure, case_id="CASE-2026-0001")
    seizure["usb_01"].append(
        op_type="ERASE", target_ref="/dev/usb_01", timestamp="2026-09-02T09:00:00Z",
        method="Clear", result_hash="ff" * 32, operator_decl="added later",
        concur_decl="", custody_tier=tiers.SOFTWARE_KEY, operator_key=op_key,
        outcome="VERIFIED")

    report = verify_manifest(manifest, seizure)
    assert report["ok"] is False
    assert [c["device_id"] for c in report["changed_devices"]] == ["usb_01"]


def test_a_device_added_to_the_case_is_reported_but_not_called_tampering(seizure, op_key):
    """A drive examined after the root was fixed looks exactly like an inserted one.

    Reporting it as tampering would cry wolf on the most ordinary event in a live case.
    The honest statement is that the root no longer covers the evidence set.
    """
    manifest = build_manifest(seizure, case_id="CASE-2026-0001")
    seizure["usb_02"] = _chain(op_key, "usb_02", 1)

    report = verify_manifest(manifest, seizure)
    assert report["ok"] is False
    assert report["extra_devices"] == ["usb_02"]
    assert "not necessarily tampering" in report["reason"].lower()


def test_an_untouched_case_verifies(seizure):
    manifest = build_manifest(seizure, case_id="CASE-2026-0001")
    report = verify_manifest(manifest, seizure)
    assert report["ok"] is True
    assert report["root_matches"] is True
    assert report["missing_devices"] == [] and report["changed_devices"] == []


# --------------------------------------------------------------- selective disclosure

def test_one_device_can_be_proven_without_revealing_the_others(seizure):
    """Real need: one drive is released to its owner while the case stays live."""
    root = case_root(seizure).hex()
    proof = device_proof(seizure, "phone_01")

    result = verify_device(proof, expected_root=root)
    assert result["ok"] is True
    assert result["matches_expected"] is True

    blob = repr(proof)
    for other in ("laptop_01", "phone_02", "usb_01"):
        assert other not in blob, f"{other} leaked into a proof about phone_01"


def test_the_proof_is_logarithmic_not_the_whole_case(seizure):
    proof = device_proof(seizure, "phone_01")
    assert len(proof["path"]) <= 3  # 4 devices -> depth 2, with headroom


def test_a_proof_checked_only_against_its_own_root_is_not_verified(seizure):
    """Whoever forged the proof also wrote its embedded root. Self-consistency is not
    evidence, and the reason string has to say so rather than returning a bare True."""
    proof = device_proof(seizure, "usb_01")
    result = verify_device(proof)  # no independent root supplied
    assert "unverified" in result["reason"].lower()


def test_a_tampered_path_does_not_rebuild_the_root(seizure):
    root = case_root(seizure).hex()
    proof = device_proof(seizure, "usb_01")
    proof["path"][0][0] = "00" * 32
    result = verify_device(proof, expected_root=root)
    assert result["ok"] is False


def test_swapping_the_device_under_a_valid_path_fails(seizure):
    """The leaf commits to device_id, chain_id, head and count together."""
    root = case_root(seizure).hex()
    proof = device_proof(seizure, "usb_01")
    proof["device"]["head_hash"] = "ab" * 32
    result = verify_device(proof, expected_root=root)
    assert result["ok"] is False


def test_a_proof_for_a_device_not_in_the_case_is_refused(seizure):
    with pytest.raises(CaseError):
        device_proof(seizure, "nas_99")


# ------------------------------------------------------------------- version discipline

def test_a_manifest_from_another_version_is_refused_not_misverified(seizure):
    manifest = build_manifest(seizure, case_id="CASE-2026-0001")
    manifest["case_version"] = "99"
    report = verify_manifest(manifest, seizure)
    assert report["ok"] is False
    assert "refused" in report["reason"].lower()


def test_a_proof_from_another_version_is_refused(seizure):
    proof = device_proof(seizure, "usb_01")
    proof["case_version"] = "99"
    result = verify_device(proof, expected_root=proof["case_root"])
    assert result["ok"] is False
    assert "refused" in result["reason"].lower()


def test_a_malformed_proof_reports_rather_than_raising(seizure):
    result = verify_device({"case_version": CASE_VERSION, "path": []})
    assert result["ok"] is False
    assert "malformed" in result["reason"].lower()


# --------------------------------------------------------------------- honest framing

def test_the_manifest_states_what_it_does_not_prove(seizure):
    """The root is a claim the operator made about their own case until it is anchored."""
    manifest = build_manifest(seizure, case_id="CASE-2026-0001")
    meaning = manifest["meaning"].lower()
    assert "anchored" in meaning or "co-signed" in meaning
    assert "claim" in meaning


def test_the_manifest_totals_are_derived_not_asserted(seizure):
    manifest = build_manifest(seizure, case_id="CASE-2026-0001")
    assert manifest["device_count"] == len(seizure)
    assert manifest["total_entries"] == sum(len(c.entries) for c in seizure.values())
