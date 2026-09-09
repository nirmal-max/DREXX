"""
Erasure engine tests, role 2's acceptance test, executable.

The acceptance test in docs/TEAM_ROLES.md is "write a known pattern, erase it, confirm by
sampling that the pattern is gone, and return method_used = 'Clear' honestly". These
tests run that on a file-backed image, which behaves identically to a block device and
costs nothing when you get it wrong.

The two tests that matter most are the guard tests and
`test_purge_request_on_flash_records_clear`. They are the ones that stop the tool from
printing a stronger word than it earned.
"""

import os

import pytest

from erasure.engine import (
    CLEAR, CONFIRM_TOKEN, DESTROY, PURGE, ErasureRefused, erase, overwrite_pass,
    plan_method, probe_media, read_back_sample, result_hash,
)

KNOWN = b"SENSITIVE-EVIDENCE-DATA-" * 4096   # ~96 KiB of recognisable plaintext


@pytest.fixture()
def image(tmp_path):
    p = tmp_path / "target.img"
    p.write_bytes(KNOWN)
    return p


# ------------------------------------------------------------------- the core loop

def test_known_pattern_is_gone_after_erase(image):
    res = erase(str(image), CLEAR)
    assert res["verified"] is True
    data = image.read_bytes()
    assert b"SENSITIVE-EVIDENCE-DATA" not in data
    assert len(data) == len(KNOWN)        # size preserved; only content replaced


def test_erase_reports_clear_on_a_file_image(image):
    res = erase(str(image), CLEAR)
    assert res["method_used"] == CLEAR
    assert res["passes"] == 1
    assert res["bytes_written"] == len(KNOWN)


def test_read_back_sampling_detects_a_write_that_did_not_land(image):
    """A stick that silently ignores writes must fail verification, not pass it."""
    seed = b"\x01" * 32
    overwrite_pass(str(image), seed)
    # Simulate the device reverting one region after the write returned.
    with open(image, "r+b") as fh:
        fh.seek(0)
        fh.write(b"OLD-DATA-STILL-HERE" * 100)
    samples = read_back_sample(str(image), seed)
    assert any(not s.match for s in samples)


def test_samples_are_recorded_with_both_digests(image):
    res = erase(str(image), CLEAR)
    assert res["sample_results"]
    for s in res["sample_results"]:
        assert s["expected_sha256"] and s["actual_sha256"]
        assert s["match"] is True


# ------------------------------------------------------------------ honesty gates

def test_purge_request_on_a_file_image_records_clear(image):
    """Asking for Purge does not grant Purge. The ceiling is the medium, not the ask."""
    res = erase(str(image), PURGE)
    assert res["method_used"] == CLEAR
    assert res["requested_level"] == PURGE
    assert "not reachable" in res["honest_note"] or "fell back" in res["honest_note"]


def test_destroy_is_refused_rather_than_faked():
    probe = {"kind": "file_image", "firmware_sanitize": False, "note": ""}
    with pytest.raises(ErasureRefused, match="physical process"):
        plan_method(probe, DESTROY)


def test_unknown_level_is_refused():
    probe = {"kind": "file_image", "firmware_sanitize": False, "note": ""}
    with pytest.raises(ErasureRefused, match="level must be"):
        plan_method(probe, "Nuke")


def test_purge_is_granted_only_when_a_firmware_command_exists():
    yes = {"kind": "block", "firmware_sanitize": True, "note": ""}
    no = {"kind": "block", "firmware_sanitize": False, "note": "removable flash"}
    assert plan_method(yes, PURGE)[0] == PURGE
    method, reason = plan_method(no, PURGE)
    assert method == CLEAR
    assert "removable flash" in reason


def test_honest_note_states_the_flash_residue_limit(image):
    res = erase(str(image), CLEAR)
    assert "spare" in res["honest_note"] or "remapped" in res["honest_note"]


# ------------------------------------------------------------------- the guard

def test_block_device_without_the_token_is_refused(tmp_path):
    fake = "/dev/sdz"
    with pytest.raises(ErasureRefused, match="confirm="):
        erase(fake, CLEAR)


def test_block_device_without_the_env_gate_is_refused(monkeypatch):
    monkeypatch.delenv("AKHANDA_ALLOW_DEVICE_WRITE", raising=False)
    with pytest.raises(ErasureRefused, match="AKHANDA_ALLOW_DEVICE_WRITE"):
        erase("/dev/sdz", CLEAR, confirm=CONFIRM_TOKEN)


def test_likely_system_disk_is_refused_even_with_both_gates(monkeypatch):
    monkeypatch.setenv("AKHANDA_ALLOW_DEVICE_WRITE", "1")
    # Wording changed when the blocklist grew to cover Windows physical drives; the
    # PROPERTY under test is unchanged: both gates set, still refused.
    with pytest.raises(ErasureRefused, match="protected device or system disk"):
        erase("/dev/sda", CLEAR, confirm=CONFIRM_TOKEN)


def test_file_images_need_no_token(image):
    # "Must not raise" alone would also pass if erase() silently did nothing, so the
    # result is checked as well: the guard is about the TOKEN, not about the wipe being
    # skipped.
    result = erase(str(image), CLEAR)
    assert result["method_used"] == CLEAR
    assert result["bytes_written"] > 0


# -------------------------------------------------------------------- plumbing

def test_probe_reports_file_images_as_such(image):
    p = probe_media(str(image))
    assert p["kind"] == "file_image"
    assert p["firmware_sanitize"] is False


def test_probe_does_not_guess_on_unknown_media(tmp_path):
    p = probe_media(str(tmp_path / "does-not-exist"))
    assert p["kind"] in ("unknown", "block_or_unknown")
    assert p["firmware_sanitize"] is False


def test_result_hash_commits_to_the_whole_result(image):
    res = erase(str(image), CLEAR)
    h = result_hash(res)
    res["method_used"] = PURGE          # the exact lie the ledger must not absorb
    assert result_hash(res) != h


def test_zero_length_target_verifies_nothing(tmp_path):
    p = tmp_path / "empty.img"
    p.write_bytes(b"")
    res = erase(str(p), CLEAR)
    assert res["sample_results"] == []
    assert res["verified"] is False     # nothing sampled means nothing proven
