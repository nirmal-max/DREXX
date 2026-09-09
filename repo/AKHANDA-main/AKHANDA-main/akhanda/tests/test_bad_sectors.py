"""G9, a drive with bad sectors must be skipped, logged, and signed. Never hung, never
silently gapped, never reported as a clean wipe.

WHY THIS FIXTURE IS A MONKEYPATCH AND NOT dm-flakey. The real kernel fixture
(`dmsetup ... flakey`) is in scripts/prep/g2b_usb_wipe.md and should be run once on real
hardware. It cannot run in CI: it needs root, a Linux kernel with the dm-flakey module,
and it fails on a schedule rather than at a chosen offset, so the same test would pass and
fail on different days. Here the failure is deterministic and offset-addressed, which is
what a regression test needs. The two are complements: the kernel one proves the code path
meets a real block layer, this one proves it keeps meeting it on every commit.

THE PROPERTY UNDER TEST IS NOT "IT SURVIVES". It is that the record afterwards is TRUE:
the skipped regions are named, the outcome is not VERIFIED, and the entry commits to both.
A wipe that survives bad sectors and still reports success is worse than one that crashes,
because it launders a hole in the erasure into a certificate.
"""
from __future__ import annotations

import errno
import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from erasure.engine import (  # noqa: E402
    BLOCK_SIZE, CONFIRM_TOKEN, MAX_CONSECUTIVE_BAD, SECTOR_SIZE, BadRange,
    MediaFailure, erase, outcome_for, overwrite_pass, read_back_sample,
)

IMAGE_SIZE = 4 * BLOCK_SIZE  # 4 MiB: enough for several chunks, fast enough for CI


@pytest.fixture
def image(tmp_path) -> Path:
    p = tmp_path / "flaky.img"
    p.write_bytes(b"\xAB" * IMAGE_SIZE)
    return p


def _fail_writes_in(monkeypatch, ranges: list[tuple[int, int]], err=errno.EIO):
    """Make os.write raise EIO when the file position is inside any given range.

    Patching at the os.write boundary rather than inside the engine is deliberate: it is
    where a real block device reports a defect, so the test exercises the same code path
    a failing drive would, not a branch added for testability.
    """
    real_write, real_lseek = os.write, os.lseek
    pos = {"at": 0}

    def fake_lseek(fd, offset, whence):
        result = real_lseek(fd, offset, whence)
        if whence == os.SEEK_SET:
            pos["at"] = offset
        return result

    def fake_write(fd, data):
        start, end = pos["at"], pos["at"] + len(data)
        for bad_off, bad_len in ranges:
            if start < bad_off + bad_len and bad_off < end:
                raise OSError(err, "Input/output error")
        pos["at"] = end
        return real_write(fd, data)

    monkeypatch.setattr(os, "lseek", fake_lseek)
    monkeypatch.setattr(os, "write", fake_write)


def _fail_reads_in(monkeypatch, ranges: list[tuple[int, int]]):
    real_read, real_lseek = os.read, os.lseek
    pos = {"at": 0}

    def fake_lseek(fd, offset, whence):
        result = real_lseek(fd, offset, whence)
        if whence == os.SEEK_SET:
            pos["at"] = offset
        return result

    def fake_read(fd, n):
        start, end = pos["at"], pos["at"] + n
        for bad_off, bad_len in ranges:
            if start < bad_off + bad_len and bad_off < end:
                raise OSError(errno.EIO, "Input/output error")
        return real_read(fd, n)

    monkeypatch.setattr(os, "lseek", fake_lseek)
    monkeypatch.setattr(os, "read", fake_read)


# ------------------------------------------------------------------ no hang, no crash

def test_a_bad_sector_does_not_abort_the_pass(image, monkeypatch):
    """The old behaviour: first OSError killed everything. That is the regression."""
    _fail_writes_in(monkeypatch, [(BLOCK_SIZE + 4096, SECTOR_SIZE)])
    bad: list = []
    written = overwrite_pass(str(image), b"seed" * 8, bad_ranges=bad)
    assert written > 0
    assert bad, "a failing sector must be recorded, not swallowed"


def test_the_pass_reaches_the_end_of_the_device(image, monkeypatch):
    """A defect early on must not cost the wipe everything after it."""
    _fail_writes_in(monkeypatch, [(0, SECTOR_SIZE)])
    bad: list = []
    written = overwrite_pass(str(image), b"seed" * 8, bad_ranges=bad)
    skipped = sum(b.length for b in bad)
    assert written + skipped == IMAGE_SIZE, (
        "every byte must be either written or recorded as skipped; anything else is a "
        "silent gap")


# --------------------------------------------------------------- minimal, truthful skip

def test_only_the_actually_bad_sectors_are_skipped(image, monkeypatch):
    """One dead sector must not condemn the whole 1 MiB chunk.

    Reporting a megabyte of surviving data when 2047 of 2048 sectors were overwritten
    overstates the damage exactly as badly as hiding it understates it.
    """
    _fail_writes_in(monkeypatch, [(BLOCK_SIZE, SECTOR_SIZE)])
    bad: list = []
    overwrite_pass(str(image), b"seed" * 8, bad_ranges=bad)
    assert sum(b.length for b in bad) == SECTOR_SIZE


def test_adjacent_bad_sectors_are_coalesced(image, monkeypatch):
    """A 20-sector defect is one finding an examiner reads, not twenty."""
    _fail_writes_in(monkeypatch, [(BLOCK_SIZE, 20 * SECTOR_SIZE)])
    bad: list = []
    overwrite_pass(str(image), b"seed" * 8, bad_ranges=bad)
    assert len(bad) == 1
    assert bad[0].length == 20 * SECTOR_SIZE


def test_the_range_records_where_and_why(image, monkeypatch):
    _fail_writes_in(monkeypatch, [(BLOCK_SIZE, SECTOR_SIZE)])
    bad: list = []
    overwrite_pass(str(image), b"seed" * 8, bad_ranges=bad)
    r = bad[0]
    assert r.offset == BLOCK_SIZE
    assert r.phase == "write"
    assert r.errno == errno.EIO
    assert r.strerror, "an unexplained skip is not evidence"


# ------------------------------------------------- write failures vs read failures differ

def test_an_unreadable_sample_is_not_recorded_as_a_mismatch(image, monkeypatch):
    """match=False says "the wipe did not land". An unreadable sector says no such thing.

    Collapsing the two would report a failed erasure where the truth is an unconfirmable
    one -- a different claim, with a different remedy, in a document a court reads.
    """
    seed = b"seed" * 8
    overwrite_pass(str(image), seed)
    _fail_reads_in(monkeypatch, [(0, IMAGE_SIZE)])
    bad: list = []
    samples = read_back_sample(str(image), seed, bad_ranges=bad)
    assert samples == [], "unreadable offsets must not appear as samples at all"
    assert bad and all(b.phase == "read" for b in bad)


def test_write_and_read_failures_are_distinguishable_in_the_record(image, monkeypatch):
    _fail_writes_in(monkeypatch, [(BLOCK_SIZE, SECTOR_SIZE)])
    result = erase(str(image), confirm=CONFIRM_TOKEN)
    phases = {b["phase"] for b in result["bad_ranges"]}
    assert "write" in phases


# ------------------------------------------------------------------- the signed outcome

def test_a_wipe_with_a_hole_is_never_VERIFIED(image, monkeypatch):
    """THE POINT OF THE WHOLE FILE. Surviving bad sectors is worthless if the record
    then presents the result as a clean wipe."""
    _fail_writes_in(monkeypatch, [(BLOCK_SIZE, SECTOR_SIZE)])
    result = erase(str(image), confirm=CONFIRM_TOKEN)
    assert result["verified"] is False
    assert outcome_for(result) == "PARTIAL"


def test_a_clean_wipe_is_still_VERIFIED(image):
    """The guard must not become a permanent downgrade. No defect, no penalty."""
    result = erase(str(image), confirm=CONFIRM_TOKEN)
    assert result["verified"] is True
    assert outcome_for(result) == "VERIFIED"
    assert result["bad_ranges"] == []
    assert result["bytes_skipped"] == 0


def test_the_note_states_that_skipped_data_was_not_destroyed(image, monkeypatch):
    """A judge reads the note, not the JSON. It must say the dangerous part out loud."""
    _fail_writes_in(monkeypatch, [(BLOCK_SIZE, SECTOR_SIZE)])
    result = erase(str(image), confirm=CONFIRM_TOKEN)
    note = result["honest_note"].lower()
    assert "not destroyed" in note
    assert "recoverable" in note


def test_every_byte_is_accounted_for_in_the_result(image, monkeypatch):
    _fail_writes_in(monkeypatch, [(BLOCK_SIZE, 3 * SECTOR_SIZE)])
    result = erase(str(image), confirm=CONFIRM_TOKEN)
    assert result["bytes_written"] + result["bytes_skipped"] == IMAGE_SIZE


# ------------------------------------------------------------- the entry commits to it

def test_the_ledger_entry_commits_to_the_skipped_ranges(image, monkeypatch):
    """A bad range outside the signed digest could be edited out afterwards, which is the
    whole class of failure this project exists to close."""
    from erasure.engine import result_hash

    _fail_writes_in(monkeypatch, [(BLOCK_SIZE, SECTOR_SIZE)])
    result = erase(str(image), confirm=CONFIRM_TOKEN)
    before = result_hash(result)

    tampered = dict(result)
    tampered["bad_ranges"] = []          # hide the hole
    tampered["bytes_skipped"] = 0
    assert result_hash(tampered) != before, (
        "removing the skipped ranges must change the digest the entry signed")


# ------------------------------------------------------------------- a dead drive stops

def test_a_totally_dead_device_stops_instead_of_grinding(image, monkeypatch):
    """Solid failure is not "bad sectors", it is a dead drive. It must stop AND explain.

    Without the cap this loops sector by sector over the whole device, which on a real
    500 GB drive is the hang this gap was opened about.
    """
    _fail_writes_in(monkeypatch, [(0, IMAGE_SIZE)])
    result = erase(str(image), confirm=CONFIRM_TOKEN)
    assert result["aborted"] is True
    assert result["abort_reason"]
    assert outcome_for(result) in ("PARTIAL", "NOT_PERFORMED")
    assert result["verified"] is False


def test_the_abort_is_bounded(image, monkeypatch):
    """The cap has to actually bound the work, or it is decoration."""
    _fail_writes_in(monkeypatch, [(0, IMAGE_SIZE)])
    bad: list = []
    with pytest.raises(MediaFailure):
        overwrite_pass(str(image), b"seed" * 8, bad_ranges=bad)
    assert sum(b.length for b in bad) <= MAX_CONSECUTIVE_BAD + BLOCK_SIZE


def test_nothing_written_at_all_is_NOT_PERFORMED():
    """Distinct from PARTIAL: nothing happened, and the vocabulary has a word for that."""
    assert outcome_for({"bytes_written": 0,
                        "bad_ranges": [{"offset": 0, "length": 512, "phase": "write"}],
                        "verified": False}) == "NOT_PERFORMED"
