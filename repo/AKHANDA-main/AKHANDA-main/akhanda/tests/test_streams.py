"""NTFS alternate data streams, the residual trace a verified erasure left behind.

SIH26149 names this requirement directly: the file and folder eraser must "remove
associated metadata and residual traces". A named alternate data stream is exactly that,
and it is the one that survives a correct, verified, honest erasure of the file it hangs on.

A named stream shares the file's directory entry but not its bytes. Overwriting the file
overwrites the default stream only. So before this module existed the eraser could write
its pattern, read it back, confirm a match, scrub the name, truncate, unlink, and report
VERIFIED, while 15 KB of payload sat untouched in `file.txt:hidden`. Every check passed.
Every check was looking at the wrong stream.

The test that matters most here is `test_the_gap_this_closes_was_real`: it demonstrates the
old failure directly rather than asserting the new code works.
"""
from __future__ import annotations

import os
import platform
import sys
import tempfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from erasure import streams as ads  # noqa: E402
from erasure.file_eraser import erase_file  # noqa: E402

WINDOWS = platform.system() == "Windows"
ntfs_only = pytest.mark.skipif(not WINDOWS,
                               reason="alternate data streams are an NTFS/ReFS concept")

PAYLOAD = b"PAYLOAD-THAT-MUST-NOT-SURVIVE-" * 200


@pytest.fixture
def file_with_stream(tmp_path):
    f = tmp_path / "evidence.txt"
    f.write_bytes(b"the visible contents" * 50)
    with open(str(f) + ":hidden", "wb") as fh:
        fh.write(PAYLOAD)
    return f


# ─────────────────────────────────────────────────────── the gap was real

@ntfs_only
def test_the_gap_this_closes_was_real(file_with_stream):
    """Demonstrates the OLD failure rather than asserting the new code works.

    The payload is fully readable, and every ordinary measure of the file's size reports a
    number that does not include it. An eraser looking only at `st_size` bytes of the
    default stream would have reported a complete, verified wipe.
    """
    f = file_with_stream
    assert os.path.getsize(f) == len(b"the visible contents" * 50)
    assert os.path.getsize(f) < len(PAYLOAD), (
        "the hidden stream is larger than the file that hides it, and the file's own "
        "reported size does not mention it")
    with open(str(f) + ":hidden", "rb") as fh:
        assert fh.read() == PAYLOAD


@ntfs_only
def test_streams_are_found(file_with_stream):
    found = ads.list_streams(file_with_stream)
    assert [s.name for s in found] == [":hidden:$DATA"]
    assert found[0].size == len(PAYLOAD)


@ntfs_only
def test_the_default_stream_is_never_reported(file_with_stream):
    """`::$DATA` is the file's own contents, which the ordinary eraser handles. Listing it
    here would double-count it and imply a stream that is not there."""
    assert all(s.name != "::$DATA" for s in ads.list_streams(file_with_stream))


@ntfs_only
def test_a_file_with_no_streams_reports_none(tmp_path):
    f = tmp_path / "plain.txt"
    f.write_bytes(b"nothing hidden")
    assert ads.list_streams(f) == []
    r = ads.erase_streams(f)
    assert r["found"] == 0 and r["erased"] == 0 and r["failed"] == 0


# ─────────────────────────────────────────────────────── erasure

@ntfs_only
def test_the_stream_is_overwritten_and_removed(file_with_stream):
    f = file_with_stream
    r = ads.erase_streams(f)
    assert r["found"] == 1 and r["erased"] == 1 and r["failed"] == 0
    assert r["remaining_after"] == 0
    assert ads.list_streams(f) == []
    with pytest.raises(OSError):
        open(str(f) + ":hidden", "rb").read()


@ntfs_only
def test_the_main_file_is_left_intact(file_with_stream):
    """Erasing streams must not touch the file itself; erase_file owns that."""
    f = file_with_stream
    before = f.read_bytes()
    ads.erase_streams(f)
    assert f.read_bytes() == before


@ntfs_only
def test_several_streams_are_all_erased(tmp_path):
    f = tmp_path / "multi.txt"
    f.write_bytes(b"x" * 100)
    for name in ("one", "two", "Zone.Identifier"):
        with open(f"{f}:{name}", "wb") as fh:
            fh.write(b"data-" + name.encode())
    r = ads.erase_streams(f)
    assert r["found"] == 3 and r["erased"] == 3
    assert ads.list_streams(f) == []


# ─────────────────────────────────────────────────────── wired into the eraser

@ntfs_only
def test_erase_file_erases_streams_too(tmp_path):
    f = tmp_path / "case.txt"
    f.write_bytes(b"visible" * 100)
    with open(str(f) + ":stash", "wb") as fh:
        fh.write(PAYLOAD)

    r = erase_file(str(f))
    assert r.outcome == "VERIFIED"
    assert r.streams["found"] == 1 and r.streams["erased"] == 1
    assert "alternate data stream" in r.reason
    assert not f.exists()


@ntfs_only
def test_the_stream_report_is_in_the_result_even_when_empty(tmp_path):
    """"This file had none" and "streams were never looked for" are different facts, and
    only the first is a statement about the file."""
    f = tmp_path / "plain.txt"
    f.write_bytes(b"nothing hidden")
    r = erase_file(str(f))
    assert r.streams != {}
    assert r.streams["supported"] is True
    assert r.streams["found"] == 0


@ntfs_only
def test_a_stream_that_survives_downgrades_the_outcome(tmp_path, monkeypatch):
    """A surviving stream is a copy of data the function just reported as destroyed. It
    cannot be VERIFIED, whatever the main stream did."""
    f = tmp_path / "case.txt"
    f.write_bytes(b"visible" * 100)
    with open(str(f) + ":stash", "wb") as fh:
        fh.write(PAYLOAD)

    import erasure.file_eraser as fe
    real = fe.ads.erase_streams
    monkeypatch.setattr(fe.ads, "erase_streams", lambda p, **k: {
        "supported": True, "found": 1, "erased": 0, "failed": 1, "bytes": 0,
        "details": [], "note": "simulated failure", "remaining_after": 1})
    r = erase_file(str(f))
    assert r.outcome == "PARTIAL"
    assert "could not be erased" in r.reason
    monkeypatch.setattr(fe.ads, "erase_streams", real)


# ─────────────────────────────────────────────────────── cross-platform honesty

def test_non_windows_reports_not_applicable_rather_than_clean(tmp_path, monkeypatch):
    """On ext4 there are no alternate data streams, and the record must say the question
    does not apply, not imply a check was performed and passed."""
    monkeypatch.setattr(ads.platform, "system", lambda: "Linux")
    f = tmp_path / "x.txt"
    f.write_bytes(b"data")
    r = ads.erase_streams(f)
    assert r["supported"] is False
    assert r["found"] == 0
    assert "not applicable" in r["note"].lower()


def test_the_limits_are_stated_not_hidden():
    d = ads.describe_limits()
    assert d["level"] == "Clear"
    assert "MFT record" in d["not_reached"]
    assert "residual trace" in d["why_it_matters"]


def test_list_streams_on_a_missing_file_returns_nothing(tmp_path):
    assert ads.list_streams(tmp_path / "nope.txt") == []
