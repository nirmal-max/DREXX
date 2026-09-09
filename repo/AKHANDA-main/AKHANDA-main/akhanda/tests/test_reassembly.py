"""Fragment reassembly against NIST CFReDS, the benchmark built so this would fail.

CFReDS level 2 contains no contiguous file. Every signature carver scores zero on it,
including this project's own until now, and that zero is structural rather than a tuning
problem: a scanner that reads forward cannot recover a file whose second half is stored
before its first.

The claim under test is deliberately narrow and checkable: `000_0021.png` is recovered from
L2 **byte-identically**, and every join that produced it was proven by the format's own
CRC-32 rather than accepted because a decoder did not complain.

WHY BYTE-IDENTITY IS THE ONLY ACCEPTABLE BAR HERE. A reassembled file that merely opens is
worthless as evidence, a decoder tolerating a file says nothing about whether those were
the original bytes. Only a hash match against ground truth distinguishes recovery from a
plausible-looking reconstruction, and that distinction is the entire reason this module is
allowed to exist in a forensic tool.
"""
from __future__ import annotations

import hashlib
import struct
import sys
import zlib
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from recovery.reassemble import (  # noqa: E402
    MAX_CHUNK, PNG_TYPES, Reassembly, _png_chunks, _recover_straddle, _runs,
    reassemble, reassemble_png, summarize,
)

DATA = ROOT / "tests" / "data"
L2 = DATA / "L2_Graphic.dd"
TARGET = DATA / "000_0021.png"

pytestmark = pytest.mark.skipif(
    not (L2.is_file() and TARGET.is_file()),
    reason="NIST CFReDS corpus not present in this checkout")


@pytest.fixture(scope="module")
def truth() -> dict:
    return {hashlib.sha256(f.read_bytes()).hexdigest(): f.name
            for f in DATA.iterdir()
            if f.suffix.lower() in (".png", ".jpg", ".gif", ".tif", ".bmp", ".pcx")}


@pytest.fixture(scope="module")
def l2_result() -> list:
    return reassemble(str(L2))


# ───────────────────────────────────────────────── THE CLAIM

def test_a_fragmented_png_is_recovered_from_cfreds_L2(l2_result, truth):
    """THE HEADLINE. Not "a PNG was produced", the ORIGINAL file, byte for byte."""
    assert l2_result, "nothing was reassembled from L2"
    names = {truth.get(r["sha256"]) for r in l2_result}
    assert "000_0021.png" in names, (
        f"no reassembly matched a ground-truth file; got sizes "
        f"{[r['size'] for r in l2_result]}")


def test_the_recovery_is_byte_identical_not_merely_decodable(l2_result, truth):
    """A file that opens is not a recovery. Only the hash separates the two."""
    src = TARGET.read_bytes()
    got = next(r for r in l2_result if truth.get(r["sha256"]) == "000_0021.png")
    assert got["size"] == len(src)
    assert got["sha256"] == hashlib.sha256(src).hexdigest()


def test_the_carver_alone_still_recovers_nothing_from_L2():
    """The control. Without this, the result above could be the ordinary carver working
    and the reassembler taking credit for it."""
    from recovery.engine import carve
    truth_hashes = {hashlib.sha256(f.read_bytes()).hexdigest()
                    for f in DATA.iterdir() if f.suffix.lower() == ".png"}
    exact = [a for a in carve(str(L2)) if a["sha256"] in truth_hashes]
    assert exact == [], "the plain carver already recovers this; the control has broken"


# ───────────────────────────────────────────────── the evidence behind the joins

def test_every_fragment_was_proven_by_crc_not_accepted_by_a_decoder(l2_result, truth):
    got = next(r for r in l2_result if truth.get(r["sha256"]) == "000_0021.png")
    assert "CRC-32" in got["integrity_checked"]
    assert got["decoded"] is True
    assert "PNG" in got["decode_note"]


def test_the_boundary_chunk_was_recovered(l2_result, truth):
    """The chunk split across the fragmentation point CRCs in neither location. Without
    it the rebuild is 8,204 bytes short, it decodes perfectly and is still wrong, which
    is exactly the failure a decoder check cannot catch."""
    got = next(r for r in l2_result if truth.get(r["sha256"]) == "000_0021.png")
    assert got["boundary_recovered"] is True


def test_it_reports_two_fragments_and_says_where_they_were(l2_result, truth):
    got = next(r for r in l2_result if truth.get(r["sha256"]) == "000_0021.png")
    assert len(got["fragments"]) == 2
    for f in got["fragments"]:
        assert f["offset"] >= 0 and f["length"] > 0 and f["chunks"] > 0
    kinds = {k for f in got["fragments"] for k in f["kinds"]}
    assert "IHDR" in kinds and "IEND" in kinds


def test_the_result_is_labelled_reassembled_never_a_contiguous_find(l2_result):
    """A reassembly presented as an ordinary carve would overstate its provenance."""
    assert all(r["reassembled"] is True for r in l2_result)


def test_the_reason_states_the_ordering_was_forced_not_chosen(l2_result, truth):
    got = next(r for r in l2_result if truth.get(r["sha256"]) == "000_0021.png")
    assert "forced by the format" in got["reason"]


# ───────────────────────────────────────────────── the CRC oracle actually discriminates

def test_a_corrupted_chunk_is_rejected(tmp_path):
    """If a flipped byte still passed, 'CRC-proven' would be decoration."""
    src = TARGET.read_bytes()
    good = len(_png_chunks(memoryview(src)))
    assert good > 3

    broken = bytearray(src)
    broken[len(src) // 2] ^= 0xFF
    after = len(_png_chunks(memoryview(bytes(broken))))
    assert after < good, "corrupting a byte did not invalidate any chunk"


def test_the_straddle_search_rejects_every_wrong_split():
    """Constructed so exactly one split can pass. If several did, the CRC would not be an
    oracle and the recovered chunk would be a guess."""
    payload = bytes(range(256)) * 8          # 2048 bytes
    body = b"IDAT" + payload
    chunk = (struct.pack(">I", len(payload)) + body
             + struct.pack(">I", zlib.crc32(body) & 0xFFFFFFFF))
    split = 700
    # Layout matters and it caught a bug in this test, not in the module: the straddle
    # TAIL sits immediately BEFORE fragment 2's validated run, not after a gap.
    #   [ head ][ unrelated bytes ][ tail ][ fragment 2 ... ]
    buf = memoryview(chunk[:split] + b"\x00" * 4096 + chunk[split:] + b"\xEE" * 64)
    frag1_end = 0
    frag2_start = split + 4096 + (len(chunk) - split)

    got = _recover_straddle(buf, frag1_end, frag2_start)
    assert got == (split, len(chunk) - split)


def test_the_straddle_search_returns_none_when_there_is_no_chunk():
    buf = memoryview(b"\x00" * 8192)
    assert _recover_straddle(buf, 0, 4096) is None


def test_random_data_does_not_yield_chunks():
    """The scan must not manufacture structure. 4 MB of SHA-256 output, no anchors."""
    blob = b"".join(hashlib.sha256(i.to_bytes(8, "big")).digest()
                    for i in range(4 << 20 // 32))
    assert _png_chunks(memoryview(blob)) == []


# ───────────────────────────────────────────────── run grouping

def test_adjacent_chunks_group_into_one_run():
    chunks = [(0, b"IHDR", 13, 25), (25, b"IDAT", 10, 47), (47, b"IEND", 0, 59)]
    assert len(_runs(chunks)) == 1


def test_a_gap_splits_a_run():
    chunks = [(0, b"IHDR", 13, 25), (900, b"IDAT", 10, 922)]
    assert len(_runs(chunks)) == 2


def test_no_chunks_gives_no_runs():
    assert _runs([]) == []


# ───────────────────────────────────────────────── it does not fire when unneeded

def test_a_contiguous_png_is_not_reported_as_reassembled(tmp_path):
    """L0 holds contiguous files. Reporting them here as well would double-count them in
    every recall figure downstream."""
    img = tmp_path / "contig.img"
    img.write_bytes(b"\x00" * 4096 + TARGET.read_bytes() + b"\x00" * 4096)
    assert reassemble(str(img)) == []


def test_an_empty_image_returns_nothing(tmp_path):
    p = tmp_path / "empty.img"
    p.write_bytes(b"")
    assert reassemble(str(p)) == []


def test_a_missing_image_raises_rather_than_returning_nothing():
    with pytest.raises(FileNotFoundError):
        reassemble(str(DATA / "does-not-exist.dd"))


# ───────────────────────────────────────────────── honest summary

def test_the_summary_says_these_are_reassembled(l2_result):
    s = summarize(l2_result)
    assert s["total"] == len(l2_result)
    assert s["boundary_chunks_recovered"] >= 1
    assert "reassembled files and are labelled as such" in s["note"]


def test_the_summary_of_nothing_is_not_a_success_claim():
    s = summarize([])
    assert s["total"] == 0
    assert s["all_decoded"] is None
