"""ZIP fragment reassembly, against real Word documents.

`.docx`, `.xlsx`, `.pptx`, `.jar` and `.apk` are ZIP containers, so a fragmented-ZIP
recovery is a fragmented-*document* recovery. The corpus here is real: the actual research
documents in this repository, not archives generated to be recoverable.

THE BAR IS BYTE-IDENTITY, and it is the whole point. Garfinkel's 2007 ZIP Carver, the
established prior art, locates components and **repackages them with a new central
directory**, producing a file that opens in any unzip utility. That is right for data
recovery and wrong for evidence: a repackaged archive is a different file whose hash matches
nothing, so it cannot be tied to a hash recorded earlier in a case. This module reconstructs
the original layout or returns nothing.

THE HARD CASE is the entry cut in half by the fragmentation. On the real corpus that entry
is `word/document.xml`, the document itself, so giving up on it means giving up on the
file. Its bytes are not contiguous anywhere in the image; the split point is found by search
with CRC-32 as the oracle.
"""
from __future__ import annotations

import hashlib
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from recovery.zipcarve import reassemble_zip_file  # noqa: E402

CORPUS = ROOT / "research" / "reference"
DOCS = sorted(CORPUS.glob("*.docx")) if CORPUS.is_dir() else []

pytestmark = pytest.mark.skipif(
    len(DOCS) < 2, reason="real .docx corpus not present in this checkout")


def filler(n: int, seed: int) -> bytes:
    """Deterministic, so a failure reproduces rather than depending on the run."""
    return b"".join(hashlib.sha256((i + seed).to_bytes(8, "big")).digest()
                    for i in range(n // 32 + 1))[:n]


def image(tmp_path, data: bytes, name="case.img") -> str:
    p = tmp_path / name
    p.write_bytes(data)
    return str(p)


def split_swapped(src: bytes, frac: float) -> bytes:
    """The realistic shape: two fragments with the SECOND HALF STORED FIRST."""
    pos = int(len(src) * frac)
    return filler(8192, 3) + src[pos:] + filler(16384, 4) + src[:pos] + filler(4096, 5)


# ───────────────────────────────────────── the claim

@pytest.mark.parametrize("doc", DOCS, ids=lambda p: p.stem[:24])
@pytest.mark.parametrize("frac", [0.3, 0.5, 0.75])
def test_a_fragmented_document_is_recovered_byte_identically(doc, frac, tmp_path):
    """THE HEADLINE, across every real document at three split points."""
    src = doc.read_bytes()
    got = reassemble_zip_file(image(tmp_path, split_swapped(src, frac)))
    assert got, f"nothing recovered from {doc.name} split at {frac}"
    assert got[0]["sha256"] == hashlib.sha256(src).hexdigest()
    assert got[0]["size"] == len(src)


def test_the_straddling_entry_is_recovered(tmp_path):
    """Its bytes are not contiguous anywhere in the image. On real .docx files that entry
    is word/document.xml, so failing it means failing the document."""
    src = DOCS[0].read_bytes()
    got = reassemble_zip_file(image(tmp_path, split_swapped(src, 0.5)))
    assert got
    assert got[0]["sha256"] == hashlib.sha256(src).hexdigest()
    assert "word/document.xml" in got[0]["names"]


def test_the_recovered_archive_opens_and_every_entry_checks_out(tmp_path):
    """Byte-identity implies this, and it is asserted anyway: a hash match on bytes that do
    not open would mean the corpus file was already broken."""
    import io
    import zipfile

    src = DOCS[0].read_bytes()
    got = reassemble_zip_file(image(tmp_path, split_swapped(src, 0.5)))
    assert got and got[0]["sha256"] == hashlib.sha256(src).hexdigest()

    with zipfile.ZipFile(io.BytesIO(src)) as z:
        assert z.testzip() is None
        assert len(z.namelist()) == got[0]["entries"]


# ───────────────────────────────────────── fragments come from the format

def test_the_fragment_count_is_derived_not_estimated(tmp_path):
    """Entries sharing an offset delta were stored together, so the count falls out of the
    format rather than being guessed at."""
    src = DOCS[0].read_bytes()
    got = reassemble_zip_file(image(tmp_path, split_swapped(src, 0.5)))
    frags = got[0]["fragments"]
    assert len(frags) == 2
    assert len({f["delta"] for f in frags}) == 2
    assert sum(f["entries"] for f in frags) <= got[0]["entries"]


def test_every_entry_was_crc_verified(tmp_path):
    src = DOCS[0].read_bytes()
    got = reassemble_zip_file(image(tmp_path, split_swapped(src, 0.5)))
    assert f"CRC-32 verified on all {got[0]['entries']} entries" in got[0]["integrity_checked"]


def test_the_reason_states_it_is_not_a_repackage(tmp_path):
    """The distinction from the prior art, in the record rather than only in the docs."""
    src = DOCS[0].read_bytes()
    got = reassemble_zip_file(image(tmp_path, split_swapped(src, 0.5)))
    assert "not a repackaged equivalent" in got[0]["reason"]


# ───────────────────────────────────────── negatives

def test_a_contiguous_archive_is_not_reported(tmp_path):
    """That is the ordinary carver's job; reporting it here too would double-count it."""
    src = DOCS[0].read_bytes()
    assert reassemble_zip_file(
        image(tmp_path, filler(8192, 1) + src + filler(4096, 2))) == []


def test_random_data_yields_nothing(tmp_path):
    assert reassemble_zip_file(image(tmp_path, filler(200_000, 9))) == []


def test_a_truncated_archive_is_refused(tmp_path):
    """First half only: no central directory, so nothing is declared and nothing is built."""
    src = DOCS[0].read_bytes()
    half = filler(4096, 1) + src[:len(src) // 2] + filler(4096, 2)
    assert reassemble_zip_file(image(tmp_path, half)) == []


def test_a_headless_archive_is_refused(tmp_path):
    """Second half only: the directory declares entries whose data is gone. A document
    missing a part is not the document."""
    src = DOCS[0].read_bytes()
    tail = filler(4096, 3) + src[len(src) // 2:] + filler(4096, 4)
    assert reassemble_zip_file(image(tmp_path, tail)) == []


def test_halves_of_two_different_documents_are_not_spliced(tmp_path):
    """THE MOST IMPORTANT NEGATIVE. Both halves are real, CRC-valid archive data, just not
    from the same file. A splice would open perfectly and be evidence of nothing."""
    a, b = DOCS[0].read_bytes(), DOCS[1].read_bytes()
    mixed = filler(4096, 5) + a[:len(a) // 2] + filler(8192, 6) + b[len(b) // 2:]
    assert reassemble_zip_file(image(tmp_path, mixed)) == []


def test_three_fragments_return_nothing_rather_than_something_wrong(tmp_path):
    """Beyond the documented two-fragment capability. Silence at the edge of a capability is
    honest; a plausible wrong answer is the failure this guards."""
    src = DOCS[0].read_bytes()
    p1, p2 = int(len(src) * 0.3), int(len(src) * 0.7)
    img = (filler(4096, 1) + src[p2:] + filler(8192, 2) + src[:p1]
           + filler(8192, 3) + src[p1:p2])
    got = reassemble_zip_file(image(tmp_path, img))
    assert all(r["sha256"] != hashlib.sha256(src).hexdigest() for r in got) or not got
    assert got == [], "a partial or wrong archive must never be offered"


def test_a_missing_image_raises_rather_than_returning_nothing(tmp_path):
    with pytest.raises(FileNotFoundError):
        reassemble_zip_file(str(tmp_path / "absent.img"))


def test_an_empty_image_returns_nothing(tmp_path):
    assert reassemble_zip_file(image(tmp_path, b"")) == []
