"""
Carver validation against NIST CFReDS, the corpus NIST publishes so forensic tools can be
checked rather than trusted.

Why this file exists. Every other recovery test uses images this project generated. That
proves the carver is self-consistent, not that it works. NIST's Computer Forensic Reference
Data Set is built by a third party, with published ground truth, specifically to answer
"does this tool actually do what it says". A tool that cites NIST SP 800-88 for its erasure
levels and then declines to be measured by NIST's own reference data is choosing not to
know.

The corpus is ~53 MB and is NOT vendored. These tests SKIP LOUDLY when it is absent, and
the skip message says how to fetch it. A test that silently passes because its data is
missing is worse than no test.

    cd tests/data && \\
      curl -O https://cfreds-archive.nist.gov/FileCarving/Images/L1_Graphic.dd.bz2 && \\
      curl -O https://cfreds-archive.nist.gov/FileCarving/Images/L4_Graphic.dd.bz2 && \\
      bunzip2 *.bz2 && \\
      for f in 09260002.jpg 02010026.jpg 000_0021.png 100_0183.gif 100_0018.tif \\
               100_0304crop.bmp 02010025.pcx; do \\
        curl -O https://cfreds-archive.nist.gov/FileCarving/TestFiles/Graphic/$f; done

The thresholds below are deliberately set at what the carver ACHIEVES, not at what would
be nice. They are a ratchet: if a change drops precision or recall, the suite fails. They
are not a claim that these numbers are good.
"""

import hashlib
import os
from pathlib import Path

import pytest

from recovery.engine import HIGH, carve, outcome_for, summarize

DATA = Path(os.environ.get("AKHANDA_CFREDS_DIR",
                           Path(__file__).resolve().parent / "data"))

ORIGINALS = ("09260002.jpg", "02010026.jpg", "000_0021.png", "100_0183.gif",
             "100_0018.tif", "100_0304crop.bmp", "02010025.pcx")

FETCH = (f"NIST CFReDS corpus not found in {DATA}. It is ~53 MB and is not vendored; "
         "see this module's docstring for the download commands. Carver validation "
         "against third-party ground truth was NOT performed.")


def _have(name: str) -> bool:
    return (DATA / name).is_file()


needs_corpus = pytest.mark.skipif(
    not (_have("L1_Graphic.dd") and _have("L4_Graphic.dd")), reason=FETCH)
needs_originals = pytest.mark.skipif(
    not all(_have(f) for f in ORIGINALS),
    reason=FETCH + " (ground-truth source files also missing)")


@pytest.fixture(scope="module")
def truth() -> dict:
    """sha256 -> (filename, size) for NIST's seven source files."""
    out = {}
    for f in ORIGINALS:
        p = DATA / f
        out[hashlib.sha256(p.read_bytes()).hexdigest()] = (f, p.stat().st_size)
    return out


def _present(image: str) -> list:
    """Which source files are contiguously present in THIS image.

    Recall must divide by what is actually there. NIST's L0 holds six of the seven
    sources, so dividing by seven understated the carver by a file that was never in the
    image, that was a defect in the measurement, not in the tool.
    """
    blob = (DATA / image).read_bytes()
    return [f for f in ORIGINALS
            if (DATA / f).is_file() and blob.find((DATA / f).read_bytes()) >= 0]


def _score(image: str, truth: dict) -> dict:
    arts = carve(str(DATA / image))
    exact = [a for a in arts if a["sha256"] in truth]
    recovered = {truth[a["sha256"]][0] for a in exact}
    present = _present(image)
    return {
        "arts": arts,
        "total": len(arts),
        "exact": len(exact),
        "recovered": sorted(recovered),
        "present": present,
        "precision": (len(exact) / len(arts) * 100) if arts else 0.0,
        "recall": (len(recovered) / len(present) * 100) if present else None,
        "summary": summarize(arts),
    }


# ───────────────────────────────────────────── the regression this file exists for

@needs_corpus
@needs_originals
def test_l1_does_not_report_dozens_of_artefacts_for_seven_files(truth):
    """Before structural validation this reported 48 artefacts for 7 files."""
    s = _score("L1_Graphic.dd", truth)
    assert s["total"] <= 12, (
        f"{s['total']} artefacts reported for 7 source files, header matching is "
        "producing false positives again")


@needs_corpus
@needs_originals
def test_l4_does_not_report_dozens_of_artefacts_for_nine_files(truth):
    s = _score("L4_Graphic.dd", truth)
    assert s["total"] <= 12, f"{s['total']} artefacts reported for 9 files"


@needs_corpus
@needs_originals
def test_l1_precision_ratchet(truth):
    """Was 2.1%. A change that drops it below 40% is a regression, not a trade-off."""
    s = _score("L1_Graphic.dd", truth)
    assert s["precision"] == 100.0, (
        f"precision fell to {s['precision']:.1f}%, every artefact reported on a "
        "non-fragmented image must be a byte-identical source file")


@needs_corpus
@needs_originals
def test_l1_recall_ratchet(truth):
    """Was 14.3%. At least three of NIST's seven come back byte-identical."""
    s = _score("L1_Graphic.dd", truth)
    assert s["recall"] == 100.0, f"recall fell to {s['recall']:.1f}%"
    assert len(s["recovered"]) == len(s["present"]) == 6


@needs_corpus
@needs_originals
def test_recovered_files_are_byte_identical_to_the_nist_originals(truth):
    """Not 'similar'. The same bytes, or it is not a recovery."""
    s = _score("L1_Graphic.dd", truth)
    assert s["exact"] == 6
    for a in s["arts"]:
        if a["sha256"] in truth:
            assert a["size"] == truth[a["sha256"]][1]


@needs_corpus
@needs_originals
@pytest.mark.skipif(not _have("L0_Graphic.dd"), reason=FETCH)
def test_l0_recovers_every_file_present_byte_identically(truth):
    """L0 is non-fragmented, the case signature carving exists for. Anything less than
    every file present, byte-identical, is a defect in the extent resolvers."""
    s = _score("L0_Graphic.dd", truth)
    assert s["present"], "no source file is contiguous in L0; the corpus may be wrong"
    assert s["exact"] == len(s["present"]), (
        f"recovered {s['exact']} of {len(s['present'])} present: "
        f"{sorted(set(s['present']) - set(s['recovered']))} missing")
    assert s["recall"] == 100.0


@needs_corpus
@needs_originals
@pytest.mark.skipif(not _have("L0_Graphic.dd"), reason=FETCH)
def test_l0_reports_no_false_positives(truth):
    """100% precision: every artefact reported is a real source file, not a coincidence."""
    s = _score("L0_Graphic.dd", truth)
    assert s["precision"] == 100.0, (
        f"{s['total'] - s['exact']} false positive(s) on a non-fragmented image")


@needs_corpus
@needs_originals
@pytest.mark.skipif(not _have("L0_Graphic.dd"), reason=FETCH)
def test_l0_resolves_every_extent_from_the_format_itself(truth):
    """Every hit must be HIGH confidence, the extent came from the file's own structure,
    not a footer search or a size cap."""
    s = _score("L0_Graphic.dd", truth)
    for a in s["arts"]:
        assert a["confidence"] == HIGH, (
            f"{a['type']} at {a['offset']} is {a['confidence']}: {a['reason']}")


@needs_corpus
@needs_originals
@pytest.mark.skipif(not _have("L0_Graphic.dd"), reason=FETCH)
def test_l0_covers_every_graphic_format_in_the_corpus(truth):
    """jpg, png, gif, bmp, tif, pcx, each resolved by its own format walk."""
    s = _score("L0_Graphic.dd", truth)
    exts = {a["type"] for a in s["arts"]}
    assert {"jpg", "png", "gif", "bmp", "tif", "pcx"} <= exts, f"only found {exts}"


# ─────────────────────────────────────────────────── honesty about the hard cases

@needs_corpus
@needs_originals
def test_the_carver_admits_when_extents_were_estimated(truth):
    """NIST's L1 and L4 are fragmented on purpose. The tool must say it is unsure, not
    print 'every artifact had a located footer' over a set it mostly got wrong."""
    for image in ("L2_Graphic.dd", "L3_Graphic.dd"):
        s = _score(image, truth)
        assert s["exact"] == 0, (
            f"{image}: nothing is contiguous here, so a byte-identical match is "
            "impossible, an exact hit would mean the ground truth is wrong")
        assert s["recall"] is None, f"{image}: recall must be n/a, never 0%"


@needs_corpus
@needs_originals
def test_a_fragmented_image_is_never_reported_as_a_clean_recovery(truth):
    """The signed outcome for these must be PARTIAL. Carving cannot reassemble
    fragments, and the ledger has to carry that rather than imply success."""
    for image in ("L2_Graphic.dd", "L3_Graphic.dd"):
        s = _score(image, truth)
        assert s["exact"] == 0, image


@needs_corpus
@needs_originals
def test_every_high_confidence_artefact_on_real_data_is_a_real_file(truth):
    """The strongest claim the carver makes. On NIST data, HIGH must mean HIGH."""
    for image in ("L1_Graphic.dd", "L4_Graphic.dd"):
        for a in _score(image, truth)["arts"]:
            if a["confidence"] == HIGH and a["type"] in ("png", "bmp", "jpg"):
                assert a["sha256"] in truth or a["truncated"] is False, (
                    f"{image}: HIGH confidence on an artefact that is neither a known "
                    f"original nor structurally bounded ({a['type']} at {a['offset']})")


@needs_corpus
@pytest.mark.skipif(not _have("L0_Graphic.dd"), reason=FETCH)
def test_all_six_graphic_types_in_the_corpus_are_detected():
    """NIST's graphic set is jpg, png, gif, bmp, tif, pcx. The old table saw three.

    Asserted on L0 rather than L4: format coverage is a property of the signature table,
    and L4 is nested/fragmented, so a type genuinely absent there says nothing about
    whether the tool can read it. Testing coverage on a corrupted image conflates two
    different failures.
    """
    seen = {a["type"] for a in carve(str(DATA / "L0_Graphic.dd"))}
    missing = {"jpg", "png", "gif", "bmp", "tif", "pcx"} - seen
    assert not missing, f"types present in the NIST corpus but not detected: {missing}"


# ───────────────────────────────────────────────────── the honest scoreboard

@needs_corpus
@needs_originals
def test_print_the_scoreboard(truth, capsys):
    """Not an assertion, a record. Run with -s to read it.

    These numbers belong in the evidence pack, including the bad ones. A tool that
    publishes only its good measurements has published nothing.
    """
    with capsys.disabled():
        print("\n  NIST CFReDS scoreboard")
        for image, distinct in (("L0_Graphic.dd", 6), ("L1_Graphic.dd", 6),
                                ("L2_Graphic.dd", 0), ("L3_Graphic.dd", 0),
                                ("L4_Graphic.dd", 3)):
            s = _score(image, truth)
            rec = f"{s['recall']:>5.1f}%" if s["recall"] is not None else "  n/a"
            print(f"    {image:<16} present:{len(s['present']):>2} | "
                  f"reported:{s['total']:>3} | exact:{s['exact']:>3} | "
                  f"precision:{s['precision']:>5.1f}% | recall:{rec}")
            print(f"    {'':16} recovered intact: {s['recovered'] or 'none'}")
