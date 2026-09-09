"""The self-accumulating regression corpus.

The claim: the tool gets harder to break with each real task, WITHOUT changing its own
code. What accumulates is evidence about itself, each real run pinned as a case it must
keep reproducing.

The two failure modes worth testing are not "does it store JSON". They are:
  * a corpus that quietly reports green while testing nothing (every case UNAVAILABLE)
  * a corpus that treats drift as an automatic verdict against the newer code
Both are tested here, because both would make the corpus worse than not having one.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from attestation import corpus  # noqa: E402

REPO_CORPUS = Path(__file__).resolve().parents[1] / "corpus"


@pytest.fixture
def box(tmp_path):
    return tmp_path / "corpus"


# --------------------------------------------------------------------------- pinning

def test_a_case_is_pinned_and_reloads(box):
    corpus.record("carve", inputs={"name": "x.dd", "size": 10, "sha256": "ab" * 32},
                  digest="cd" * 32, base=box)
    cases = corpus.load_all(base=box)
    assert len(cases) == 1
    assert cases[0]["digest"] == "cd" * 32


def test_pinning_the_same_observation_twice_does_not_duplicate(box):
    args = dict(inputs={"name": "x.dd", "size": 10, "sha256": "ab" * 32},
                digest="cd" * 32, base=box)
    a = corpus.record("carve", **args)
    b = corpus.record("carve", **args)
    assert a == b
    assert len(corpus.load_all(base=box)) == 1


def test_the_kind_vocabulary_is_closed(box):
    with pytest.raises(ValueError):
        corpus.record("whatever-i-felt-like", inputs={}, digest="ab" * 32, base=box)


def test_a_case_with_no_digest_is_refused(box):
    with pytest.raises(ValueError):
        corpus.record("carve", inputs={}, digest="", base=box)


def test_the_case_names_the_build_that_pinned_it(box):
    """Without it, a drift report cannot say which two builds disagreed."""
    from attestation.toolref import tool_ref
    corpus.record("carve", inputs={"sha256": "ab" * 32}, digest="cd" * 32, base=box)
    assert corpus.load_all(base=box)[0]["recorded_by_tool"] == tool_ref()


# ------------------------------------------------------------------- it stores no evidence

def test_a_pinned_case_holds_no_evidence_and_no_machine_identity(box):
    """The corpus is committed to a public repo. A field that leaked the examiner's
    machine, or the drive's contents, would make it unshareable, and an unshareable
    regression suite is not one."""
    path = corpus.record("carve", inputs={"name": "x.dd", "size": 10,
                                          "sha256": "ab" * 32},
                         digest="cd" * 32, base=box)
    # The FILE, not the loaded dict: load_all injects _path at load time, which is a
    # local convenience and is never written. Testing the dict would fail on the temp
    # directory's own name and prove nothing about what gets committed.
    blob = path.read_text(encoding="utf-8").lower()
    import getpass, socket
    for leak in (getpass.getuser().lower(), socket.gethostname().lower()):
        if leak and len(leak) > 3:
            assert leak not in blob, f"{leak!r} leaked into a corpus case"
    assert "c:\\users" not in blob and "/home/" not in blob


def test_the_environment_is_recorded_but_only_the_explanatory_parts(box):
    corpus.record("carve", inputs={"sha256": "ab" * 32}, digest="cd" * 32, base=box)
    env = corpus.load_all(base=box)[0]["environment"]
    assert set(env) == {"python", "system", "machine", "byteorder"}


# --------------------------------------------------------------------------- replaying

def test_a_reproducing_case_passes(box):
    corpus.record("carve", inputs={"sha256": "ab" * 32}, digest="cd" * 32, base=box)
    report = corpus.replay_all({"carve": lambda _i: "cd" * 32}, base=box)
    assert report["ok"] is True
    assert report["counts"]["REPRODUCED"] == 1


def test_drift_is_caught(box):
    corpus.record("carve", inputs={"sha256": "ab" * 32}, digest="cd" * 32, base=box)
    report = corpus.replay_all({"carve": lambda _i: "ee" * 32}, base=box)
    assert report["ok"] is False
    assert report["counts"]["DRIFTED"] == 1


def test_drift_is_a_question_not_a_verdict(box):
    """If a run was wrong, pinning it pinned the bug. The report must not assert that the
    newer code is the broken side."""
    corpus.record("carve", inputs={"sha256": "ab" * 32}, digest="cd" * 32, base=box)
    report = corpus.replay_all({"carve": lambda _i: "ee" * 32}, base=box)
    drifted = [r for r in report["results"] if r["status"] == "DRIFTED"][0]
    assert "question for a human" in drifted["reason"]
    assert drifted["pinned_by_tool"] and drifted["current_tool"]


def test_an_unavailable_case_is_not_a_pass(box):
    """THE DANGEROUS FAILURE. A corpus where every case became unavailable would report a
    green suite while testing nothing."""
    corpus.record("carve", inputs={"sha256": "ab" * 32}, digest="cd" * 32, base=box)
    report = corpus.replay_all({"carve": lambda _i: None}, base=box)
    assert report["counts"].get("REPRODUCED", 0) == 0
    assert report["counts"]["UNAVAILABLE"] == 1
    assert "unavailable" in report["reason"]


def test_a_raising_recompute_is_reported_not_propagated(box):
    def boom(_inputs):
        raise RuntimeError("carver exploded")

    corpus.record("carve", inputs={"sha256": "ab" * 32}, digest="cd" * 32, base=box)
    report = corpus.replay_all({"carve": boom}, base=box)
    assert report["ok"] is False
    assert report["counts"]["ERROR"] == 1


def test_a_malformed_case_file_is_reported_not_skipped(box):
    """Silently ignoring corpus entries would let the suite shrink to zero unnoticed."""
    d = box / "carve"
    d.mkdir(parents=True)
    (d / "junk.json").write_text("{not json", encoding="utf-8")
    report = corpus.replay_all({"carve": lambda _i: "cd" * 32}, base=box)
    assert report["ok"] is False
    assert report["counts"]["BROKEN"] == 1


def test_a_case_from_another_corpus_version_is_refused(box):
    path = corpus.record("carve", inputs={"sha256": "ab" * 32}, digest="cd" * 32, base=box)
    case = json.loads(path.read_text(encoding="utf-8"))
    case["corpus_version"] = "99"
    path.write_text(json.dumps(case), encoding="utf-8")

    report = corpus.replay_all({"carve": lambda _i: "cd" * 32}, base=box)
    assert report["counts"]["BROKEN"] == 1


def test_a_kind_with_no_recompute_function_is_unavailable_not_passed(box):
    corpus.record("erase", inputs={"sha256": "ab" * 32}, digest="cd" * 32, base=box)
    report = corpus.replay_all({}, base=box)
    assert report["counts"]["UNAVAILABLE"] == 1
    assert report["counts"].get("REPRODUCED", 0) == 0


def test_an_empty_corpus_says_so_rather_than_passing_silently(box):
    report = corpus.replay_all({"carve": lambda _i: "x"}, base=box)
    assert "empty" in report["reason"]


# ------------------------------------------------------- the corpus that actually exists

@pytest.mark.skipif(not REPO_CORPUS.is_dir(), reason="no corpus pinned in this checkout")
def test_the_repo_corpus_reproduces():
    """THE REAL GATE. Replays every case pinned from real data in this repository.

    UNAVAILABLE is tolerated -- a checkout without the CFReDS images should not fail the
    build -- but DRIFTED, BROKEN and ERROR are not.
    """
    sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
    from pin_corpus import RECOMPUTE

    report = corpus.replay_all(RECOMPUTE)
    bad = [r for r in report["results"]
           if r["status"] in ("DRIFTED", "BROKEN", "ERROR")]
    assert not bad, f"corpus no longer reproduces: {bad}"


@pytest.mark.skipif(not REPO_CORPUS.is_dir(), reason="no corpus pinned in this checkout")
def test_the_repo_corpus_is_not_empty():
    """A corpus that silently emptied would make the gate above vacuous."""
    assert corpus.stats()["total"] > 0
