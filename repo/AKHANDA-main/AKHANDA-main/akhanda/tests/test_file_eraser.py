"""
Secure File and Folder Eraser, problem statement module (b).

The four tests that matter most are the ones the shipped reference implementation failed,
each confirmed against the real code before it was rewritten:

  A. verification actually verifies. The first version wrote unreproducible random bytes
     and "verified" by checking the read-back was not all zeros, so it returned True for
     a file that had never been touched.
  B. an unidentifiable filesystem downgrades the outcome, as its own docstring claimed , 
     the stub returned "unknown" unconditionally and unknown produced VERIFIED, the
     strongest value.
  C. a partial run does not report "NotPerformed" while files were irreversibly
     destroyed. Understating destruction is no more honest than overstating it.
  D. the guard has the same three gates as the drive eraser, not one boolean. A recursive
     file eraser can destroy as much as a block-device wipe.

Everything here runs against the real filesystem of the machine it is run on.
"""

import os
import platform

import pytest

from erasure import file_eraser as fe

SECRET = b"SENSITIVE-EVIDENCE-" * 500          # ~9.5 KB, recognisable in a hex dump


@pytest.fixture(autouse=True)
def gate(monkeypatch):
    """Open the environment gate for the whole module; the token is still per-call."""
    monkeypatch.setenv(fe.ALLOW_ENV, "1")


@pytest.fixture()
def target(tmp_path):
    p = tmp_path / "secret.bin"
    p.write_bytes(SECRET)
    return p


def _erase(path, **kw):
    return fe.erase_path(str(path), confirm=fe.CONFIRM_TOKEN, **kw)


# ══════════════════════════════════════════ A. verification actually verifies

def test_verify_rejects_a_file_that_was_never_overwritten(tmp_path):
    """THE BUG. The old check returned True here because old data is not zeros."""
    p = tmp_path / "untouched.bin"
    p.write_bytes(SECRET)
    seed = b"\x01" * 32
    matched, samples = fe.verify_overwritten(p, p.stat().st_size, seed)
    assert matched is False
    assert samples and not all(s["match"] for s in samples)


def test_verify_accepts_a_file_that_was_overwritten_with_that_seed(tmp_path):
    p = tmp_path / "wiped.bin"
    p.write_bytes(SECRET)
    seed = b"\x02" * 32
    fe._overwrite_in_place(p, p.stat().st_size, seed, 1)
    matched, samples = fe.verify_overwritten(p, p.stat().st_size, seed)
    assert matched is True
    assert all(s["match"] for s in samples)


def test_verify_rejects_the_wrong_seed(tmp_path):
    """Proves the comparison is against a real reference, not a shape heuristic."""
    p = tmp_path / "wiped.bin"
    p.write_bytes(SECRET)
    fe._overwrite_in_place(p, p.stat().st_size, b"\x03" * 32, 1)
    matched, _ = fe.verify_overwritten(p, p.stat().st_size, b"\x04" * 32)
    assert matched is False


def test_verify_detects_a_write_that_was_silently_reverted(tmp_path):
    """A failing or write-protected volume must fail verification, not pass it."""
    p = tmp_path / "flaky.bin"
    p.write_bytes(SECRET)
    seed = b"\x05" * 32
    fe._overwrite_in_place(p, p.stat().st_size, seed, 1)
    with open(p, "r+b") as fh:
        fh.seek(0)
        fh.write(b"OLD-DATA-CAME-BACK" * 100)
    matched, _ = fe.verify_overwritten(p, p.stat().st_size, seed)
    assert matched is False


def test_the_pattern_matches_the_drive_eraser_construction(tmp_path):
    """One idea, one implementation, in the two places that needed it."""
    from erasure.engine import _pattern as drive_pattern
    seed = b"\x06" * 32
    assert fe._pattern(seed, 0, 4096) == drive_pattern(seed, 0, 4096)
    assert fe._pattern(seed, 12345, 777) == drive_pattern(seed, 12345, 777)


# ══════════════════════════════════ B. unknown filesystem downgrades the outcome

def test_unknown_filesystem_downgrades_to_unverified(target, monkeypatch):
    """The docstring promised this; the stub did the opposite."""
    monkeypatch.setattr(fe, "detect_filesystem", lambda p: "unknown")
    r = _erase(target)
    assert r["outcome"] == fe.OUTCOME_UNVERIFIED
    assert "could not be identified" in r["targets"][0]["reason"]


def test_cow_filesystem_downgrades_to_partial(target, monkeypatch):
    monkeypatch.setattr(fe, "detect_filesystem", lambda p: "btrfs")
    r = _erase(target)
    assert r["outcome"] == fe.OUTCOME_PARTIAL
    assert any("copy-on-write" in l for l in r["limitations"])


def test_cow_is_partial_even_when_read_back_matched(target, monkeypatch):
    """The read came back through the same layer that may have written elsewhere."""
    monkeypatch.setattr(fe, "detect_filesystem", lambda p: "zfs")
    monkeypatch.setattr(fe, "verify_overwritten", lambda *a, **k: (True, []))
    r = _erase(target)
    assert r["outcome"] == fe.OUTCOME_PARTIAL


def test_a_known_non_cow_filesystem_can_reach_verified(target, monkeypatch):
    monkeypatch.setattr(fe, "detect_filesystem", lambda p: "ext4")
    r = _erase(target)
    assert r["outcome"] == fe.OUTCOME_VERIFIED
    assert "ext4" in r["targets"][0]["reason"]


# ═══════════════════════════ C. a partial run does not understate destruction

def test_a_partial_run_reports_clear_and_counts_what_was_destroyed(tmp_path, monkeypatch):
    """Reporting NotPerformed while files were destroyed is false in the other
    direction."""
    for n in ("a.bin", "b.bin", "c.bin"):
        (tmp_path / n).write_bytes(SECRET)

    real = fe.erase_file
    calls = {"n": 0}

    def flaky(path, **kw):
        calls["n"] += 1
        if calls["n"] == 3:
            return fe.TargetResult(path, 0, "NotPerformed", fe.OUTCOME_NOT_PERFORMED,
                                   "forced failure")
        return real(path, **kw)

    monkeypatch.setattr(fe, "erase_file", flaky)
    r = _erase(tmp_path, recursive=True)

    assert r["performed"] == 2
    assert r["method_used"] == "Clear"                  # not "NotPerformed"
    assert r["outcome"] == fe.OUTCOME_NOT_PERFORMED     # outcome still quotes the worst
    assert r["verified"] is False
    assert any("remain on disk" in l for l in r["limitations"])


def test_outcome_is_quoted_at_the_weakest_target(tmp_path, monkeypatch):
    """One clean file must not launder a failed one beside it."""
    (tmp_path / "a.bin").write_bytes(SECRET)
    (tmp_path / "b.bin").write_bytes(SECRET)
    real = fe.erase_file
    calls = {"n": 0}

    def flaky(path, **kw):
        calls["n"] += 1
        if calls["n"] == 2:
            return fe.TargetResult(path, 1, "Clear", fe.OUTCOME_UNVERIFIED, "forced")
        return real(path, **kw)

    monkeypatch.setattr(fe, "erase_file", flaky)
    r = _erase(tmp_path, recursive=True)
    assert r["outcome"] == fe.OUTCOME_UNVERIFIED
    assert r["verified"] is False


def test_a_fully_failed_run_reports_not_performed(tmp_path, monkeypatch):
    (tmp_path / "a.bin").write_bytes(SECRET)
    monkeypatch.setattr(fe, "erase_file",
                        lambda path, **kw: fe.TargetResult(path, 0, "NotPerformed",
                                                           fe.OUTCOME_NOT_PERFORMED, "x"))
    r = _erase(tmp_path, recursive=True)
    assert r["performed"] == 0
    assert r["method_used"] == "NotPerformed"


# ═════════════════════════════════════════════════ D. three gates, not one boolean

def test_missing_token_is_refused(target):
    with pytest.raises(fe.FileErasureRefused, match="confirm="):
        fe.erase_path(str(target))
    assert target.read_bytes() == SECRET


def test_wrong_token_is_refused(target):
    with pytest.raises(fe.FileErasureRefused, match="confirm="):
        fe.erase_path(str(target), confirm="please")
    assert target.read_bytes() == SECRET


def test_missing_env_gate_is_refused(target, monkeypatch):
    monkeypatch.delenv(fe.ALLOW_ENV, raising=False)
    with pytest.raises(fe.FileErasureRefused, match=fe.ALLOW_ENV):
        fe.erase_path(str(target), confirm=fe.CONFIRM_TOKEN)
    assert target.read_bytes() == SECRET


@pytest.mark.parametrize("root", ["/", "/etc", "/usr", "C:\\", "C:\\Windows",
                                  "C:\\Users"])
def test_system_roots_are_refused_even_with_both_gates(root):
    with pytest.raises(fe.FileErasureRefused):
        fe.erase_path(root, recursive=True, confirm=fe.CONFIRM_TOKEN)


def test_the_guard_matches_the_drive_eraser_gate_count():
    """Same discipline, because a recursive file eraser destroys as much."""
    from erasure import engine as drive
    assert fe.CONFIRM_TOKEN == drive.CONFIRM_TOKEN
    assert fe.ALLOW_ENV != drive.ALLOW_ENV        # separate opt-in per capability
    assert fe.REFUSED_ROOTS and drive.REFUSED_PREFIXES


# ═══════════════════════════════════════════════════════ the erasure itself

def test_the_file_is_gone(target):
    _erase(target)
    assert not target.exists()


def test_the_plaintext_is_nowhere_in_the_directory(target, tmp_path):
    _erase(target)
    for leftover in tmp_path.rglob("*"):
        if leftover.is_file():
            assert b"SENSITIVE-EVIDENCE-" not in leftover.read_bytes()


def test_the_original_filename_is_not_left_behind(target, tmp_path):
    _erase(target)
    assert "secret.bin" not in [q.name for q in tmp_path.rglob("*")]


def test_method_recorded_is_clear_never_purge(target):
    r = _erase(target)
    assert r["method_used"] == "Clear"
    assert r["method_used"] != "Purge"
    assert all(t["method_used"] in ("Clear", "NotPerformed") for t in r["targets"])


def test_purge_is_named_as_unreachable_in_the_limitations(target):
    r = _erase(target)
    assert any("Purge is unreachable from userspace" in l for l in r["limitations"])


def test_limitations_are_never_empty_even_on_a_refusal(tmp_path):
    r = _erase(tmp_path / "nope.bin")
    assert r["outcome"] == fe.OUTCOME_NOT_PERFORMED
    assert len(r["limitations"]) >= 4


def test_empty_file_is_handled(tmp_path):
    p = tmp_path / "empty.bin"
    p.write_bytes(b"")
    r = _erase(p)
    assert not p.exists()
    assert r["performed"] == 1


def test_directory_without_recursive_is_refused_and_untouched(tmp_path):
    (tmp_path / "a.bin").write_bytes(SECRET)
    r = _erase(tmp_path)
    assert r["outcome"] == fe.OUTCOME_NOT_PERFORMED
    assert (tmp_path / "a.bin").read_bytes() == SECRET


def test_recursive_erases_every_file_including_subdirectories(tmp_path):
    for name in ("a.bin", "b.bin"):
        (tmp_path / name).write_bytes(SECRET)
    sub = tmp_path / "sub"
    sub.mkdir()
    (sub / "c.bin").write_bytes(SECRET)

    r = _erase(tmp_path, recursive=True)
    assert len(r["targets"]) == 3
    assert r["performed"] == 3
    assert not any(q.is_file() for q in tmp_path.rglob("*"))


def test_multiple_passes_still_verify_against_the_last_one(target):
    r = _erase(target, passes=3)
    assert r["targets"][0]["outcome"] in (fe.OUTCOME_VERIFIED, fe.OUTCOME_UNVERIFIED)
    assert not target.exists()


def test_result_hash_commits_to_the_whole_result(target):
    r = _erase(target)
    h = fe.result_hash(r)
    r["outcome"] = fe.OUTCOME_VERIFIED
    r["method_used"] = "Purge"
    assert fe.result_hash(r) != h


def test_result_hash_uses_the_one_canonical_rule(target):
    from attestation.canonical import result_digest
    r = _erase(target)
    assert fe.result_hash(r) == result_digest(r)


# ══════════════════════════════════════ real filesystem detection on this machine

def test_detect_filesystem_returns_a_real_answer_here(tmp_path):
    """Runs against the actual volume this test is executing on."""
    fs = fe.detect_filesystem(tmp_path)
    assert fs != "unknown", (
        f"filesystem detection failed on {platform.system()}; this downgrades every "
        "outcome to UNVERIFIED, which is honest but means detection is not working")
    if platform.system() == "Windows":
        assert fs in ("ntfs", "fat32", "exfat", "refs")
    elif platform.system() == "Linux":
        assert fs in ("ext4", "ext3", "xfs", "btrfs", "tmpfs", "overlay", "zfs", "f2fs")


def test_detect_filesystem_on_a_nonexistent_path_does_not_raise(tmp_path):
    assert isinstance(fe.detect_filesystem(tmp_path / "no" / "such" / "path"), str)


def test_a_real_erase_on_this_machine_reaches_a_defined_outcome(tmp_path):
    """End to end on the real volume, whatever it is."""
    p = tmp_path / "real.bin"
    p.write_bytes(SECRET)
    r = _erase(p)
    assert r["outcome"] in (fe.OUTCOME_VERIFIED, fe.OUTCOME_PARTIAL,
                            fe.OUTCOME_UNVERIFIED)
    assert r["filesystem"] == fe.detect_filesystem(tmp_path)
    assert not p.exists()
