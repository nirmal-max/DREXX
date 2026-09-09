"""The device write guard. Safety-critical, so it is tested like it.

WHY THIS FILE EXISTS. The guard had a hole exactly where it mattered most: the blocklist
named `/dev/sda`, `/dev/nvme0n1` and `C:\\`, and did not name
`\\\\.\\PhysicalDrive0` -- which on Windows IS the system disk. A confirm token plus one
environment variable would have reached it. Nobody wrote that path down, so nothing
protected it.

The lesson shapes the design: a hand-written blocklist protects only the paths someone
thought of. The gates below are layered so that no single omission is fatal, and two of
them do not depend on anyone's imagination at all.

    1. confirm token          deliberate action, not a stray argument
    2. AKHANDA_ALLOW_DEVICE_WRITE=1   a second, independent switch
    3. REFUSED_PREFIXES       the named-pattern blocklist (necessary, not sufficient)
    4. protected roots        the volume holding the OS or this repository (Windows)
    5. /proc/mounts           the device actually mounted at / or /boot (POSIX)
    6. AKHANDA_TARGET_DEVICE  must equal the target EXACTLY, for any whole disk

Gate 6 is the one that makes a typo harmless. `ALLOW_DEVICE_WRITE=1` plus a mistyped drive
number is a wiped system disk, and the environment variable would have been telling the
truth the whole time.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from erasure.engine import (  # noqa: E402
    ALLOW_ENV, CONFIRM_TOKEN, NAMED_TARGET_ENV, REFUSED_PREFIXES, ErasureRefused,
    _guard, _is_whole_disk, _posix_holds_root, _protected_roots,
)

BS = chr(92)
PHYS0 = BS * 2 + "." + BS + "PhysicalDrive0"
PHYS1 = BS * 2 + "." + BS + "PhysicalDrive1"
CVOL = BS * 2 + "." + BS + "C:"


@pytest.fixture
def both_gates(monkeypatch):
    """Token and environment switch both set: everything below must still refuse."""
    monkeypatch.setenv(ALLOW_ENV, "1")
    monkeypatch.delenv(NAMED_TARGET_ENV, raising=False)


# ───────────────────────────────────────── THE HOLE THAT WAS THERE

def test_windows_physical_drive_zero_is_refused(both_gates):
    """THE REGRESSION. This path matched no prefix in the original blocklist."""
    with pytest.raises(ErasureRefused):
        _guard(PHYS0, CONFIRM_TOKEN)


def test_naming_physical_drive_zero_exactly_still_cannot_authorise_it(monkeypatch):
    """Gate 6 authorises a target; it must not be able to authorise a refused one.

    Otherwise the strongest gate would become a way around the blocklist rather than an
    addition to it.
    """
    monkeypatch.setenv(ALLOW_ENV, "1")
    monkeypatch.setenv(NAMED_TARGET_ENV, PHYS0)
    with pytest.raises(ErasureRefused):
        _guard(PHYS0, CONFIRM_TOKEN)


@pytest.mark.parametrize("target", [PHYS0, CVOL, "C:" + BS, "C:/Windows"])
def test_every_windows_system_path_shape_is_refused(both_gates, target):
    with pytest.raises(ErasureRefused):
        _guard(target, CONFIRM_TOKEN)


def test_a_non_system_physical_drive_is_not_blocklisted(both_gates):
    r"""THE OTHER HALF, and it was broken. Refusing every \.\PhysicalDriveN by prefix
    made the Windows erasure path dead - a legitimate second drive, or a VHD attached for
    testing, could never be a target. A guard that blocks everything is as broken as one
    that blocks nothing.

    PhysicalDrive1 must now fall through the blocklist and be stopped by a gate that is
    ABOUT this run: the named-target requirement, or the device not existing.
    """
    with pytest.raises(ErasureRefused) as exc:
        _guard(PHYS1, CONFIRM_TOKEN)
    message = str(exc.value)
    assert "protected device or system disk pattern" not in message, (
        "PhysicalDrive1 is being refused by the blocklist, which blocks every physical "
        "drive and leaves no legitimate target")
    assert (NAMED_TARGET_ENV in message or "does not exist" in message
            or "backing the volume" in message)


def test_the_system_disk_is_identified_by_asking_windows(monkeypatch):
    """Not guessed from the device name. A striped volume spans more than one disk, which
    a name-based rule cannot express."""
    import erasure.engine as eng
    monkeypatch.setenv(ALLOW_ENV, "1")
    monkeypatch.setenv(NAMED_TARGET_ENV, PHYS1)
    monkeypatch.setattr(eng, "_windows_system_disks", lambda: {1, 3})
    with pytest.raises(ErasureRefused, match="backing the volume"):
        _guard(PHYS1, CONFIRM_TOKEN)


def test_a_failed_system_disk_query_narrows_rather_than_opens(monkeypatch):
    """If Windows will not answer, the named-target gate and the drive-0 blocklist still
    stand. A guard whose failure mode is permissive is not a guard."""
    import erasure.engine as eng
    monkeypatch.setenv(ALLOW_ENV, "1")
    monkeypatch.delenv(NAMED_TARGET_ENV, raising=False)
    monkeypatch.setattr(eng, "_windows_system_disks", lambda: set())
    with pytest.raises(ErasureRefused, match=NAMED_TARGET_ENV):
        _guard(PHYS1, CONFIRM_TOKEN)


def test_forward_slashes_do_not_evade_the_blocklist(both_gates):
    """`C:/` and `C:\\` are the same volume; a guard that only knows one is not a guard."""
    with pytest.raises(ErasureRefused):
        _guard("C:/", CONFIRM_TOKEN)


# ───────────────────────────────────────── POSIX: mounts, not names

def _mounts(monkeypatch, text: str):
    """Point _posix_holds_root at a synthetic /proc/mounts and pretend to be POSIX."""
    import builtins
    import erasure.engine as eng
    real_open = builtins.open

    def fake_open(path, *a, **k):
        if str(path) == "/proc/mounts":
            import io
            return io.StringIO(text)
        return real_open(path, *a, **k)

    monkeypatch.setattr(builtins, "open", fake_open)
    monkeypatch.setattr(eng.os, "name", "posix")


MOUNTS = (
    "/dev/sda2 / ext4 rw,relatime 0 0\n"
    "/dev/sda1 /boot/efi vfat rw 0 0\n"
    "/dev/sdb1 /media/evidence ext4 rw 0 0\n"
)


# ───────────────────────────────────────── the two independent switches

def test_no_token_refuses(monkeypatch):
    monkeypatch.setenv(ALLOW_ENV, "1")
    monkeypatch.setenv(NAMED_TARGET_ENV, "/dev/sdz")
    with pytest.raises(ErasureRefused):
        _guard("/dev/sdz", "")


def test_no_environment_switch_refuses(monkeypatch):
    monkeypatch.delenv(ALLOW_ENV, raising=False)
    monkeypatch.setenv(NAMED_TARGET_ENV, "/dev/sdz")
    with pytest.raises(ErasureRefused):
        _guard("/dev/sdz", CONFIRM_TOKEN)


def test_a_whole_disk_needs_the_named_target(monkeypatch):
    """Reached only on POSIX, so POSIX is what the test pretends to be.

    On Windows a "/dev/..." string resolves onto the current drive and the protected-root
    gate fires first. Still refused, and for a good reason -- but a different one, and a
    test that accepted either would stop proving that gate 6 exists.
    """
    _mounts(monkeypatch, "/dev/nvme0n1p2 / ext4 rw 0 0\n")
    monkeypatch.setenv(ALLOW_ENV, "1")
    monkeypatch.delenv(NAMED_TARGET_ENV, raising=False)
    with pytest.raises(ErasureRefused, match=NAMED_TARGET_ENV):
        _guard("/dev/sdz", CONFIRM_TOKEN)


def test_a_typo_reaches_nothing(monkeypatch):
    """Authorise sdz, type sdy. The whole reason gate 6 names a path and not a boolean."""
    monkeypatch.setenv(ALLOW_ENV, "1")
    monkeypatch.setenv(NAMED_TARGET_ENV, "/dev/sdz")
    with pytest.raises(ErasureRefused):
        _guard("/dev/sdy", CONFIRM_TOKEN)


def test_posix_refuses_the_device_holding_root(monkeypatch):
    _mounts(monkeypatch, MOUNTS)
    assert _posix_holds_root("/dev/sda2")
    assert "mounted at /" in _posix_holds_root("/dev/sda2")


def test_posix_refuses_the_whole_disk_behind_root(monkeypatch):
    """Wiping /dev/sda destroys /dev/sda2 mounted at / just as surely."""
    _mounts(monkeypatch, MOUNTS)
    assert _posix_holds_root("/dev/sda")


def test_posix_PERMITS_the_evidence_drive(monkeypatch):
    """THE OTHER HALF. A guard that refuses everything is as broken as one that refuses
    nothing, and would be discovered on Linux at the demo with a drive plugged in."""
    _mounts(monkeypatch, MOUNTS)
    assert _posix_holds_root("/dev/sdb") == ""
    assert _posix_holds_root("/dev/sdc") == ""


def test_posix_permits_sda_when_sda_is_not_the_running_system(monkeypatch):
    """On a forensic workstation the evidence drive may well BE /dev/sda. A name-based
    blocklist cannot tell that apart from the boot disk; /proc/mounts can."""
    _mounts(monkeypatch, "/dev/nvme0n1p2 / ext4 rw 0 0\n/dev/sda1 /media/ev ext4 rw 0 0\n")
    assert _posix_holds_root("/dev/sda") == ""
    assert _posix_holds_root("/dev/nvme0n1")


def test_protected_roots_is_empty_on_posix(monkeypatch):
    """The bug this encodes: on POSIX every absolute path has the anchor "/", so comparing
    anchors refused every target including the USB stick the guard exists to permit."""
    import erasure.engine as eng
    monkeypatch.setattr(eng.os, "name", "posix")
    assert _protected_roots() == []


def test_a_missing_proc_mounts_does_not_crash(monkeypatch):
    import builtins
    import erasure.engine as eng
    monkeypatch.setattr(eng.os, "name", "posix")

    def boom(path, *a, **k):
        raise OSError("no /proc here")

    monkeypatch.setattr(builtins, "open", boom)
    assert _posix_holds_root("/dev/sdb") == ""      # reports nothing, refuses nothing


# ───────────────────────────────────────── classification

@pytest.mark.parametrize("t", [PHYS0, "/dev/sda", "/dev/nvme0n1", "/dev/mmcblk0",
                               "/dev/disk2", "/dev/loop0"])
def test_whole_disk_paths_are_recognised(t):
    assert _is_whole_disk(t)


@pytest.mark.parametrize("t", ["evidence.img", "/home/x/disk.img", "D:" + BS + "img.dd"])
def test_file_images_are_not_whole_disks(t):
    assert not _is_whole_disk(t)


def test_a_file_image_needs_no_gates_at_all(tmp_path, monkeypatch):
    """Development must stay frictionless, or the gates get disabled wholesale.

    "Must not raise" alone is not an assertion, the adversarial audit flagged exactly this
    shape once already. So the CONTRAST is asserted too: the same empty arguments that sail
    past for a file are refused for a device path, which proves the file branch is what let
    it through rather than the gates simply being off.
    """
    img = tmp_path / "x.img"
    img.write_bytes(b"\x00" * 1024)
    monkeypatch.delenv(ALLOW_ENV, raising=False)
    monkeypatch.delenv(NAMED_TARGET_ENV, raising=False)

    _guard(str(img), "")            # no token, no environment, no named target
    assert img.read_bytes() == b"\x00" * 1024, "the guard must not touch its target"

    with pytest.raises(ErasureRefused):
        _guard("/dev/sdz", "")      # identical arguments, not a file -> refused


def test_the_blocklist_still_names_the_obvious_ones():
    """Necessary but not sufficient -- kept, and kept honest about which it is."""
    joined = " ".join(REFUSED_PREFIXES).lower()
    assert "physicaldrive" in joined
    assert "/dev/sda" in joined
    assert "c:" in joined
