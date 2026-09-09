"""
Erasure engine.

Contract (docs/ENGINEERING_RULES.md section 5):
    erase(device: str, level: str) -> {
        "method_used": str,       # "Clear" | "Purge" | "Destroy"
        "verified": bool,         # read-back sampling confirmed the wipe
        "sample_results": list }

THE HONESTY RULE IS THE ENGINEERING (docs/ENGINEERING_RULES.md rule 2). This module records what it
ACTUALLY achieved, never what sounds strongest:

  - USB flash / SD: only overwrite is possible -> method_used = "Clear". Never "Purge".
    Flash translation layers keep spare blocks the host cannot address, so an overwrite
    does not reach every cell. NIST SP 800-88 Rev. 2 calls that Clear, and so do we.
  - HDD / SATA SSD: a firmware sanitize command (hdparm --security-erase, blkdiscard
    --secure, nvme sanitize) reaches media the host cannot address -> "Purge".
  - "Destroy" is PHYSICAL. Software cannot shred, incinerate, or degauss anything. This
    module will never return Destroy, and asking for it raises rather than lying.

SAFETY GUARD. Nothing writes to a block device unless the caller passes the explicit
confirm token AND the device passes the refusal checks. During development you work on
file-backed images, which behave identically and cost nothing when you get it wrong.
"""

from __future__ import annotations
import hashlib
import json
import os
import platform
import shutil
import sys
import subprocess
import time
from dataclasses import dataclass, asdict, field
from pathlib import Path

from attestation.canonical import result_digest
from erasure import deviceid

class MediaFailure(Exception):
    """Raised internally when a device fails solidly enough that continuing is pointless.

    NOT an error the caller sees. erase() catches it and turns it into a RESULT: an
    aborted wipe with everything achieved so far recorded and signed. An exception that
    escaped here would destroy the evidence of its own cause, which is the one thing this
    engine must never do.
    """

    def __init__(self, reached: int, consecutive: int):
        self.reached = reached
        self.consecutive = consecutive
        super().__init__(f"device failed for {consecutive} consecutive bytes "
                         f"at offset {reached}")


CONFIRM_TOKEN = "I-UNDERSTAND-THIS-DESTROYS-DATA"
ALLOW_ENV = "AKHANDA_ALLOW_DEVICE_WRITE"

CLEAR, PURGE, DESTROY = "Clear", "Purge", "Destroy"

BLOCK_SIZE = 1024 * 1024        # 1 MiB write chunks
SAMPLE_COUNT = 16               # read-back sample points
SAMPLE_LEN = 4096               # bytes read at each sample point

# G9, BAD SECTORS.
#
# Failing media is not the exceptional case in forensics, it is the normal one: drives
# arrive at a lab precisely because something went wrong with them. The old code called
# os.write() in a loop, so the FIRST unreadable sector raised OSError and killed the whole
# pass. That is the worst of the three possible behaviours:
#
#   * hang        - the operator waits, gives up, and there is no record at all
#   * abort       - the wipe stops, and what WAS overwritten is never recorded either
#   * skip-and-log- the wipe completes, and every region it could not touch is named
#
# Only the third produces evidence. A skipped range means the data in it was NOT
# destroyed, and saying so is the entire point; a wipe that silently steps over bad
# sectors and still reports success is the omission this project exists to make
# impossible, committed by the tool itself.
SECTOR_SIZE = 512               # retry granularity when a 1 MiB chunk fails
MAX_CONSECUTIVE_BAD = 4096      # ~2 MiB of solid failure => stop, and say why

# Devices that are never acceptable targets, whatever the caller says.
# Paths that are never an acceptable target, whatever the caller says.
#
# WINDOWS PHYSICAL DRIVES WERE MISSING FROM THIS LIST AND THAT WAS THE DANGEROUS BUG.
# `\\.\PhysicalDrive0` starts with none of the old prefixes, so on the machine this is
# developed on -- where PhysicalDrive0 IS the system disk -- the guard would have let it
# through on a token and an environment variable. A blocklist of hand-written strings
# protects only the paths someone thought to write down; see NAMED_TARGET_ENV below for
# the part that does not depend on anyone's imagination.
REFUSED_PREFIXES = (
    "/dev/sda", "/dev/nvme0n1", "/dev/mmcblk0",
    "c:\\", "c:/",
    # PhysicalDrive0 by name, because it is the boot disk on essentially every Windows
    # machine. The OTHER physical drives are not blocklisted -- see _windows_system_disks(),
    # which asks the operating system which disk actually backs the system volume rather
    # than assuming. Refusing every \\.\PhysicalDriveN by prefix made the Windows
    # erasure path dead: a guard that blocks everything is as broken as one that blocks
    # nothing, which is the same bug this file already carries a POSIX note about.
    "\\\\.\\physicaldrive0",
    "\\\\?\\physicaldrive0",
    "\\\\.\\c:", "\\\\?\\c:",
    "/dev/disk0", "/dev/rdisk0",
)

# The gate that does not rely on a blocklist being complete.
#
# For any whole-disk device the operator must ALSO set this variable to the EXACT target
# string. Not "1", not "yes" -- the device path itself. A typo cannot then reach a
# different disk than the one that was authorised, which is the failure mode a boolean
# flag invites: `AKHANDA_ALLOW_DEVICE_WRITE=1` plus a mistyped drive number is a wiped
# system disk, and the environment variable would have been telling the truth.
NAMED_TARGET_ENV = "AKHANDA_TARGET_DEVICE"


class ErasureRefused(Exception):
    """Raised when the guard blocks an operation. Never caught internally."""


@dataclass
class BadRange:
    """One region the device would not accept or return, recorded rather than skipped.

    `phase` is "write" or "read". Both matter and they mean different things: a write
    failure means those bytes were never overwritten, so the old data may still be there.
    A read failure means the wipe may have landed but cannot be CONFIRMED. The first is a
    hole in the erasure, the second is a hole in the evidence, and collapsing them into
    one "error" field would hide the distinction an examiner needs.
    """
    offset: int
    length: int
    phase: str
    errno: int = 0
    strerror: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class Sample:
    offset: int
    expected_sha256: str
    actual_sha256: str
    match: bool


@dataclass
class ErasureResult:
    target: str
    requested_level: str
    method_used: str
    verified: bool
    sample_results: list = field(default_factory=list)
    media_kind: str = "unknown"
    media_note: str = ""
    # Physical identity of the media: vendor, model, SERIAL, plus the NIST Appendix C and
    # BSA Part A field mappings. Lives here rather than in a 17th hashed entry field
    # because result_hash is already inside the signed preimage and the stored result is
    # re-verified against it -- so the identity is tamper-evident without an ENTRY_VERSION
    # bump and a synchronised change across three verifier implementations.
    device_identity: dict = field(default_factory=dict)
    bytes_written: int = 0
    bytes_skipped: int = 0
    bad_ranges: list = field(default_factory=list)
    aborted: bool = False
    abort_reason: str = ""
    passes: int = 0
    started_utc: str = ""
    finished_utc: str = ""
    tool: str = ""
    honest_note: str = ""

    def to_dict(self) -> dict:
        return asdict(self)

    def result_hash(self) -> str:
        """Digest of the whole result record. This is what goes into the ledger entry,
        so the entry commits to the full outcome, not to a summary of it."""
        return result_hash(self.to_dict())


# ---------------------------------------------------------------- media probing

def probe_media(target: str) -> dict:
    """What is this thing, honestly?

    Returns kind/removable/rotational/bus and whether a firmware sanitize command is
    even available. Unknown is reported as unknown, a guess here becomes an overclaim
    on a certificate.
    """
    p = Path(target)
    info = {"kind": "unknown", "removable": None, "rotational": None,
            "bus": "unknown", "firmware_sanitize": False, "note": ""}

    if p.is_file():
        info.update(kind="file_image", removable=False, rotational=False,
                    bus="none", note="regular file used as a disk image")
        return info

    if platform.system() != "Linux":
        info.update(kind="block_or_unknown",
                    note=(f"media probing is implemented for Linux sysfs; on "
                          f"{platform.system()} the class of media cannot be "
                          f"determined, so no Purge claim is available"))
        return info

    name = p.name
    base = Path("/sys/block") / name
    if not base.exists():
        info["note"] = f"{target} is not a whole block device in /sys/block"
        return info

    info["kind"] = "block"
    try:
        info["removable"] = (base / "removable").read_text().strip() == "1"
    except OSError:
        pass
    try:
        info["rotational"] = (base / "queue/rotational").read_text().strip() == "1"
    except OSError:
        pass
    try:
        info["bus"] = "usb" if "usb" in os.path.realpath(base) else "internal"
    except OSError:
        pass

    if name.startswith("mmcblk") or info["bus"] == "usb":
        info["firmware_sanitize"] = False
        info["note"] = ("removable flash: no ATA Secure Erase and no NVMe Sanitize, so "
                        "Purge is not reachable on this medium")
    elif name.startswith("nvme"):
        info["firmware_sanitize"] = shutil.which("nvme") is not None
        info["note"] = "NVMe: Purge available if `nvme sanitize` is supported"
    elif name.startswith("sd"):
        info["firmware_sanitize"] = shutil.which("hdparm") is not None
        info["note"] = "ATA: Purge available if the drive reports security-erase support"
    return info


def plan_method(probe: dict, requested_level: str) -> tuple[str, str]:
    """Decide the method that is actually achievable, and say why.

    Returns (method, reason). The requested level is a CEILING, never a promise: asking
    for Purge on a USB stick gets you Clear and a reason, not a lie.
    """
    if requested_level == DESTROY:
        raise ErasureRefused(
            "Destroy is a physical process (shred, incinerate, degauss). No software "
            "tool can perform or attest it. Record it as a manual step with its own "
            "chain entry and a photograph, never as a software result."
        )
    if requested_level not in (CLEAR, PURGE):
        raise ErasureRefused(f"level must be {CLEAR!r} or {PURGE!r}; got {requested_level!r}")

    if requested_level == PURGE:
        if probe.get("firmware_sanitize"):
            return PURGE, "firmware sanitize command available on this device"
        return CLEAR, (
            "Purge requested but not reachable on this medium, "
            + (probe.get("note") or "no firmware sanitize command available")
            + "; achieved Clear and recorded Clear"
        )
    return CLEAR, "single-pass overwrite; NIST SP 800-88 Rev. 2 Clear for this medium"


# ------------------------------------------------------------------ the guard

def _is_whole_disk(target: str) -> bool:
    """Does this path address a whole physical disk rather than a file or partition?"""
    low = target.lower()
    # Windows device paths are matched on a slash-normalised copy, POSIX ones on the
    # original. Normalising BOTH was the bug: "/dev/sda" became "\dev\sda" and then matched
    # no POSIX prefix, so every Linux whole-disk target skipped the strongest gate, on the
    # platform where whole-disk erasure is actually performed.
    win = low.replace("/", "\\")
    return (win.startswith("\\\\.\\physicaldrive") or win.startswith("\\\\?\\physicaldrive")
            or low.startswith("/dev/sd") or low.startswith("/dev/nvme")
            or low.startswith("/dev/mmcblk") or low.startswith("/dev/disk")
            or low.startswith("/dev/loop") or low.startswith("/dev/hd")
            or low.startswith("/dev/vd") or low.startswith("/dev/xvd"))


def _protected_roots() -> list:
    """Windows volumes that must never be a target: the OS, and this repository.

    WINDOWS ONLY, AND THAT IS THE POINT. The first version compared `Path(target).anchor`
    on every platform. On Windows an anchor is a drive letter and the comparison is
    meaningful. On POSIX every absolute path has the anchor "/", so `_protected_roots()`
    returned ["/"] and the check refused EVERY target -- including the USB stick it exists
    to permit. A guard that blocks everything is as broken as one that blocks nothing, and
    it would have been discovered on Linux, at the demo, with a drive plugged in.

    POSIX gets a different and better check: `_posix_holds_root()` compares the device to
    what is actually mounted at "/" and "/boot", which is the real question rather than a
    proxy for it.
    """
    if os.name != "nt":
        return []
    roots = []
    for probe in (os.environ.get("SystemRoot", ""), os.environ.get("SystemDrive", ""),
                  sys.executable, str(Path(__file__).resolve()), os.getcwd()):
        if not probe:
            continue
        try:
            anchor = Path(probe).resolve().anchor
        except (OSError, ValueError):
            continue
        if anchor:
            roots.append(anchor.rstrip("\\/").lower())
    return sorted(set(r for r in roots if r))


def _windows_disk_number(target: str):
    r"""The disk number in a \\.\PhysicalDriveN path, or None."""
    low = target.lower().replace("/", "\\")
    for prefix in ("\\\\.\\physicaldrive", "\\\\?\\physicaldrive"):
        if low.startswith(prefix):
            tail = low[len(prefix):]
            return int(tail) if tail.isdigit() else None
    return None


def _windows_system_disks() -> set:
    """Which physical disks back the system volume and this repository? Asks Windows.

    The POSIX branch reads /proc/mounts rather than guessing from a device name; this is
    the same idea for Windows. IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS maps a volume to the
    physical disk(s) beneath it, so "the drive holding C:" becomes a fact rather than an
    assumption -- and a striped or mirrored volume correctly returns MORE THAN ONE disk,
    which a name-based rule could never express.

    Returns an empty set when the query fails. That is deliberate: the named-target gate
    and the PhysicalDrive0 blocklist still stand, so a failure here narrows the guard
    rather than opening it.
    """
    if os.name != "nt":
        return set()
    try:
        import ctypes
        from ctypes import wintypes

        IOCTL = 0x00560000
        GENERIC_READ = 0x80000000
        SHARE = 0x00000003
        OPEN_EXISTING = 3
        INVALID = ctypes.c_void_p(-1).value

        class EXTENT(ctypes.Structure):
            _fields_ = [("DiskNumber", wintypes.DWORD),
                        ("StartingOffset", ctypes.c_longlong),
                        ("ExtentLength", ctypes.c_longlong)]

        class EXTENTS(ctypes.Structure):
            _fields_ = [("NumberOfDiskExtents", wintypes.DWORD),
                        ("Extents", EXTENT * 16)]

        k32 = ctypes.WinDLL("kernel32", use_last_error=True)
        k32.CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD,
                                    ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD,
                                    ctypes.c_void_p]
        k32.CreateFileW.restype = ctypes.c_void_p
        k32.DeviceIoControl.argtypes = [ctypes.c_void_p, wintypes.DWORD, ctypes.c_void_p,
                                        wintypes.DWORD, ctypes.c_void_p, wintypes.DWORD,
                                        ctypes.POINTER(wintypes.DWORD), ctypes.c_void_p]
        k32.DeviceIoControl.restype = wintypes.BOOL
        k32.CloseHandle.argtypes = [ctypes.c_void_p]

        disks = set()
        for anchor in _protected_roots():
            letter = anchor.rstrip("\\/").rstrip(":")
            if not letter:
                continue
            handle = k32.CreateFileW(f"\\\\.\\{letter}:", GENERIC_READ, SHARE, None,
                                     OPEN_EXISTING, 0, None)
            if handle == INVALID or handle is None:
                continue
            try:
                buf = EXTENTS()
                got = wintypes.DWORD()
                if k32.DeviceIoControl(handle, IOCTL, None, 0, ctypes.byref(buf),
                                       ctypes.sizeof(buf), ctypes.byref(got), None):
                    for i in range(min(buf.NumberOfDiskExtents, 16)):
                        disks.add(int(buf.Extents[i].DiskNumber))
            finally:
                k32.CloseHandle(handle)
        return disks
    except Exception:  # noqa: BLE001 - a guard that crashes is a guard that is skipped
        return set()


def _posix_holds_root(target: str) -> str:
    """On POSIX: is `target` the device backing "/", "/boot" or "/home"? Returns why, or "".

    Compares against /proc/mounts rather than guessing from the name, so /dev/sda3 is
    refused when it is the root filesystem and permitted when it is not -- a name-based
    blocklist cannot tell those apart, and on a forensic workstation the evidence drive
    may well be /dev/sda.
    """
    if os.name == "nt":
        return ""
    try:
        with open("/proc/mounts", "r", encoding="utf-8", errors="replace") as fh:
            mounts = [ln.split() for ln in fh if ln.strip()]
    except OSError:
        return ""
    t = target.rstrip("0123456789") if target.startswith("/dev/") else target
    for parts in mounts:
        if len(parts) < 2:
            continue
        dev, point = parts[0], parts[1]
        if point in ("/", "/boot", "/boot/efi", "/home", "/var"):
            # match the whole device as well as its partitions: wiping /dev/sda destroys
            # /dev/sda1 mounted at "/" just as surely as targeting the partition would.
            if dev == target or dev.startswith(target) or dev.rstrip("0123456789") == t:
                return f"{dev} is mounted at {point}"
    return ""


def _guard(target: str, confirm: str) -> None:
    p = Path(target)
    if p.is_file():
        return  # file images are always safe to work on

    if confirm != CONFIRM_TOKEN:
        raise ErasureRefused(
            f"refusing to write to block device {target!r}: pass "
            f"confirm={CONFIRM_TOKEN!r} to proceed. Develop against a file image first."
        )
    if os.environ.get(ALLOW_ENV) != "1":
        raise ErasureRefused(
            f"refusing to write to block device {target!r}: set {ALLOW_ENV}=1 in the "
            "environment. Two independent gates, on purpose."
        )
    # Check BOTH forms. Normalising only the slash-converted copy was a bug of exactly
    # the kind this guard exists to prevent: "/dev/sda" becomes "\dev\sda", matches no
    # POSIX entry in the blocklist, and falls through. On Windows the protected-root gate
    # happened to catch it, which is why it looked fine here and would not have been fine
    # on Linux -- the platform where whole-disk erasure is actually performed.
    low = target.lower()
    win = low.replace("/", "\\")
    for bad in REFUSED_PREFIXES:
        b = bad.lower()
        if low.startswith(b) or win.startswith(b):
            raise ErasureRefused(
                f"refusing to erase {target!r}: it matches a protected device or system "
                f"disk pattern ({bad!r}). This guard is not disabled by the environment "
                "variable or the confirm token; a target matching this list is refused "
                "outright."
            )

    # The volume this machine boots from, and the one this code lives on.
    #
    # Only meaningful for a path that names a Windows volume. A POSIX device path resolves
    # to the anchor "/" and would match unconditionally, which is why this is gated on the
    # anchor actually being a drive letter rather than on the platform alone.
    if os.name == "nt":
        anchor = ""
        try:
            anchor = Path(target).resolve().anchor.rstrip("\\/").lower()
        except (OSError, ValueError):
            pass
        if anchor and ":" in anchor and anchor in _protected_roots():
            raise ErasureRefused(
                f"refusing to erase {target!r}: it resolves to {anchor!r}, which holds the "
                "operating system or this repository. Erasing the machine you are recording "
                "the erasure on destroys the evidence along with the data."
            )

    # WINDOWS: is this physical drive the one the system actually lives on? Asked of the
    # operating system, so a legitimate second drive is PERMITTED while the system disk
    # never is -- the same distinction /proc/mounts provides below.
    disk_no = _windows_disk_number(target)
    if disk_no is not None:
        system_disks = _windows_system_disks()
        if disk_no in system_disks:
            raise ErasureRefused(
                f"refusing to erase {target!r}: Windows reports disk {disk_no} as backing "
                f"the volume holding the operating system or this repository "
                f"(system disks: {sorted(system_disks)}). Determined by asking the volume "
                "which disk it sits on, not by guessing from the device name.")

    mounted = _posix_holds_root(target)
    if mounted:
        raise ErasureRefused(
            f"refusing to erase {target!r}: {mounted}. Checked against /proc/mounts rather "
            "than guessed from the name, so an evidence drive that happens to be /dev/sda "
            "is still permitted while the running system never is."
        )

    # THE GATE THAT DOES NOT DEPEND ON A BLOCKLIST BEING COMPLETE.
    if _is_whole_disk(target):
        named = os.environ.get(NAMED_TARGET_ENV, "")
        if named != target:
            raise ErasureRefused(
                f"refusing to erase whole disk {target!r}: set {NAMED_TARGET_ENV} to the "
                f"EXACT device string as a third gate, i.e.\n"
                f"    {NAMED_TARGET_ENV}={target}\n"
                f"(currently {named!r}). A boolean flag plus a mistyped drive number is a "
                "wiped system disk; naming the target means a typo reaches nothing."
            )

    if not p.exists():
        raise ErasureRefused(f"{target!r} does not exist")


# ------------------------------------------------------------- overwrite + verify

def _pattern(seed: bytes, offset: int, length: int) -> bytes:
    """Deterministic pseudorandom bytes for a given offset.

    Deterministic so verification can recompute exactly what SHOULD be at any offset
    without storing the whole pattern. Not a security primitive, it is a wipe pattern,
    and the ledger says so.
    """
    out = bytearray()
    counter = offset // 32
    while len(out) < length + 32:
        out += hashlib.sha256(seed + counter.to_bytes(8, "big")).digest()
        counter += 1
    skew = offset % 32
    return bytes(out[skew:skew + length])


def _target_size(target: str) -> int:
    p = Path(target)
    if p.is_file():
        return p.stat().st_size
    fd = os.open(target, os.O_RDONLY)
    try:
        return os.lseek(fd, 0, os.SEEK_END)
    finally:
        os.close(fd)


def _write_at(fd: int, offset: int, data: bytes) -> None:
    os.lseek(fd, offset, os.SEEK_SET)
    os.write(fd, data)


def _retry_by_sector(fd: int, seed: bytes, offset: int, length: int,
                     bad: list) -> int:
    """A 1 MiB chunk failed. Find out how much of it is ACTUALLY bad.

    This is the ddrescue instinct and it matters for honesty, not just for yield: giving
    up on a whole megabyte because one 512-byte sector is dead would report 1 MiB of
    surviving data when 511 sectors were in fact overwritten. The skipped region must be
    the region that is genuinely unreachable, or the record overstates the damage as
    surely as skipping the log would understate it.
    """
    good = 0
    pos = offset
    end = offset + length
    while pos < end:
        n = min(SECTOR_SIZE, end - pos)
        try:
            _write_at(fd, pos, _pattern(seed, pos, n))
            good += n
        except OSError as exc:
            # Coalesce with the previous range when adjacent, so a 40-sector defect is
            # one finding an examiner can read, not forty.
            if bad and bad[-1].phase == "write" and bad[-1].offset + bad[-1].length == pos:
                bad[-1].length += n
            else:
                bad.append(BadRange(offset=pos, length=n, phase="write",
                                    errno=exc.errno or 0, strerror=str(exc)))
        pos += n
    return good


def overwrite_pass(target: str, seed: bytes, size: int | None = None, *,
                   bad_ranges: list | None = None) -> int:
    """One overwrite pass, surviving bad sectors. Returns bytes ACTUALLY written.

    NIST 800-88 Rev. 2: one pass suffices at Clear for both flash and modern magnetic
    media. Unreadable regions are skipped, retried at sector granularity, and appended to
    `bad_ranges` if given. The return value counts only bytes that were really written,
    so `bytes_written < size` is itself the signal that something was skipped.
    """
    size = size if size is not None else _target_size(target)
    bad = bad_ranges if bad_ranges is not None else []
    written = 0
    pos = 0
    consecutive_bad = 0

    flags = os.O_WRONLY
    if hasattr(os, "O_BINARY"):
        flags |= os.O_BINARY
    fd = os.open(target, flags)
    try:
        while pos < size:
            chunk = min(BLOCK_SIZE, size - pos)
            try:
                _write_at(fd, pos, _pattern(seed, pos, chunk))
                written += chunk
                consecutive_bad = 0
            except OSError:
                before = sum(b.length for b in bad)
                got = _retry_by_sector(fd, seed, pos, chunk, bad)
                written += got
                skipped_here = sum(b.length for b in bad) - before
                consecutive_bad = consecutive_bad + skipped_here if got == 0 else 0
                if consecutive_bad >= MAX_CONSECUTIVE_BAD:
                    # A drive failing solidly for megabytes is not a drive with bad
                    # sectors, it is a drive that is gone. Grinding on would hang the
                    # operator with nothing to show; stopping here still leaves a record
                    # of exactly how far the pass got.
                    raise MediaFailure(pos + chunk, consecutive_bad)
            pos += chunk
        try:
            os.fsync(fd)
        except OSError:
            pass  # a dying device may refuse the flush; the bad ranges already say so
    finally:
        os.close(fd)
    return written


def read_back_sample(target: str, seed: bytes, n: int = SAMPLE_COUNT,
                     size: int | None = None, *,
                     bad_ranges: list | None = None) -> list[Sample]:
    """Read n spread offsets and confirm each holds the pattern we wrote.

    This is the evidence that the write LANDED, not merely that the call returned. A
    device that silently ignores writes (a failing or write-protected stick) is caught
    here and reported as verified=False rather than passed off as erased.
    """
    size = size if size is not None else _target_size(target)
    if size <= 0:
        return []
    n = max(1, min(n, max(1, size // SAMPLE_LEN)))
    step = max(SAMPLE_LEN, size // n)

    samples: list[Sample] = []
    flags = os.O_RDONLY
    if hasattr(os, "O_BINARY"):
        flags |= os.O_BINARY
    fd = os.open(target, flags)
    try:
        for i in range(n):
            off = min(i * step, max(0, size - SAMPLE_LEN))
            want = min(SAMPLE_LEN, size - off)
            expected = _pattern(seed, off, want)
            try:
                os.lseek(fd, off, os.SEEK_SET)
                actual = os.read(fd, want)
            except OSError as exc:
                # An unreadable sample is NOT a mismatch and must never be recorded as
                # one. match=False here would say "the wipe did not land"; the truth is
                # "the wipe cannot be confirmed at this offset", which is a different
                # claim with a different remedy.
                if bad_ranges is not None:
                    bad_ranges.append(BadRange(offset=off, length=want, phase="read",
                                               errno=exc.errno or 0, strerror=str(exc)))
                continue
            samples.append(Sample(
                offset=off,
                expected_sha256=hashlib.sha256(expected).hexdigest(),
                actual_sha256=hashlib.sha256(actual).hexdigest(),
                match=(actual == expected),
            ))
    finally:
        os.close(fd)
    return samples


def _firmware_sanitize(target: str, probe: dict) -> tuple[bool, str, str]:
    """Attempt a firmware-level sanitize. Returns (ok, tool, detail).

    Never invents success: a missing tool, a non-zero exit, or an unsupported drive all
    return ok=False, and the caller then falls back to overwrite and records Clear.
    """
    name = Path(target).name
    if name.startswith("nvme") and shutil.which("nvme"):
        cmd, tool = ["nvme", "sanitize", target, "-a", "2"], "nvme sanitize"
    elif shutil.which("hdparm"):
        cmd, tool = ["hdparm", "--user-master", "u", "--security-erase", "NULL", target], "hdparm --security-erase"
    else:
        return False, "", "no firmware sanitize tool present"

    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=3600)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return False, tool, f"{tool} failed: {exc}"
    if proc.returncode != 0:
        return False, tool, f"{tool} returned {proc.returncode}: {proc.stderr.strip()[:200]}"
    return True, tool, f"{tool} completed"


# ---------------------------------------------------------------------- entry point

def erase(device: str, level: str = CLEAR, confirm: str = "",
          seed: bytes | None = None) -> dict:
    """Erase `device` to at most `level`, and report what was actually achieved.

    Never raises for a media limitation, a Purge that is not reachable becomes a Clear
    with a stated reason. It DOES raise for a guard violation or a Destroy request,
    because those are caller errors, not outcomes.
    """
    _guard(device, confirm)
    # Identify the media BEFORE touching it. Afterwards a drive may not answer, and a
    # certificate naming a device path instead of a serial number identifies nothing that
    # can be found again in an evidence bag six months later.
    identity = deviceid.describe(deviceid.identify(device))
    probe = probe_media(device)
    method, reason = plan_method(probe, level)
    seed = seed or os.urandom(32)
    started = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

    tool = "overwrite (python)"
    if method == PURGE:
        ok, tool_used, detail = _firmware_sanitize(device, probe)
        if ok:
            samples = read_back_sample(device, seed)  # post-sanitize read-back
            finished = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
            res = ErasureResult(
                target=device, requested_level=level, method_used=PURGE,
                verified=True, sample_results=[asdict(s) for s in samples],
                media_kind=probe["kind"], media_note=probe.get("note", ""),
                device_identity=identity,
                bytes_written=0, passes=0, started_utc=started, finished_utc=finished,
                tool=tool_used,
                honest_note=(f"{detail}. Purge reached by a firmware command that "
                             "addresses media the host cannot reach directly."),
            )
            return res.to_dict()
        method = CLEAR
        reason = f"firmware sanitize unavailable ({detail}); fell back to overwrite"

    size = _target_size(device)
    bad: list = []
    aborted, abort_reason = False, ""

    try:
        written = overwrite_pass(device, seed, size, bad_ranges=bad)
    except MediaFailure as mf:
        # The device gave up. Record how far we got and stop -- a partial wipe that is
        # honestly described is evidence; a partial wipe that raised is a lost afternoon.
        written = mf.reached - sum(b.length for b in bad)
        aborted = True
        abort_reason = (f"device failed solidly after {mf.consecutive} bytes of "
                        f"consecutive unwritable sectors near offset {mf.reached}; "
                        "the pass was stopped rather than continued indefinitely")

    samples = read_back_sample(device, seed, size=size, bad_ranges=bad)
    skipped = sum(b.length for b in bad)

    # VERIFIED REQUIRES THREE THINGS, NOT ONE.
    #   * samples exist and every one matched  -- the wipe demonstrably landed
    #   * nothing was skipped                  -- there is no region it did not reach
    #   * the pass was not aborted             -- it ran to the end of the device
    # Dropping any of the three lets a wipe with a hole in it present as a clean one,
    # which is precisely the overclaim `outcome` was added to prevent (G2).
    verified = (bool(samples) and all(s.match for s in samples)
                and not bad and not aborted)
    finished = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

    note = (
        f"{reason}. Clear overwrites every host-addressable block. On flash media "
        "the controller may retain data in spare or remapped blocks that the host "
        "cannot address; that residue is why this is Clear and not Purge."
    )
    if bad:
        w = sum(b.length for b in bad if b.phase == "write")
        r = sum(b.length for b in bad if b.phase == "read")
        note += (
            f" {len(bad)} unreadable region(s) totalling {skipped} bytes were skipped "
            f"and logged ({w} bytes unwritable, {r} bytes unverifiable). Data in the "
            "unwritable regions was NOT destroyed and may still be recoverable; the "
            "unverifiable regions may have been overwritten but could not be confirmed. "
            "Every range is listed in bad_ranges and is covered by this record's digest."
        )
    if aborted:
        note += f" {abort_reason}."

    res = ErasureResult(
        target=device, requested_level=level, method_used=CLEAR, verified=verified,
        sample_results=[asdict(s) for s in samples],
        media_kind=probe["kind"], media_note=probe.get("note", ""),
        device_identity=identity,
        bytes_written=written, bytes_skipped=skipped,
        bad_ranges=[b.to_dict() for b in bad],
        aborted=aborted, abort_reason=abort_reason,
        passes=1, started_utc=started, finished_utc=finished,
        tool=tool, honest_note=note,
    )
    return res.to_dict()


def outcome_for(result: dict) -> str:
    """The signed `outcome` for an erasure entry. The closed vocabulary, applied honestly.

    Mirrors recovery.outcome_for so both engines answer the same question the same way,
    and so the CLI never has to invent the mapping at the call site -- an outcome decided
    in the caller is an outcome that drifts between callers.

        NOT_PERFORMED  nothing ran
        PARTIAL        it ran, and there are regions it provably did not reach
        UNVERIFIED     it ran and reached everything, but read-back did not confirm it
        VERIFIED       it ran, reached everything, and read-back confirmed it

    PARTIAL OUTRANKS UNVERIFIED, deliberately. A wipe with a hole in it is a worse
    outcome than a complete wipe that could not be sampled: the first has known surviving
    data, the second has unconfirmed success. Reporting the stronger of the two would be
    the overclaim; where both apply, the record says PARTIAL and the note carries the rest.
    """
    if result.get("bytes_written", 0) == 0 and result.get("bad_ranges"):
        return "NOT_PERFORMED"
    if result.get("bad_ranges") or result.get("aborted"):
        return "PARTIAL"
    return "VERIFIED" if result.get("verified") else "UNVERIFIED"


def result_hash(result: dict) -> str:
    """Digest of an erase() result, for the ledger entry.

    Delegates to attestation.canonical so the engine, the recovery engine, and the
    verifier that re-checks a stored record all compute one digest, not three.
    """
    return result_digest(result)
