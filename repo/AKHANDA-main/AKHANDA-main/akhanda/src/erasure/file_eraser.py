"""
Secure File and Folder Eraser, problem statement SIH26149, module (b).

ORDERING IS A CORRECTNESS MATTER, not a style choice:

  overwrite -> verify -> rename -> truncate -> unlink

1. Overwrite BEFORE unlink. Once a file is unlinked the filesystem may reallocate its
   blocks immediately; writing afterwards scribbles on whatever now owns them and never
   touches the original data.
2. Verify BEFORE the name is scrubbed, while the path is still the one we wrote to.
3. Rename to a same-length random name so the original filename is overwritten in the
   directory entry rather than left behind for a carver.
4. Truncate to zero so the length is not left in metadata either.

VERIFICATION IS AGAINST A KNOWN PATTERN, and that is the whole point.

The first version of this module wrote `secrets.token_bytes` and then "verified" by
checking the read-back was not all zeros. That cannot work: unreproducible bytes leave
nothing to compare against, and old data is not zeros either, so the check returned True
for a file that had never been touched. A function named verify that returns VERIFIED for
untouched data is the worst defect this project can ship, because the entire pitch is that
it does not claim more than it achieved.

This version derives the pattern from a per-file random seed with SHA-256, exactly as
`erasure/engine.py` does for block devices, so any offset can be recomputed and compared
byte-for-byte. One implementation of one idea, in two places that needed it.

WHAT THIS CANNOT DO, recorded in `limitations` on every result:
  - Filesystem-internal metadata (NTFS MFT resident data, ext4 inode tables, journal
    copies, snapshots) may retain traces userspace cannot reach.
  - On btrfs, ZFS, APFS, or ext4 mounted data=journal, an in-place overwrite is not
    guaranteed to land on the original blocks.
  - Small files stored resident inside an MFT record are not reached by a data-stream
    overwrite.
  - NIST Purge is unreachable from userspace. This module records Clear, never Purge.

Contract (do not change without updating docs/ENGINEERING_RULES.md):

    erase_path(path, *, recursive=False, passes=1, confirm="") -> dict
        {
          "targets": [ {path, size, method_used, outcome, reason}, ... ],
          "method_used": str,      # "Clear" if ANY target was cleared, else "NotPerformed"
          "outcome":     str,      # VERIFIED | UNVERIFIED | PARTIAL | NOT_PERFORMED
          "verified":    bool,
          "performed":   int,      # how many targets were actually destroyed
          "filesystem":  str,
          "limitations": [str],    # always populated, never empty
        }
"""

from __future__ import annotations

import ctypes
import hashlib
import os
import platform
import secrets
import string
from dataclasses import dataclass, asdict, field
from pathlib import Path

from erasure import streams as ads

from attestation.canonical import result_digest

CONFIRM_TOKEN = "I-UNDERSTAND-THIS-DESTROYS-DATA"
ALLOW_ENV = "AKHANDA_ALLOW_FILE_ERASE"

# Filesystems where an in-place overwrite is not guaranteed to reach original blocks.
COW_OR_JOURNALLED = {"btrfs", "zfs", "apfs", "refs", "nilfs2", "bcachefs"}

OUTCOME_VERIFIED = "VERIFIED"
OUTCOME_UNVERIFIED = "UNVERIFIED"
OUTCOME_PARTIAL = "PARTIAL"
OUTCOME_NOT_PERFORMED = "NOT_PERFORMED"

OUTCOME_RANK = {OUTCOME_VERIFIED: 3, OUTCOME_PARTIAL: 2,
                OUTCOME_UNVERIFIED: 1, OUTCOME_NOT_PERFORMED: 0}

BLOCK = 1024 * 1024
SAMPLE_COUNT = 16
SAMPLE_LEN = 4096

_NAME_ALPHABET = string.ascii_lowercase + string.digits

# Paths that are never acceptable targets, whatever the caller passes. The drive eraser
# has three independent gates; a recursive file eraser can destroy just as much, so it
# gets the same treatment rather than a bare boolean.
REFUSED_ROOTS = (
    "/", "/bin", "/boot", "/dev", "/etc", "/home", "/lib", "/proc", "/root",
    "/sbin", "/sys", "/usr", "/var",
    "c:\\", "c:\\windows", "c:\\program files", "c:\\program files (x86)",
    "c:\\users",
)


class FileErasureRefused(Exception):
    """Raised when the guard blocks an operation. Never caught internally."""


@dataclass
class TargetResult:
    path: str
    size: int
    method_used: str        # "Clear" | "NotPerformed"
    outcome: str
    reason: str
    # Alternate data streams found and erased alongside the file. Recorded even when the
    # count is zero: "this file had none" and "streams were never looked for" are
    # different facts, and only the first is a statement about the file.
    streams: dict = field(default_factory=dict)


# ───────────────────────────────────────────────────────── filesystem detection

def detect_filesystem(path) -> str:
    """The filesystem type at `path`, or "unknown".

    "unknown" is honest and is handled honestly downstream, it downgrades the outcome to
    UNVERIFIED rather than being treated as a safe default. The previous stub returned
    "unknown" unconditionally while its docstring claimed a downgrade that the code did
    not perform, so an unrecognised filesystem produced the STRONGEST outcome.
    """
    p = Path(path).resolve()
    system = platform.system()

    if system == "Windows":
        return _detect_windows(p)
    if system == "Linux":
        return _detect_linux(p)
    if system == "Darwin":
        return _detect_darwin(p)
    return "unknown"


def _detect_windows(p: Path) -> str:
    """GetVolumeInformationW on the volume containing `p`."""
    try:
        drive = os.path.splitdrive(str(p))[0]
        if not drive:
            return "unknown"
        root = drive + "\\"
        fs_buf = ctypes.create_unicode_buffer(256)
        name_buf = ctypes.create_unicode_buffer(256)
        serial = ctypes.c_ulong()
        maxlen = ctypes.c_ulong()
        flags = ctypes.c_ulong()
        ok = ctypes.windll.kernel32.GetVolumeInformationW(
            ctypes.c_wchar_p(root), name_buf, ctypes.sizeof(name_buf),
            ctypes.byref(serial), ctypes.byref(maxlen), ctypes.byref(flags),
            fs_buf, ctypes.sizeof(fs_buf),
        )
        return fs_buf.value.lower() if ok else "unknown"
    except (OSError, AttributeError, ValueError):
        return "unknown"


def _detect_linux(p: Path) -> str:
    """Longest matching mount point in /proc/mounts."""
    try:
        best_len, best_fs = -1, "unknown"
        target = str(p)
        with open("/proc/mounts", "r", encoding="utf-8") as fh:
            for line in fh:
                parts = line.split()
                if len(parts) < 3:
                    continue
                mount, fstype = parts[1], parts[2]
                if (target == mount or target.startswith(mount.rstrip("/") + "/")) \
                        and len(mount) > best_len:
                    best_len, best_fs = len(mount), fstype
        return best_fs.lower()
    except OSError:
        return "unknown"


def _detect_darwin(p: Path) -> str:
    """Filesystem type on macOS, via an ABSOLUTE path to stat.

    A bare "stat" is resolved through PATH, so anything earlier on PATH answers instead --
    and the answer decides whether an erasure is recorded VERIFIED or PARTIAL. On a
    forensic workstation that is a decision worth not delegating to the environment
    (bandit B607). The absolute path is checked to exist first; if it does not, the
    filesystem is reported unknown, which downgrades the outcome honestly.
    """
    import subprocess
    for stat_bin in ("/usr/bin/stat", "/bin/stat"):
        if not Path(stat_bin).is_file():
            continue
        try:
            out = subprocess.run([stat_bin, "-f", "%T", str(p)],  # noqa: S603 - fixed argv
                                 capture_output=True, text=True, timeout=10, check=False)
            return out.stdout.strip().lower() or "unknown"
        except (OSError, subprocess.SubprocessError):
            return "unknown"
    return "unknown"


# ─────────────────────────────────────────────────────── pattern and verification

def _pattern(seed: bytes, offset: int, length: int) -> bytes:
    """Deterministic pseudorandom bytes for a given offset.

    Identical construction to erasure/engine.py. Deterministic so verification can
    recompute exactly what SHOULD be at any offset without storing the whole pattern.
    Not a security primitive, it is a wipe pattern, and the record says so.
    """
    out = bytearray()
    counter = offset // 32
    while len(out) < length + 32:
        out += hashlib.sha256(seed + counter.to_bytes(8, "big")).digest()
        counter += 1
    skew = offset % 32
    return bytes(out[skew:skew + length])


def _overwrite_in_place(p: Path, size: int, seed: bytes, passes: int) -> None:
    """Overwrite the file's own bytes, flush, and fsync so the write actually lands.

    NIST SP 800-88 Rev. 2: one pass suffices for Clear. Extra passes do not improve
    security on modern media and only wear flash cells, so `passes` defaults to 1 and
    exists only for operators whose local policy demands more. The LAST pass writes the
    pattern that verification checks.
    """
    if size == 0:
        return
    with open(p, "r+b", buffering=0) as fh:
        for _ in range(passes):
            fh.seek(0)
            written = 0
            while written < size:
                n = min(BLOCK, size - written)
                fh.write(_pattern(seed, written, n))
                written += n
            fh.flush()
            os.fsync(fh.fileno())


def verify_overwritten(p: Path, size: int, seed: bytes,
                       samples: int = SAMPLE_COUNT) -> tuple[bool, list]:
    """Read back spread offsets and compare byte-for-byte against the written pattern.

    Returns (all_matched, sample_records). This is what makes VERIFIED mean something:
    a device or filesystem that silently discarded the write fails here instead of being
    reported as a clean wipe.
    """
    if size == 0:
        return True, []

    n = max(1, min(samples, max(1, size // SAMPLE_LEN)))
    step = max(SAMPLE_LEN, size // n)
    records = []
    try:
        with open(p, "rb", buffering=0) as fh:
            for i in range(n):
                off = min(i * step, max(0, size - SAMPLE_LEN))
                want = min(SAMPLE_LEN, size - off)
                fh.seek(off)
                actual = fh.read(want)
                expected = _pattern(seed, off, want)
                records.append({
                    "offset": off,
                    "expected_sha256": hashlib.sha256(expected).hexdigest(),
                    "actual_sha256": hashlib.sha256(actual).hexdigest(),
                    "match": actual == expected,
                })
    except OSError:
        return False, records
    return all(r["match"] for r in records), records


# ─────────────────────────────────────────────────────────── name and metadata

def _random_name(length: int) -> str:
    return "".join(secrets.choice(_NAME_ALPHABET) for _ in range(max(1, length)))


def _scrub_name_and_unlink(p: Path) -> None:
    """Rename to a same-length random name, truncate to zero, then unlink.

    The rename retries on collision. POSIX rename silently REPLACES an existing target,
    so a collision would destroy an unrelated file, improbable, and improbable is not a
    reason to leave it in a tool that destroys data.
    """
    scrubbed = None
    for _ in range(8):
        candidate = p.with_name(_random_name(len(p.name)))
        if candidate.exists():
            continue
        try:
            p.rename(candidate)
            scrubbed = candidate
            break
        except OSError:
            continue

    if scrubbed is None:          # could not scrub the name; still remove the data
        p.unlink()
        return

    with open(scrubbed, "r+b", buffering=0) as fh:
        fh.truncate(0)
        fh.flush()
        os.fsync(fh.fileno())
    scrubbed.unlink()


# ────────────────────────────────────────────────────────────────── the guard

def _guard(path: str, confirm: str, recursive: bool) -> None:
    p = Path(path).resolve()

    if confirm != CONFIRM_TOKEN:
        raise FileErasureRefused(
            f"refusing to erase {path!r}: pass confirm={CONFIRM_TOKEN!r}. "
            "This destroys data irreversibly."
        )
    if os.environ.get(ALLOW_ENV) != "1":
        raise FileErasureRefused(
            f"refusing to erase {path!r}: set {ALLOW_ENV}=1 in the environment. "
            "Two independent gates, matching the drive eraser."
        )

    # Check the RESOLVED path and the RAW input. Resolving alone is not enough: on
    # Windows `Path("/etc").resolve()` becomes `D:\etc`, so a POSIX system root typed by
    # a operator on the wrong platform slipped straight through the resolved comparison.
    # Checking both means the refusal does not depend on which OS the guard runs under.
    candidates = {
        str(p).lower().replace("/", "\\").rstrip("\\"),
        str(path).lower().replace("/", "\\").rstrip("\\"),
    }
    for bad in REFUSED_ROOTS:
        b = bad.lower().replace("/", "\\").rstrip("\\")
        if b and b in candidates:
            raise FileErasureRefused(
                f"refusing to erase {path!r}: it is a system root ({bad}). "
                "If this really is the evidence path, name a subdirectory explicitly."
            )
    if p.parent == p or str(path).strip() in ("/", "\\"):
        raise FileErasureRefused(f"refusing to erase a filesystem root: {path!r}")


# ───────────────────────────────────────────────────────────────── the operation

def erase_file(path: str, *, passes: int = 1, seed: bytes | None = None) -> TargetResult:
    """Erase one file. Records the level actually achieved, never the level requested."""
    p = Path(path)
    if not p.is_file():
        return TargetResult(str(p), 0, "NotPerformed", OUTCOME_NOT_PERFORMED,
                            "not a regular file")
    if p.is_symlink():
        return TargetResult(str(p), 0, "NotPerformed", OUTCOME_NOT_PERFORMED,
                            "symlink: refusing to follow it and erase the target")

    try:
        size = p.stat().st_size
    except OSError as e:
        return TargetResult(str(p), 0, "NotPerformed", OUTCOME_NOT_PERFORMED,
                            f"cannot stat: {e}")

    fs = detect_filesystem(p)
    seed = seed or secrets.token_bytes(32)

    try:
        _overwrite_in_place(p, size, seed, passes)
    except OSError as e:
        return TargetResult(str(p), size, "NotPerformed", OUTCOME_NOT_PERFORMED,
                            f"overwrite failed: {e}")

    matched, _samples = verify_overwritten(p, size, seed)

    # ALTERNATE DATA STREAMS, BEFORE THE UNLINK.
    #
    # A named NTFS stream shares the file's directory entry but not its bytes, so
    # everything above -- the pattern write, the read-back, the verification -- touched the
    # default stream and nothing else. A file can therefore be erased, verified and
    # reported VERIFIED while a stream attached to it still holds its contents intact.
    # SIH26149 names this: "remove associated metadata and residual traces".
    #
    # The ordering is the correctness. Unlinking first would drop the streams along with
    # the file, leaving their blocks unreferenced but never overwritten -- which is
    # ordinary deletion wearing the name of erasure.
    stream_report = ads.erase_streams(p, seed=seed)

    try:
        _scrub_name_and_unlink(p)
    except OSError as e:
        return TargetResult(str(p), size, "Clear", OUTCOME_UNVERIFIED,
                            f"overwritten but unlink/scrub failed: {e}", stream_report)

    # Order matters: a copy-on-write filesystem is PARTIAL even when the read-back
    # matched, because the read came back through the same layer that may have written
    # the new bytes somewhere else entirely.
    if fs in COW_OR_JOURNALLED:
        return TargetResult(
            str(p), size, "Clear", OUTCOME_PARTIAL,
            f"filesystem {fs}: an in-place overwrite is not guaranteed to reach the "
            "original blocks; content may persist in snapshots or copy-on-write extents",
            stream_report)

    if not matched:
        return TargetResult(str(p), size, "Clear", OUTCOME_UNVERIFIED,
                            "read-back sampling did not match the written pattern",
                            stream_report)

    if fs == "unknown":
        return TargetResult(
            str(p), size, "Clear", OUTCOME_UNVERIFIED,
            "overwrite verified by read-back, but the filesystem could not be "
            "identified, so it is not known whether the write reached the original "
            "blocks", stream_report)

    # A stream that could not be erased is a surviving copy of data this function has
    # just reported as destroyed. It cannot be VERIFIED, whatever the main stream did.
    if stream_report.get("failed"):
        return TargetResult(
            str(p), size, "Clear", OUTCOME_PARTIAL,
            f"overwritten on {fs} and read-back matched, but "
            f"{stream_report['failed']} alternate data stream(s) could not be erased and "
            "may still hold recoverable content", stream_report)

    extra = ""
    if stream_report.get("erased"):
        extra = (f", and {stream_report['erased']} alternate data stream(s) "
                 f"({stream_report['bytes']} bytes) overwritten and removed")
    return TargetResult(str(p), size, "Clear", OUTCOME_VERIFIED,
                        f"overwritten on {fs}, read-back matched the written pattern, "
                        "name scrubbed, truncated, unlinked" + extra, stream_report)


def erase_path(path: str, *, recursive: bool = False, passes: int = 1,
               confirm: str = "") -> dict:
    """Entry point the attestation core calls. See the module docstring for the contract.

    Raises FileErasureRefused for a guard violation, a caller error, not an outcome.
    Returns a NOT_PERFORMED result for anything that is merely absent or ineligible.
    """
    _guard(path, confirm, recursive)

    root = Path(path)
    fs = detect_filesystem(root if root.exists() else root.parent)

    def refuse(reason: str) -> dict:
        return {
            "targets": [], "method_used": "NotPerformed",
            "outcome": OUTCOME_NOT_PERFORMED, "verified": False, "performed": 0,
            "filesystem": fs, "limitations": [reason] + _base_limitations(),
        }

    if root.is_file():
        targets = [root]
    elif root.is_dir():
        if not recursive:
            return refuse("target is a directory and recursive=False")
        targets = sorted(q for q in root.rglob("*") if q.is_file() and not q.is_symlink())
        if not targets:
            return refuse(f"no regular files under {path}")
    else:
        return refuse(f"no such file or directory: {path}")

    results = [erase_file(str(q), passes=passes) for q in targets]

    # The OUTCOME is quoted at the weakest target, one clean file cannot launder a
    # failed one beside it. But METHOD_USED is not: reporting "NotPerformed" for the
    # whole operation while nine of ten files were irreversibly destroyed is a false
    # record in the other direction, and understating destruction is no more honest
    # than overstating it. `performed` carries the count so neither is guessed.
    worst = min((r.outcome for r in results), key=lambda o: OUTCOME_RANK[o])
    performed = sum(1 for r in results if r.method_used == "Clear")

    limitations = _base_limitations()
    if any(r.outcome == OUTCOME_PARTIAL for r in results):
        limitations.append(
            "One or more targets are on a copy-on-write or journalling filesystem where "
            "an in-place overwrite is not guaranteed to reach the original blocks.")
    if any(r.outcome == OUTCOME_NOT_PERFORMED for r in results):
        failed = [r.path for r in results if r.outcome == OUTCOME_NOT_PERFORMED]
        limitations.append(
            f"{len(failed)} target(s) were not erased and remain on disk: "
            f"{', '.join(failed[:5])}{' ...' if len(failed) > 5 else ''}")

    return {
        "targets": [asdict(r) for r in results],
        "method_used": "Clear" if performed else "NotPerformed",
        "outcome": worst,
        "verified": worst == OUTCOME_VERIFIED,
        "performed": performed,
        "filesystem": fs,
        "limitations": limitations,
    }


def _base_limitations() -> list[str]:
    """Stated on every result, including refusals. Never omitted for being inconvenient."""
    return [
        "NIST SP 800-88 Rev. 2 Purge is unreachable from userspace; this module records "
        "Clear and never Purge.",
        "Filesystem-internal metadata (NTFS MFT records, ext4 inode tables, journal "
        "copies, snapshots) may retain traces that cannot be reached from userspace.",
        "Small files stored resident inside a filesystem metadata record are not reached "
        "by a data-stream overwrite.",
    ]


def result_hash(result: dict) -> str:
    """Digest of an erase_path() result, for the ledger entry.

    Delegates to attestation.canonical so this engine, the drive eraser, and the recovery
    engine all compute one digest rather than three.
    """
    return result_digest(result)
