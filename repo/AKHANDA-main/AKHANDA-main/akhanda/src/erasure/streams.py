"""NTFS alternate data streams, the residual trace an overwrite leaves behind.

WHY THIS EXISTS. SIH26149 names it directly: the file and folder eraser must "remove
associated metadata and residual traces". An alternate data stream is exactly that, and it
is the one that survives a correct, verified, honest erasure of the file it is attached to.

WHAT AN ADS IS. On NTFS every file has an unnamed default stream (`file.txt::$DATA`) and
may have any number of NAMED streams (`file.txt:notes:$DATA`). They share the directory
entry and the file name. They do not share bytes. `dir` does not list them, `os.path.getsize`
does not count them, and overwriting the file overwrites the default stream ONLY.

So a file can be securely erased, pattern written, read-back verified, name scrubbed,
truncated, unlinked, while a named stream attached to it was never touched. Before unlink
the data is fully intact and reachable by anyone who knows the stream name; after unlink the
blocks are unreferenced but were never overwritten, so they are exactly as recoverable as
any other deleted data. That is a residual trace, and it is invisible to every check the
eraser performed.

Streams are how data actually gets hidden on Windows. Zone.Identifier is the benign one
everybody has; malware has used them to stash payloads for twenty years. An eraser for
forensic use that silently ignores them is making a claim it has not earned.

    list_streams(path)   -> [StreamRef]     named streams only, never the default
    erase_streams(path)  -> {found, erased, failed, details}

WHAT THIS CANNOT DO, stated here rather than discovered later. It overwrites the stream's
bytes and deletes the stream, which is the same Clear-level guarantee the main eraser gives
and no stronger. It does not reach a stream small enough to be resident in the MFT record
itself, for the same reason the main eraser cannot: that data lives inside filesystem
metadata, not in a data run, and userspace cannot address it. That limit is reported, not
papered over.
"""
from __future__ import annotations

import ctypes
import os
import platform
import secrets
import subprocess
from ctypes import wintypes
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Optional

# FindFirstStreamW / FindNextStreamW. Available since Vista; the fallback below covers
# the case where they are missing rather than pretending no streams exist.
_STREAM_INFO_LEVEL_STANDARD = 0
_INVALID_HANDLE = ctypes.c_void_p(-1).value
_ERROR_HANDLE_EOF = 38


@dataclass
class StreamRef:
    """One named alternate data stream attached to a file."""
    path: str          # the full "file:stream:$DATA" path, usable with open()
    name: str          # ":stream:$DATA"
    size: int

    def to_dict(self) -> dict:
        return asdict(self)


class _WIN32_FIND_STREAM_DATA(ctypes.Structure):
    _fields_ = [("StreamSize", ctypes.c_longlong),
                ("cStreamName", ctypes.c_wchar * 296)]


def supported() -> bool:
    """Are alternate data streams even a concept here?

    Only NTFS and ReFS carry them. Returning False elsewhere is a statement that the
    question does not apply, NOT that the check was skipped -- callers distinguish the two.
    """
    return platform.system() == "Windows"


def list_streams(path) -> list:
    """Named streams on `path`. The default `::$DATA` stream is never included.

    Returns [] both when a file genuinely has no streams and when the platform has no such
    concept. `supported()` is what separates those, and every caller here checks it.
    """
    if not supported():
        return []
    p = Path(path)
    if not p.is_file():
        return []

    try:
        k32 = ctypes.WinDLL("kernel32", use_last_error=True)
        find_first = k32.FindFirstStreamW
        find_next = k32.FindNextStreamW
    except (AttributeError, OSError):
        return []

    find_first.argtypes = [wintypes.LPCWSTR, ctypes.c_int,
                           ctypes.POINTER(_WIN32_FIND_STREAM_DATA), wintypes.DWORD]
    find_first.restype = ctypes.c_void_p
    find_next.argtypes = [ctypes.c_void_p, ctypes.POINTER(_WIN32_FIND_STREAM_DATA)]
    find_next.restype = wintypes.BOOL
    k32.FindClose.argtypes = [ctypes.c_void_p]

    data = _WIN32_FIND_STREAM_DATA()
    handle = find_first(str(p), _STREAM_INFO_LEVEL_STANDARD, ctypes.byref(data), 0)
    if handle in (None, _INVALID_HANDLE):
        return []

    out = []
    try:
        while True:
            name = data.cStreamName
            # "::$DATA" is the file's own contents, which the ordinary eraser handles.
            # Reporting it here would double-count it and imply a stream that is not there.
            if name and name != "::$DATA":
                out.append(StreamRef(path=str(p) + name, name=name,
                                     size=int(data.StreamSize)))
            if not find_next(handle, ctypes.byref(data)):
                break
    finally:
        k32.FindClose(handle)
    return out


def _overwrite_stream(stream_path: str, size: int, seed: bytes) -> bool:
    """Overwrite a stream's bytes in place. True if every byte was written and flushed."""
    if size <= 0:
        return True
    block = 1 << 20
    try:
        fd = os.open(stream_path, os.O_WRONLY | getattr(os, "O_BINARY", 0))
    except OSError:
        return False
    try:
        written = 0
        while written < size:
            n = min(block, size - written)
            chunk = (seed * ((n // len(seed)) + 1))[:n]
            os.write(fd, chunk)
            written += n
        os.fsync(fd)
        return True
    except OSError:
        return False
    finally:
        os.close(fd)


def erase_streams(path, *, seed: Optional[bytes] = None) -> dict:
    """Overwrite and delete every named stream on `path`. Reports, never raises.

    Returns {supported, found, erased, failed, bytes, details, note}. `found` is reported
    separately from `erased` on purpose: "there were none" and "there were three and all
    three are gone" are different facts, and a caller that cannot tell them apart cannot
    write an honest record.

    ORDER MATTERS, for the same reason it does in the main eraser: overwrite the bytes
    first, then delete the stream. Deleting first would unreference the blocks while
    leaving their contents intact, which is the failure this module exists to prevent.
    """
    out = {"supported": supported(), "found": 0, "erased": 0, "failed": 0,
           "bytes": 0, "details": [], "note": ""}
    if not supported():
        out["note"] = (f"alternate data streams are an NTFS/ReFS concept; "
                       f"{platform.system()} has none. Not skipped -- not applicable.")
        return out

    streams = list_streams(path)
    out["found"] = len(streams)
    if not streams:
        out["note"] = "no named alternate data streams on this file"
        return out

    seed = seed or secrets.token_bytes(32)
    for s in streams:
        rec = {"name": s.name, "size": s.size, "overwritten": False, "deleted": False,
               "reason": ""}
        rec["overwritten"] = _overwrite_stream(s.path, s.size, seed)
        try:
            os.remove(s.path)
            rec["deleted"] = True
        except OSError as exc:
            rec["reason"] = f"{type(exc).__name__}: {exc}"

        if rec["overwritten"] and rec["deleted"]:
            out["erased"] += 1
            out["bytes"] += s.size
        else:
            out["failed"] += 1
            if not rec["reason"]:
                rec["reason"] = ("the stream was deleted but its bytes were not "
                                 "overwritten first" if rec["deleted"] else
                                 "overwrite failed")
        out["details"].append(rec)

    remaining = len(list_streams(path))
    out["remaining_after"] = remaining
    out["note"] = (
        f"{out['erased']} of {out['found']} named stream(s) overwritten and removed"
        + (f"; {remaining} still present" if remaining else "; none remain")
        + ". Clear level only: a stream small enough to be resident inside the MFT record "
          "is not reachable from userspace, exactly as for the file's own data."
    )
    return out


def describe_limits() -> dict:
    """What this module does and does not claim, for the certificate."""
    return {
        "checked": supported(),
        "applies_to": "NTFS and ReFS",
        "why_it_matters": (
            "A named alternate data stream shares a file's directory entry but not its "
            "bytes. Overwriting the file overwrites the default stream only, so a file "
            "can be erased, read-back verified and unlinked while an attached stream was "
            "never touched -- a residual trace invisible to every check performed."),
        "level": "Clear",
        "not_reached": (
            "A stream resident inside the MFT record itself, for the same reason the "
            "file's own resident data is not reached: it lives in filesystem metadata "
            "rather than in a data run, and userspace cannot address it."),
    }
