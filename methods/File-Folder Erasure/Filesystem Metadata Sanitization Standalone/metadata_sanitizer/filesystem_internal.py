from __future__ import annotations

from dataclasses import dataclass, asdict
from pathlib import Path
import ctypes
import os
import subprocess


@dataclass(frozen=True)
class FilesystemAssessment:
    target: str
    filesystem: str | None
    internal_metadata_status: str
    supported_operations: list[str]
    unsupported_reasons: list[str]
    recommended_route: str

    def to_dict(self):
        return asdict(self)


def _windows_filesystem(path: Path) -> str | None:
    if os.name != "nt":
        return None
    root = Path(str(path.resolve())).anchor
    if not root:
        return None
    name = ctypes.create_unicode_buffer(261)
    serial = ctypes.c_ulong()
    max_component = ctypes.c_ulong()
    flags = ctypes.c_ulong()
    fs_name = ctypes.create_unicode_buffer(261)
    ok = ctypes.windll.kernel32.GetVolumeInformationW(
        ctypes.c_wchar_p(root), name, len(name), ctypes.byref(serial),
        ctypes.byref(max_component), ctypes.byref(flags), fs_name, len(fs_name)
    )
    return fs_name.value.lower() if ok else None


def _unix_filesystem(path: Path) -> str | None:
    try:
        result = subprocess.run(
            ["findmnt", "-T", str(path), "-n", "-o", "FSTYPE"],
            check=False, capture_output=True, text=True, timeout=5,
        )
        if result.returncode == 0 and result.stdout.strip():
            return result.stdout.strip().lower()
    except (FileNotFoundError, OSError, subprocess.SubprocessError):
        pass
    return None


def detect_filesystem(target) -> str | None:
    path = Path(target)
    return _windows_filesystem(path) if os.name == "nt" else _unix_filesystem(path)


def assess_internal_metadata(target) -> FilesystemAssessment:
    path = Path(target)
    fs = detect_filesystem(path)
    common = (
        "filesystem-internal historical metadata is not exposed through the portable "
        "file API; a filesystem-specific, independently qualified mechanism is required"
    )
    if fs in {"ntfs", "refs"}:
        return FilesystemAssessment(
            str(path), fs, "REQUIRES_FILESYSTEM_SPECIFIC_BACKEND", [],
            [common, "free MFT records, directory slack and transaction history are not covered"],
            "Use a qualified Windows/filesystem-specific workflow or whole-media purge",
        )
    if fs in {"ext2", "ext3", "ext4"}:
        return FilesystemAssessment(
            str(path), fs, "REQUIRES_FILESYSTEM_SPECIFIC_BACKEND", [],
            [common, "filesystem journal and deleted directory metadata are not covered"],
            "Use a qualified filesystem-specific workflow or whole-media purge",
        )
    if fs == "btrfs":
        return FilesystemAssessment(
            str(path), fs, "REQUIRES_FILESYSTEM_SPECIFIC_BACKEND", [],
            [common, "copy-on-write extents, snapshots and metadata trees are not covered"],
            "Use qualified snapshot handling followed by appropriate media sanitization",
        )
    if fs in {"apfs", "hfs", "hfsplus"}:
        return FilesystemAssessment(
            str(path), fs, "REQUIRES_FILESYSTEM_SPECIFIC_BACKEND", [],
            [common, "filesystem-internal and snapshot records are not covered"],
            "Use a qualified Apple/filesystem-specific workflow or media purge",
        )
    return FilesystemAssessment(
        str(path), fs, "UNSUPPORTED", [],
        [common if fs else "filesystem type could not be determined safely"],
        "Do not guess; select a qualified filesystem-specific handler or media-level sanitization",
    )
