from __future__ import annotations

from dataclasses import dataclass, asdict
from pathlib import Path
import json
import os
import secrets
import stat
import time
from typing import Iterable


class MetadataError(RuntimeError):
    pass


@dataclass(frozen=True)
class MetadataResult:
    target: str
    status: str
    xattrs_seen: int
    xattrs_removed: int
    timestamps_normalized: bool
    permissions_normalized: bool
    renamed: bool
    new_name: str | None
    recursive: bool
    verified: bool
    unsupported: list[str]
    started_utc: str
    completed_utc: str
    error: str | None = None

    def to_dict(self):
        return asdict(self)


def _utc_now():
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _validate(path: Path):
    try:
        st = path.lstat()
    except FileNotFoundError as exc:
        raise MetadataError(f"target does not exist: {path}") from exc
    if stat.S_ISLNK(st.st_mode):
        raise MetadataError("refusing symbolic-link target")
    return st


def _list_xattrs(path: Path) -> list[str]:
    if not hasattr(os, "listxattr"):
        return []
    try:
        return list(os.listxattr(path, follow_symlinks=False))
    except OSError as exc:
        raise MetadataError(f"cannot enumerate xattrs: errno={exc.errno}") from exc


def inspect_metadata(target):
    path = Path(target)
    st = _validate(path)
    return {
        "target": str(path),
        "type": "directory" if stat.S_ISDIR(st.st_mode) else "file",
        "size": st.st_size,
        "mode_octal": oct(stat.S_IMODE(st.st_mode)),
        "uid": getattr(st, "st_uid", None),
        "gid": getattr(st, "st_gid", None),
        "atime_ns": st.st_atime_ns,
        "mtime_ns": st.st_mtime_ns,
        "ctime_ns": st.st_ctime_ns,
        "xattrs": _list_xattrs(path),
        "name": path.name,
    }


def _targets(path: Path, recursive: bool) -> Iterable[Path]:
    st = _validate(path)
    if stat.S_ISDIR(st.st_mode):
        yield path
        if recursive:
            for child in path.rglob("*"):
                try:
                    child_st = child.lstat()
                except FileNotFoundError:
                    continue
                if stat.S_ISLNK(child_st.st_mode):
                    continue
                yield child
    else:
        yield path


def _clear_xattrs(path: Path):
    names = _list_xattrs(path)
    if not names:
        return 0, []
    if not hasattr(os, "removexattr"):
        return 0, ["xattrs-not-removable-by-platform"]

    removed = 0
    unsupported = []
    for name in names:
        try:
            os.removexattr(path, name, follow_symlinks=False)
            removed += 1
        except OSError as exc:
            unsupported.append(f"xattr:{name}:errno={exc.errno}")
    return removed, unsupported


def _normalize_times(path: Path):
    if os.name == "nt":
        os.utime(path, ns=(0, 0))
    else:
        os.utime(path, ns=(0, 0), follow_symlinks=False)


def _verify_times(path: Path):
    st = path.lstat()
    return st.st_atime_ns == 0 and st.st_mtime_ns == 0


def _normalize_permissions(path: Path):
    if os.name == "nt":
        raise MetadataError("permission normalization is not supported by this backend")
    mode = stat.S_IMODE(path.lstat().st_mode)
    os.chmod(path, mode & (stat.S_IRUSR | stat.S_IWUSR), follow_symlinks=False)


def _verify_permissions(path: Path):
    if os.name == "nt":
        return False
    return stat.S_IMODE(path.lstat().st_mode) == (stat.S_IRUSR | stat.S_IWUSR)


def _rename(path: Path, token: str):
    if not token or "/" in token or "\\" in token or token in {".", ".."}:
        raise MetadataError("invalid rename token")
    candidate = path.with_name(f".{token}-{secrets.token_hex(8)}")
    if candidate.exists() or candidate.is_symlink():
        raise MetadataError("generated destination already exists")
    path.rename(candidate)
    return candidate


def _verify_renamed(original: Path, new_path: Path):
    return (not original.exists()) and new_path.exists() and not new_path.is_symlink()


def sanitize_metadata(
    target,
    *,
    clear_xattrs=False,
    normalize_times=False,
    normalize_permissions=False,
    rename=False,
    name_token="sanitized",
    recursive=False,
):
    path = Path(target)
    started = _utc_now()
    try:
        _validate(path)
        x_seen = 0
        x_removed = 0
        unsupported: list[str] = []
        renamed = False
        new_name = None
        verified = True
        targets = list(_targets(path, recursive))

        for item in targets:
            names_before = _list_xattrs(item)
            x_seen += len(names_before)
            if clear_xattrs:
                removed, un = _clear_xattrs(item)
                x_removed += removed
                unsupported.extend(un)
                remaining = _list_xattrs(item)
                if remaining:
                    verified = False
                    unsupported.append(f"xattr-verification:{item}")

            if normalize_times:
                _normalize_times(item)
                if not _verify_times(item):
                    verified = False
                    unsupported.append(f"timestamp-verification:{item}")

            if normalize_permissions:
                _normalize_permissions(item)
                if not _verify_permissions(item):
                    verified = False
                    unsupported.append(f"permission-verification:{item}")

        if rename:
            new_path = _rename(path, name_token)
            renamed = True
            new_name = str(new_path)
            if not _verify_renamed(path, new_path):
                verified = False
                unsupported.append("rename-verification")

        status = "SANITIZED" if verified else "VERIFICATION_FAILED"
        return MetadataResult(
            target=str(path),
            status=status,
            xattrs_seen=x_seen,
            xattrs_removed=x_removed,
            timestamps_normalized=normalize_times,
            permissions_normalized=normalize_permissions,
            renamed=renamed,
            new_name=new_name,
            recursive=recursive,
            verified=verified,
            unsupported=unsupported,
            started_utc=started,
            completed_utc=_utc_now(),
        )
    except Exception as exc:
        return MetadataResult(
            target=str(path),
            status="ERROR",
            xattrs_seen=0,
            xattrs_removed=0,
            timestamps_normalized=False,
            permissions_normalized=False,
            renamed=False,
            new_name=None,
            recursive=recursive,
            verified=False,
            unsupported=[],
            started_utc=started,
            completed_utc=_utc_now(),
            error=str(exc),
        )


def write_audit(path, result: MetadataResult):
    record = {
        "schema": "secure-erasure.audit.v1",
        "method": "filesystem-metadata-sanitization",
        "created_utc": _utc_now(),
        "result": result.to_dict(),
        "assurance_note": (
            "Only metadata exposed through selected OS APIs is covered. "
            "Filesystem journals, deleted directory-entry slack, snapshots, backups, "
            "replicas and controller-level copies require filesystem-specific handling."
        ),
    }
    out = Path(path)
    out.parent.mkdir(parents=True, exist_ok=True)
    tmp = out.with_suffix(out.suffix + ".tmp")
    tmp.write_text(json.dumps(record, indent=2, sort_keys=True), encoding="utf-8")
    os.replace(tmp, out)
    return out
