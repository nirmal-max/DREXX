from __future__ import annotations
from dataclasses import dataclass, asdict
from pathlib import Path
import json, os, stat, time, secrets


class MetadataError(RuntimeError):
    pass


@dataclass(frozen=True)
class MetadataResult:
    target: str
    status: str
    xattrs_seen: int
    xattrs_removed: int
    xattrs_verified_removed: bool
    timestamps_normalized: bool
    timestamps_verified: bool
    permissions_normalized: bool
    permissions_verified: bool
    renamed: bool
    new_name: str | None
    recursive: bool
    coverage: str
    started_utc: str
    completed_utc: str
    unsupported: list[str]
    error: str | None = None

    def to_dict(self):
        return asdict(self)


def _utc_now():
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _validate(path: Path):
    if not path.exists() and not path.is_symlink():
        raise MetadataError(f"target does not exist: {path}")
    if path.is_symlink():
        raise MetadataError("refusing symbolic-link target")


def _list_xattrs(path: Path):
    if not hasattr(os, "listxattr"):
        return []
    try:
        return os.listxattr(path, follow_symlinks=False)
    except (AttributeError, OSError):
        return []


def inspect_metadata(target):
    path = Path(target)
    _validate(path)
    st = path.lstat()
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


def _targets(path: Path, recursive: bool):
    if path.is_dir():
        yield path
        if recursive:
            for child in path.rglob("*"):
                if child.is_symlink():
                    continue
                yield child
    else:
        yield path


def _clear_xattrs(path: Path):
    removed = 0
    unsupported = []
    if not hasattr(os, "listxattr") or not hasattr(os, "removexattr"):
        return removed, ["xattrs-not-supported-by-platform"]
    try:
        names = os.listxattr(path, follow_symlinks=False)
        for name in names:
            try:
                os.removexattr(path, name, follow_symlinks=False)
                removed += 1
            except OSError as exc:
                unsupported.append(f"xattr:{name}:{exc.errno}")
    except OSError as exc:
        unsupported.append(f"xattr-list:{exc.errno}")
    return removed, unsupported


def _verify_xattrs(path: Path):
    if not hasattr(os, "listxattr"):
        return False
    try:
        return len(os.listxattr(path, follow_symlinks=False)) == 0
    except OSError:
        return False


def _normalize_times(path: Path):
    # Windows' os.utime implementation does not accept follow_symlinks on
    # this runtime. Targets are already rejected when they are symlinks.
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
    return stat.S_IMODE(path.lstat().st_mode) == (
        stat.S_IMODE(path.lstat().st_mode) & (stat.S_IRUSR | stat.S_IWUSR)
    )


def _rename(path: Path, token: str):
    if not token or "/" in token or "\\" in token or token in {".", ".."}:
        raise MetadataError("invalid rename token")
    candidate = path.with_name(f".{token}-{secrets.token_hex(8)}")
    if candidate.exists() or candidate.is_symlink():
        raise MetadataError("generated destination already exists")
    path.rename(candidate)
    return candidate


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
        x_seen = x_removed = 0
        x_verified = True
        times_verified = True
        permissions_verified = True
        unsupported = [
            "ctime-is-filesystem-controlled-and-is-not-user-settable",
            "filesystem-journals-snapshots-backups-and-deleted-directory-slack-not-covered",
        ]
        renamed = False
        new_name = None
        targets = list(_targets(path, recursive))

        for item in targets:
            x_seen += len(_list_xattrs(item))
            if clear_xattrs:
                r, u = _clear_xattrs(item)
                x_removed += r
                unsupported.extend(u)
                x_verified = x_verified and _verify_xattrs(item)
            if normalize_times:
                _normalize_times(item)
                times_verified = times_verified and _verify_times(item)
            if normalize_permissions:
                _normalize_permissions(item)
                permissions_verified = permissions_verified and _verify_permissions(item)

        if rename:
            new_path = _rename(path, name_token)
            renamed = True
            new_name = str(new_path)

        requested_ok = (
            (not clear_xattrs or x_verified)
            and (not normalize_times or times_verified)
            and (not normalize_permissions or permissions_verified)
        )
        if not requested_ok:
            raise MetadataError("metadata post-operation verification failed")

        return MetadataResult(
            target=str(path),
            status="SANITIZED",
            xattrs_seen=x_seen,
            xattrs_removed=x_removed,
            xattrs_verified_removed=x_verified if clear_xattrs else True,
            timestamps_normalized=normalize_times,
            timestamps_verified=times_verified if normalize_times else True,
            permissions_normalized=normalize_permissions,
            permissions_verified=permissions_verified if normalize_permissions else True,
            renamed=renamed,
            new_name=new_name,
            recursive=recursive,
            coverage="selected OS-visible metadata only",
            started_utc=started,
            completed_utc=_utc_now(),
            unsupported=unsupported,
        )
    except Exception as exc:
        return MetadataResult(
            target=str(path), status="ERROR",
            xattrs_seen=0, xattrs_removed=0,
            xattrs_verified_removed=False,
            timestamps_normalized=False, timestamps_verified=False,
            permissions_normalized=False, permissions_verified=False,
            renamed=False, new_name=None, recursive=recursive,
            coverage="none",
            started_utc=started, completed_utc=_utc_now(),
            unsupported=[], error=str(exc)
        )


def write_audit(path, result: MetadataResult):
    record = {
        "schema": "secure-erasure.audit.v1",
        "method": "filesystem-metadata-sanitization",
        "created_utc": _utc_now(),
        "result": result.to_dict(),
        "assurance_note": (
            "This method sanitizes only metadata exposed through the selected OS APIs. "
            "It does not claim eradication of filesystem journals, snapshots, backups, "
            "deleted directory-entry slack, NTFS transactional logs, or other historical copies."
        )
    }
    out = Path(path)
    out.parent.mkdir(parents=True, exist_ok=True)
    tmp = out.with_suffix(out.suffix + ".tmp")
    tmp.write_text(json.dumps(record, indent=2, sort_keys=True), encoding="utf-8")
    os.replace(tmp, out)
    return out
