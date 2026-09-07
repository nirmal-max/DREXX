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
    timestamps_normalized: bool
    permissions_normalized: bool
    renamed: bool
    new_name: str | None
    recursive: bool
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


def _normalize_times(path: Path):
    # The target has already been rejected as a symlink. Some Windows Python builds
    # expose os.utime but do not implement its follow_symlinks keyword. In that case,
    # use the portable two-argument form; the prior validation makes this safe here.
    try:
        os.utime(path, ns=(0, 0), follow_symlinks=False)
    except (NotImplementedError, TypeError, ValueError, OSError) as exc:
        try:
            os.utime(path, ns=(0, 0))
        except OSError as fallback_exc:
            raise MetadataError(f"timestamp normalization failed: {fallback_exc}") from exc

    st = path.lstat()
    if st.st_atime_ns != 0 or st.st_mtime_ns != 0:
        raise MetadataError("timestamp normalization could not be verified")


def _normalize_permissions(path: Path):
    if os.name == "nt":
        raise MetadataError("permission normalization is not supported by this backend")
    mode = stat.S_IMODE(path.lstat().st_mode)
    os.chmod(path, mode & stat.S_IRUSR | stat.S_IWUSR, follow_symlinks=False)

    verified = stat.S_IMODE(path.lstat().st_mode)
    if verified != (mode & stat.S_IRUSR | stat.S_IWUSR):
        raise MetadataError("permission normalization could not be verified")


def _rename(path: Path, token: str):
    if not token or "/" in token or "\\" in token or token in {".", ".."}:
        raise MetadataError("invalid rename token")
    candidate = path.with_name(f".{token}-{secrets.token_hex(8)}")
    if candidate.exists() or candidate.is_symlink():
        raise MetadataError("generated destination already exists")
    path.rename(candidate)
    if not candidate.exists() or candidate.is_symlink():
        raise MetadataError("rename could not be verified")
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
    path=Path(target)
    started=_utc_now()
    try:
        _validate(path)
        x_seen=x_removed=0
        unsupported=[]
        renamed=False
        new_name=None
        targets=list(_targets(path, recursive))

        for item in targets:
            x_seen += len(_list_xattrs(item))
            if clear_xattrs:
                r,u=_clear_xattrs(item)
                x_removed += r
                unsupported.extend(u)
            if normalize_times:
                _normalize_times(item)
            if normalize_permissions:
                _normalize_permissions(item)

        if rename:
            new_path=_rename(path, name_token)
            renamed=True
            new_name=str(new_path)

        return MetadataResult(
            target=str(path), status="SANITIZED",
            xattrs_seen=x_seen, xattrs_removed=x_removed,
            timestamps_normalized=normalize_times,
            permissions_normalized=normalize_permissions,
            renamed=renamed, new_name=new_name, recursive=recursive,
            started_utc=started, completed_utc=_utc_now(),
            unsupported=unsupported
        )
    except Exception as exc:
        return MetadataResult(
            target=str(path), status="ERROR",
            xattrs_seen=0, xattrs_removed=0,
            timestamps_normalized=False, permissions_normalized=False,
            renamed=False, new_name=None, recursive=recursive,
            started_utc=started, completed_utc=_utc_now(),
            unsupported=[],
            error=str(exc)
        )


def write_audit(path, result: MetadataResult):
    record={
        "schema":"secure-erasure.audit.v1",
        "method":"filesystem-metadata-sanitization",
        "created_utc":_utc_now(),
        "result":result.to_dict(),
        "assurance_note":(
            "Only metadata exposed through the selected OS APIs is covered. "
            "Filesystem journals, deleted directory-entry slack, snapshots, backups "
            "and other historical copies require filesystem-specific handling."
        )
    }
    out=Path(path)
    out.parent.mkdir(parents=True,exist_ok=True)
    tmp=out.with_suffix(out.suffix+".tmp")
    tmp.write_text(json.dumps(record,indent=2,sort_keys=True),encoding="utf-8")
    os.replace(tmp,out)
    return out
