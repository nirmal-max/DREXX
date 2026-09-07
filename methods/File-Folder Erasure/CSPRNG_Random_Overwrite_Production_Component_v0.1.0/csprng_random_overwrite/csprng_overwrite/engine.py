from __future__ import annotations

from dataclasses import dataclass, asdict
from pathlib import Path
import hashlib
import json
import os
import secrets
import stat
import time
from typing import Callable


class CSPRNGOverwriteError(RuntimeError):
    pass


@dataclass(frozen=True)
class ErasureResult:
    target: str
    bytes_overwritten: int
    verified: bool
    removed: bool
    started_utc: str
    completed_utc: str
    sha256_before: str | None
    sha256_after: str | None
    error: str | None = None

    def to_dict(self):
        return asdict(self)


def _utc_now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _validate_regular_file(path: Path) -> None:
    try:
        st = path.lstat()
    except FileNotFoundError as exc:
        raise CSPRNGOverwriteError(f"target does not exist: {path}") from exc
    if stat.S_ISLNK(st.st_mode):
        raise CSPRNGOverwriteError(f"refusing symbolic link: {path}")
    if not stat.S_ISREG(st.st_mode):
        raise CSPRNGOverwriteError(f"target is not a regular file: {path}")


def _hash_file(path: Path, chunk_size: int) -> str:
    h = hashlib.sha256()
    with path.open("rb", buffering=0) as f:
        while True:
            block = f.read(chunk_size)
            if not block:
                break
            h.update(block)
    return h.hexdigest()


def _random_block(size: int) -> bytes:
    return secrets.token_bytes(size)


def _write_all(f, data: bytes) -> None:
    view = memoryview(data)
    offset = 0
    while offset < len(view):
        n = f.write(view[offset:])
        if n is None or n <= 0:
            raise CSPRNGOverwriteError("short write: file write made no progress")
        offset += n


def _clear_readonly(path: Path) -> None:
    mode = path.stat().st_mode
    if not (mode & stat.S_IWUSR):
        path.chmod(mode | stat.S_IWUSR)


def overwrite_file(
    target: str | os.PathLike,
    *,
    verify: bool = True,
    remove: bool = True,
    chunk_size: int = 1024 * 1024,
    progress: Callable[[int, int], None] | None = None,
) -> ErasureResult:
    path = Path(target)
    _validate_regular_file(path)
    if chunk_size <= 0:
        raise ValueError("chunk_size must be positive")
    if remove and not verify:
        raise ValueError("remove=True requires verify=True")

    started = _utc_now()
    before = _hash_file(path, chunk_size)
    total = path.stat().st_size
    written = 0

    try:
        _clear_readonly(path)
        with path.open("r+b", buffering=0) as f:
            remaining = total
            while remaining:
                n = min(remaining, chunk_size)
                _write_all(f, _random_block(n))
                written += n
                remaining -= n
                if progress:
                    progress(written, total)
            f.flush()
            os.fsync(f.fileno())

        current_size = path.stat().st_size
        if current_size != total or written != total:
            raise CSPRNGOverwriteError(
                f"verification failed: expected {total} bytes overwritten, "
                f"wrote {written} and file size is {current_size}"
            )

        after = _hash_file(path, chunk_size) if verify else None
        verified = False
        if verify:
            if total > 0 and after == before:
                raise CSPRNGOverwriteError(
                    "verification failed: post-overwrite SHA-256 equals the original SHA-256"
                )
            verified = True

        if remove:
            if not verified:
                raise CSPRNGOverwriteError("refusing removal without successful verification")
            path.unlink()
            removed = True
        else:
            removed = False

        return ErasureResult(
            target=str(path), bytes_overwritten=written, verified=verified,
            removed=removed, started_utc=started, completed_utc=_utc_now(),
            sha256_before=before, sha256_after=after,
        )
    except Exception as exc:
        return ErasureResult(
            target=str(path), bytes_overwritten=written, verified=False,
            removed=False, started_utc=started, completed_utc=_utc_now(),
            sha256_before=before, sha256_after=None, error=str(exc),
        )


def _safe_tree(root: Path) -> list[Path]:
    if root.is_symlink():
        raise CSPRNGOverwriteError(f"refusing symbolic-link root: {root}")
    if not root.is_dir():
        raise CSPRNGOverwriteError(f"target is not a directory: {root}")
    return sorted(p for p in root.rglob("*") if not p.is_symlink() and p.is_file())


def overwrite_tree(
    target: str | os.PathLike,
    *, verify: bool = True, remove: bool = True,
    chunk_size: int = 1024 * 1024,
) -> list[ErasureResult]:
    root = Path(target)
    results = [
        overwrite_file(p, verify=verify, remove=remove, chunk_size=chunk_size)
        for p in _safe_tree(root)
    ]
    if remove and all(r.error is None and r.removed for r in results):
        for d in sorted(
            (p for p in root.rglob("*") if p.is_dir() and not p.is_symlink()),
            reverse=True,
        ):
            try:
                d.rmdir()
            except OSError:
                pass
        try:
            root.rmdir()
        except OSError:
            pass
    return results


def write_audit(path: str | os.PathLike, results: list[ErasureResult]):
    record = {
        "schema": "secure-erasure.audit.v1",
        "method": "csprng-random-overwrite",
        "random_source": "OS CSPRNG via Python secrets.token_bytes",
        "created_utc": _utc_now(),
        "results": [r.to_dict() for r in results],
    }
    out = Path(path)
    out.parent.mkdir(parents=True, exist_ok=True)
    tmp = out.with_suffix(out.suffix + ".tmp")
    tmp.write_text(json.dumps(record, indent=2, sort_keys=True), encoding="utf-8")
    os.replace(tmp, out)
    return out
