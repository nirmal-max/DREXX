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
    while view:
        n = f.write(view)
        if n is None or n <= 0:
            raise CSPRNGOverwriteError("short write while overwriting target")
        view = view[n:]


def _clear_readonly(path: Path) -> None:
    mode = path.stat().st_mode
    if not (mode & stat.S_IWUSR):
        path.chmod(mode | stat.S_IWUSR)


def _fsync_directory(path: Path) -> None:
    # Directory fsync makes the unlink durable on filesystems that support it.
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    except (OSError, AttributeError):
        return
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


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

    started = _utc_now()
    before = _hash_file(path, chunk_size)
    total = path.stat().st_size
    written = 0

    try:
        _clear_readonly(path)
        with path.open("r+b", buffering=0) as f:
            offset = 0
            while offset < total:
                n = min(chunk_size, total - offset)
                data = _random_block(n)
                f.seek(offset)
                _write_all(f, data)
                if verify:
                    f.seek(offset)
                    got = f.read(n)
                    if got != data:
                        raise CSPRNGOverwriteError(
                            f"read-back mismatch at offset {offset}"
                        )
                offset += n
                written += n
                if progress:
                    progress(written, total)
            f.flush()
            os.fsync(f.fileno())

        after = _hash_file(path, chunk_size) if verify else None
        if verify and total > 0 and after == before:
            raise CSPRNGOverwriteError(
                "verification failed: post-overwrite SHA-256 equals original SHA-256"
            )
        verified = bool(verify)

        if remove:
            path.unlink()
            _fsync_directory(path.parent)
            removed = True
        else:
            removed = False

        return ErasureResult(
            target=str(path),
            bytes_overwritten=written,
            verified=verified,
            removed=removed,
            started_utc=started,
            completed_utc=_utc_now(),
            sha256_before=before,
            sha256_after=after,
        )
    except Exception as exc:
        return ErasureResult(
            target=str(path),
            bytes_overwritten=written,
            verified=False,
            removed=False,
            started_utc=started,
            completed_utc=_utc_now(),
            sha256_before=before,
            sha256_after=None,
            error=str(exc),
        )


def _safe_tree(root: Path) -> list[Path]:
    if root.is_symlink():
        raise CSPRNGOverwriteError(f"refusing symbolic-link root: {root}")
    if not root.is_dir():
        raise CSPRNGOverwriteError(f"target is not a directory: {root}")
    files = []
    for p in root.rglob("*"):
        if p.is_symlink():
            continue
        if p.is_file():
            files.append(p)
    return sorted(files)


def overwrite_tree(
    target: str | os.PathLike,
    *,
    verify: bool = True,
    remove: bool = True,
    chunk_size: int = 1024 * 1024,
) -> list[ErasureResult]:
    root = Path(target)
    results = []
    for p in _safe_tree(root):
        results.append(
            overwrite_file(p, verify=verify, remove=remove, chunk_size=chunk_size)
        )

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
            _fsync_directory(root.parent)
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
