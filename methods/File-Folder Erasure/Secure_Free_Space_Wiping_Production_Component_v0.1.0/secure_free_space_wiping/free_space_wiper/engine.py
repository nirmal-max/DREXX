from __future__ import annotations
from dataclasses import dataclass, asdict
from pathlib import Path
import errno
import json
import os
import secrets
import shutil
import stat
import time
from typing import Callable, Protocol


class WipeError(RuntimeError):
    pass


@dataclass(frozen=True)
class WipeResult:
    target: str
    pattern: str
    files_created: int
    bytes_allocated: int
    bytes_written: int
    verified: bool
    cleaned_up: bool
    started_utc: str
    completed_utc: str
    error: str | None = None

    def to_dict(self):
        return asdict(self)


def _utc_now():
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _validate_target(path: Path):
    if not path.exists():
        raise WipeError(f"target does not exist: {path}")
    if path.is_symlink():
        raise WipeError(f"refusing symbolic-link target: {path}")
    if not path.is_dir():
        raise WipeError(f"target must be a directory/mount point: {path}")
    if path.parent == path:
        raise WipeError("refusing filesystem root target")


def estimate_free_space(path: str | os.PathLike) -> int:
    # os.statvfs is POSIX-only. shutil.disk_usage is available on Windows and POSIX
    # and reports filesystem capacity for an explicitly selected path.
    try:
        return shutil.disk_usage(path).free
    except (AttributeError, OSError):
        if hasattr(os, "statvfs"):
            st = os.statvfs(path)
            return st.f_bavail * st.f_frsize
        raise WipeError(f"cannot determine free space for: {path}")


class AllocationBackend(Protocol):
    def allocate_and_fill(self, directory: Path, size: int, pattern: str, chunk_size: int) -> tuple[Path, int]: ...
    def remove(self, path: Path) -> None: ...


def _write_all(f, data: bytes) -> int:
    total = 0
    view = memoryview(data)
    while total < len(view):
        n = f.write(view[total:])
        if n is None or n <= 0:
            raise OSError("short write while creating free-space filler")
        total += n
    return total


class RealAllocationBackend:
    def allocate_and_fill(self, directory: Path, size: int, pattern: str, chunk_size: int):
        if size <= 0:
            raise ValueError("size must be positive")
        if chunk_size <= 0:
            raise ValueError("chunk_size must be positive")
        name = f".sanitization-free-space-{os.getpid()}-{secrets.token_hex(8)}"
        path = directory / name
        written = 0
        try:
            with path.open("xb", buffering=0) as f:
                while written < size:
                    n = min(chunk_size, size - written)
                    if pattern == "zero":
                        block = b"\x00" * n
                    elif pattern == "random":
                        block = secrets.token_bytes(n)
                    else:
                        raise ValueError(f"unsupported pattern: {pattern}")
                    written += _write_all(f, block)
                f.flush()
                os.fsync(f.fileno())
            if path.stat().st_size != size:
                raise WipeError(f"filler size mismatch: expected {size}, got {path.stat().st_size}")
            return path, written
        except Exception:
            try:
                path.unlink()
            except OSError:
                pass
            raise

    def remove(self, path: Path):
        path.unlink()


def _verify_file(path: Path, pattern: str, chunk_size: int, expected_size: int | None = None) -> bool:
    size = path.stat().st_size
    if expected_size is not None and size != expected_size:
        return False
    with path.open("rb", buffering=0) as f:
        while True:
            b = f.read(chunk_size)
            if not b:
                return True
            if pattern == "zero":
                if any(b):
                    return False
            elif pattern == "random":
                # Random bytes cannot be compared to a regenerated value. A complete
                # read plus exact size check verifies the persisted filler object, not
                # the physical storage layer.
                continue
            else:
                raise ValueError(f"unsupported pattern: {pattern}")


def wipe_free_space(
    target: str | os.PathLike,
    *,
    pattern: str = "zero",
    reserve_bytes: int = 64 * 1024 * 1024,
    chunk_size: int = 1024 * 1024,
    min_chunk_size: int = 4096,
    verify: bool = True,
    backend: AllocationBackend | None = None,
    progress: Callable[[int, int], None] | None = None,
) -> WipeResult:
    directory = Path(target)
    _validate_target(directory)
    if pattern not in {"zero", "random"}:
        raise ValueError("pattern must be 'zero' or 'random'")
    if reserve_bytes < 0:
        raise ValueError("reserve_bytes must be non-negative")
    if chunk_size <= 0 or min_chunk_size <= 0:
        raise ValueError("chunk sizes must be positive")

    backend = backend or RealAllocationBackend()
    started = _utc_now()
    created: list[tuple[Path, int]] = []
    allocated = written = 0

    try:
        initial_free = estimate_free_space(directory)
        target_bytes = max(0, initial_free - reserve_bytes)
        remaining = target_bytes
        allocation_size = min(max(chunk_size * 16, 16 * 1024 * 1024), remaining)

        while remaining >= min_chunk_size:
            current_free = estimate_free_space(directory)
            allowed = max(0, current_free - reserve_bytes)
            if allowed < min_chunk_size:
                break
            size = min(allocation_size, allowed, remaining)
            if size < min_chunk_size:
                break
            try:
                p, n = backend.allocate_and_fill(directory, size, pattern, chunk_size)
                if n <= 0 or n != size:
                    raise WipeError(f"allocator returned invalid byte count: {n} for {size}")
                created.append((p, n))
                allocated += n
                written += n
                remaining -= n
                if progress:
                    progress(allocated, target_bytes)
                allocation_size = min(max(allocation_size * 2, min_chunk_size), 256 * 1024 * 1024)
            except OSError as exc:
                if exc.errno == errno.ENOSPC:
                    if allocation_size > min_chunk_size:
                        allocation_size = max(min_chunk_size, allocation_size // 2)
                        continue
                    break
                raise

        verified = True
        if verify:
            for p, n in created:
                if not _verify_file(p, pattern, chunk_size, n):
                    raise WipeError(f"verification failed for filler file: {p}")

        for p, _ in created:
            backend.remove(p)

        return WipeResult(str(directory), pattern, len(created), allocated, written,
                          verified, True, started, _utc_now())
    except Exception as exc:
        cleanup_ok = True
        for p, _ in created:
            try:
                backend.remove(p)
            except OSError:
                cleanup_ok = False
        return WipeResult(str(directory), pattern, len(created), allocated, written,
                          False, cleanup_ok, started, _utc_now(), str(exc))


def write_audit(path: str | os.PathLike, result: WipeResult):
    record = {
        "schema": "secure-erasure.audit.v1",
        "method": "secure-free-space-wiping",
        "created_utc": _utc_now(),
        "result": result.to_dict(),
        "assurance_note": "Allocation-based logical free-space sanitization; not a universal physical purge."
    }
    out = Path(path)
    out.parent.mkdir(parents=True, exist_ok=True)
    tmp = out.with_suffix(out.suffix + ".tmp")
    tmp.write_text(json.dumps(record, indent=2, sort_keys=True), encoding="utf-8")
    os.replace(tmp, out)
    return out
