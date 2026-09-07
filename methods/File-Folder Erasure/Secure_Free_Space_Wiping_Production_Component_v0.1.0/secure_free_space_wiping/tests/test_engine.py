import os
import errno
from pathlib import Path
import pytest
from free_space_wiper.engine import wipe_free_space, WipeError, write_audit


class FakeBackend:
    def __init__(self, capacity):
        self.capacity = capacity
        self.used = 0
        self.files = {}
        self.counter = 0

    def allocate_and_fill(self, directory, size, pattern, chunk_size):
        if size > self.capacity - self.used:
            raise OSError(errno.ENOSPC, "ENOSPC")
        self.counter += 1
        p = directory / f"fake-{self.counter}"
        if pattern == "zero":
            data = b"\x00" * size
        else:
            data = os.urandom(size)
        self.files[p] = data
        p.write_bytes(data)
        self.used += size
        return p, size

    def remove(self, path):
        data = self.files.pop(path)
        try:
            path.unlink()
        except FileNotFoundError:
            pass
        self.used -= len(data)


def test_bounded_zero_free_space_wipe(tmp_path, monkeypatch):
    b = FakeBackend(1024 * 1024)
    monkeypatch.setattr("free_space_wiper.engine.estimate_free_space", lambda _: b.capacity - b.used)
    r = wipe_free_space(
        tmp_path, pattern="zero", reserve_bytes=256 * 1024,
        chunk_size=64 * 1024, min_chunk_size=4096, backend=b, verify=True
    )
    assert r.error is None
    assert r.verified
    assert r.cleaned_up
    assert r.bytes_written > 0
    assert b.used == 0


def test_bounded_random_free_space_wipe(tmp_path, monkeypatch):
    b = FakeBackend(512 * 1024)
    monkeypatch.setattr("free_space_wiper.engine.estimate_free_space", lambda _: b.capacity - b.used)
    r = wipe_free_space(
        tmp_path, pattern="random", reserve_bytes=64 * 1024,
        chunk_size=32 * 1024, min_chunk_size=4096, backend=b, verify=True
    )
    assert r.error is None
    assert r.verified
    assert r.cleaned_up
    assert b.used == 0


def test_reserve_larger_than_capacity_does_nothing(tmp_path, monkeypatch):
    b = FakeBackend(1000)
    monkeypatch.setattr("free_space_wiper.engine.estimate_free_space", lambda _: b.capacity - b.used)
    r = wipe_free_space(
        tmp_path, reserve_bytes=2000, backend=b, verify=True
    )
    assert r.error is None
    assert r.bytes_written == 0
    assert r.cleaned_up


def test_invalid_pattern(tmp_path):
    with pytest.raises(ValueError):
        wipe_free_space(tmp_path, pattern="bad")


def test_negative_reserve(tmp_path):
    with pytest.raises(ValueError):
        wipe_free_space(tmp_path, reserve_bytes=-1)


def test_symlink_target_refused(tmp_path):
    target = tmp_path / "real"
    target.mkdir()
    link = tmp_path / "link"
    link.symlink_to(target, target_is_directory=True)
    with pytest.raises(WipeError):
        wipe_free_space(link)


def test_file_target_refused(tmp_path):
    p = tmp_path / "file"
    p.write_bytes(b"x")
    with pytest.raises(WipeError):
        wipe_free_space(p)


def test_cleanup_on_backend_failure(tmp_path):
    class BrokenBackend(FakeBackend):
        def allocate_and_fill(self, directory, size, pattern, chunk_size):
            raise OSError("simulated failure")
    r = wipe_free_space(
        tmp_path, reserve_bytes=0, chunk_size=4096,
        min_chunk_size=4096, backend=BrokenBackend(10000)
    )
    assert r.error is not None
    assert r.cleaned_up
    assert r.bytes_written == 0


def test_audit(tmp_path):
    b = FakeBackend(20000)
    r = wipe_free_space(
        tmp_path, reserve_bytes=1000, chunk_size=4096,
        min_chunk_size=4096, backend=b
    )
    out = write_audit(tmp_path / "audit.json", r)
    assert out.exists()
    assert "secure-free-space-wiping" in out.read_text()


def test_real_backend_bounded_file(tmp_path):
    from free_space_wiper.engine import RealAllocationBackend
    backend = RealAllocationBackend()
    p, n = backend.allocate_and_fill(tmp_path, 4096, "zero", 1024)
    assert n == 4096
    assert p.stat().st_size == 4096
    assert p.read_bytes() == b"\x00" * 4096
    backend.remove(p)
    assert not p.exists()
