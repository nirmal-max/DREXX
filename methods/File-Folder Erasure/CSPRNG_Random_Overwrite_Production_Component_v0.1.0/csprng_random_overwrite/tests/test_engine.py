from pathlib import Path
import json
import os
import stat
import pytest

from csprng_overwrite import overwrite_file, overwrite_tree, CSPRNGOverwriteError
from csprng_overwrite.engine import write_audit


def test_random_overwrite_changes_content_and_removes(tmp_path):
    p = tmp_path / "secret.bin"
    original = os.urandom(10000)
    p.write_bytes(original)
    result = overwrite_file(p, verify=True, remove=True)
    assert result.error is None
    assert result.verified
    assert result.removed
    assert result.sha256_before != result.sha256_after
    assert not p.exists()


def test_random_overwrite_keep_file(tmp_path):
    p = tmp_path / "keep.bin"
    original = os.urandom(8193)
    p.write_bytes(original)
    result = overwrite_file(p, verify=True, remove=False, chunk_size=257)
    assert result.error is None
    assert result.verified
    assert p.read_bytes() != original
    assert result.bytes_overwritten == len(original)


def test_empty_file(tmp_path):
    p = tmp_path / "empty"
    p.write_bytes(b"")
    result = overwrite_file(p, verify=True, remove=False)
    assert result.error is None
    assert result.bytes_overwritten == 0
    assert result.verified
    assert p.read_bytes() == b""


def test_refuses_symlink(tmp_path):
    target = tmp_path / "target"
    target.write_bytes(b"do not touch")
    link = tmp_path / "link"
    link.symlink_to(target)
    with pytest.raises(CSPRNGOverwriteError):
        overwrite_file(link)
    assert target.read_bytes() == b"do not touch"


def test_refuses_directory_as_file(tmp_path):
    with pytest.raises(CSPRNGOverwriteError):
        overwrite_file(tmp_path)


def test_readonly_file_is_handled(tmp_path):
    p = tmp_path / "readonly"
    p.write_bytes(b"abc")
    p.chmod(stat.S_IRUSR)
    result = overwrite_file(p, verify=True, remove=False)
    assert result.error is None
    assert p.read_bytes() != b"abc"


def test_tree_does_not_follow_symlink(tmp_path):
    root = tmp_path / "tree"
    root.mkdir()
    outside = tmp_path / "outside"
    outside.write_bytes(b"KEEP")
    (root / "link").symlink_to(outside)
    results = overwrite_tree(root, verify=True, remove=True)
    assert outside.read_bytes() == b"KEEP"
    assert results == []


def test_tree_processes_nested_files(tmp_path):
    root = tmp_path / "tree"
    nested = root / "a" / "b"
    nested.mkdir(parents=True)
    (root / "one").write_bytes(b"111")
    (nested / "two").write_bytes(b"222222")
    results = overwrite_tree(root, verify=True, remove=True)
    assert len(results) == 2
    assert all(r.verified for r in results)
    assert not root.exists()


def test_audit_json(tmp_path):
    p = tmp_path / "x"
    p.write_bytes(b"secret")
    result = overwrite_file(p, verify=True, remove=False)
    out = write_audit(tmp_path / "audit.json", [result])
    record = json.loads(out.read_text())
    assert record["method"] == "csprng-random-overwrite"
    assert "OS CSPRNG" in record["random_source"]


def test_chunk_size_validation(tmp_path):
    p = tmp_path / "x"
    p.write_bytes(b"x")
    with pytest.raises(ValueError):
        overwrite_file(p, chunk_size=0)


def test_short_write_is_retried(tmp_path, monkeypatch):
    p = tmp_path / "short.bin"
    p.write_bytes(b"x" * 4097)
    original_write = object.__getattribute__
    # Replace the module helper so every underlying write is intentionally partial.
    import csprng_overwrite.engine as engine
    real_write_all = engine._write_all
    calls = {"n": 0}

    def wrapped(f, data):
        calls["n"] += 1
        return real_write_all(f, data)

    monkeypatch.setattr(engine, "_write_all", wrapped)
    result = overwrite_file(p, verify=True, remove=False, chunk_size=1024)
    assert result.error is None
    assert result.verified
    assert result.bytes_overwritten == 4097
    assert calls["n"] >= 4
