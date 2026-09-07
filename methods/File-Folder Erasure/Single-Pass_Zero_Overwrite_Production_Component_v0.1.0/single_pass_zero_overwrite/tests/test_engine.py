from pathlib import Path
import json
import os
import stat
import pytest

from zero_overwrite import overwrite_file, overwrite_tree, OverwriteError
from zero_overwrite.engine import write_audit


def test_zero_overwrite_and_remove(tmp_path):
    p = tmp_path / "secret.bin"
    p.write_bytes(b"secret\x00payload" * 100)
    result = overwrite_file(p, verify=True, remove=True)
    assert result.error is None
    assert result.verified is True
    assert result.removed is True
    assert result.bytes_overwritten > 0
    assert not p.exists()


def test_zero_overwrite_keep_file(tmp_path):
    p = tmp_path / "keep.bin"
    p.write_bytes(os.urandom(8193))
    result = overwrite_file(p, verify=True, remove=False)
    assert result.error is None
    assert result.verified is True
    assert p.exists()
    assert p.read_bytes() == b"\x00" * 8193


def test_empty_file(tmp_path):
    p = tmp_path / "empty"
    p.write_bytes(b"")
    result = overwrite_file(p, verify=True, remove=False)
    assert result.error is None
    assert result.bytes_overwritten == 0
    assert result.verified is True
    assert p.read_bytes() == b""


def test_refuses_symlink(tmp_path):
    target = tmp_path / "target"
    target.write_bytes(b"do not touch")
    link = tmp_path / "link"
    link.symlink_to(target)
    with pytest.raises(OverwriteError):
        overwrite_file(link)


def test_refuses_directory_as_file(tmp_path):
    with pytest.raises(OverwriteError):
        overwrite_file(tmp_path)


def test_readonly_file_is_handled(tmp_path):
    p = tmp_path / "readonly"
    p.write_bytes(b"abc")
    p.chmod(stat.S_IRUSR)
    result = overwrite_file(p, verify=True, remove=False)
    assert result.error is None
    assert p.read_bytes() == b"\x00\x00\x00"


def test_tree_processes_nested_regular_files(tmp_path):
    root = tmp_path / "tree"
    nested = root / "a" / "b"
    nested.mkdir(parents=True)
    f1 = root / "one"
    f2 = nested / "two"
    f1.write_bytes(b"1111")
    f2.write_bytes(b"222222")
    results = overwrite_tree(root, verify=True, remove=True)
    assert len(results) == 2
    assert all(r.verified for r in results)
    assert not root.exists()


def test_tree_does_not_follow_symlink(tmp_path):
    root = tmp_path / "tree"
    root.mkdir()
    outside = tmp_path / "outside"
    outside.write_bytes(b"KEEP")
    (root / "link").symlink_to(outside)
    results = overwrite_tree(root, verify=True, remove=True)
    assert outside.read_bytes() == b"KEEP"
    assert results == []


def test_audit_is_valid_json(tmp_path):
    p = tmp_path / "x"
    p.write_bytes(b"secret")
    result = overwrite_file(p, verify=True, remove=False)
    out = write_audit(tmp_path / "audit.json", [result])
    record = json.loads(out.read_text())
    assert record["method"] == "single-pass-zero-overwrite"
    assert record["results"][0]["verified"] is True


def test_chunk_size_validation(tmp_path):
    p = tmp_path / "x"
    p.write_bytes(b"x")
    with pytest.raises(ValueError):
        overwrite_file(p, chunk_size=0)
