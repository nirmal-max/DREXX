from pathlib import Path

from single_pass_zero_overwrite.zero_overwrite.cli import main


def test_execute_requires_verify(tmp_path, capsys):
    target = tmp_path / "target.bin"
    target.write_bytes(b"secret")

    rc = main([str(target), "--execute", "--confirm", str(target)])

    assert rc == 2
    assert target.read_bytes() == b"secret"
    assert "--verify is required" in capsys.readouterr().err


def test_execute_with_verify_can_remove(tmp_path):
    target = tmp_path / "target.bin"
    target.write_bytes(b"secret")

    rc = main([str(target), "--execute", "--confirm", str(target), "--verify"])

    assert rc == 0
    assert not target.exists()


def test_keep_with_verify_retains_zeroed_file(tmp_path):
    target = tmp_path / "target.bin"
    target.write_bytes(b"secret")

    rc = main([str(target), "--execute", "--confirm", str(target), "--verify", "--keep"])

    assert rc == 0
    assert target.exists()
    assert target.read_bytes() == b"\x00" * 6
