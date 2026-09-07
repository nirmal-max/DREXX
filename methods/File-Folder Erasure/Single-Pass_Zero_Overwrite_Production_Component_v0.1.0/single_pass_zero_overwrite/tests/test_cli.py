import json
from pathlib import Path
from zero_overwrite.cli import main


def test_cli_defaults_to_dry_run(tmp_path, capsys):
    p = tmp_path / "x"
    p.write_bytes(b"secret")
    assert main([str(p)]) == 0
    assert p.read_bytes() == b"secret"
    assert "dry-run" in capsys.readouterr().out


def test_cli_requires_exact_confirmation(tmp_path, capsys):
    p = tmp_path / "x"
    p.write_bytes(b"secret")
    assert main([str(p), "--execute", "--confirm", "wrong"]) == 2
    assert p.read_bytes() == b"secret"


def test_cli_executes_with_confirmation(tmp_path):
    p = tmp_path / "x"
    p.write_bytes(b"secret")
    assert main([str(p), "--execute", "--confirm", str(p), "--verify"]) == 0
    assert not p.exists()
