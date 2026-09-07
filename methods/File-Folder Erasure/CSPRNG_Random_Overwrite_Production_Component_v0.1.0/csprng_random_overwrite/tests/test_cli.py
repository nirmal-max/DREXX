from csprng_overwrite.cli import main


def test_cli_dry_run(tmp_path, capsys):
    p = tmp_path / "x"
    p.write_bytes(b"secret")
    assert main([str(p)]) == 0
    assert p.read_bytes() == b"secret"
    assert "dry-run" in capsys.readouterr().out


def test_cli_requires_exact_confirmation(tmp_path):
    p = tmp_path / "x"
    p.write_bytes(b"secret")
    assert main([str(p), "--execute", "--verify", "--confirm", "wrong"]) == 2
    assert p.read_bytes() == b"secret"


def test_cli_requires_verify_for_destructive_execution(tmp_path, capsys):
    p = tmp_path / "x"
    original = b"secret"
    p.write_bytes(original)
    assert main([str(p), "--execute", "--confirm", str(p)]) == 2
    assert p.read_bytes() == original
    assert "--verify is required" in capsys.readouterr().err


def test_cli_executes(tmp_path):
    p = tmp_path / "x"
    p.write_bytes(b"secret")
    assert main([str(p), "--execute", "--confirm", str(p), "--verify"]) == 0
    assert not p.exists()


def test_cli_audit_write_failure_is_reported(tmp_path, monkeypatch, capsys):
    p = tmp_path / "x"
    p.write_bytes(b"secret")
    audit = tmp_path / "audit.json"

    def fail_audit(*args, **kwargs):
        raise OSError("audit unavailable")

    monkeypatch.setattr("csprng_overwrite.cli.write_audit", fail_audit)
    assert main([
        str(p), "--execute", "--confirm", str(p), "--verify", "--audit", str(audit)
    ]) == 2
    assert "failed to write audit record" in capsys.readouterr().err
