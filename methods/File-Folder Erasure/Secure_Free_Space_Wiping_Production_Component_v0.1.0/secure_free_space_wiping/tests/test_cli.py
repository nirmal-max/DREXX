from free_space_wiper.cli import main


def test_cli_dry_run(tmp_path, capsys):
    assert main([str(tmp_path)]) == 0
    out = capsys.readouterr().out
    assert "dry-run" in out


def test_cli_confirmation_required(tmp_path):
    assert main([str(tmp_path), "--execute", "--confirm", "wrong"]) == 2
