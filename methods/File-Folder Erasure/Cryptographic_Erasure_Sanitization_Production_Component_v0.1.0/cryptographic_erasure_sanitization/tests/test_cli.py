from crypto_eraser.cli import main

def test_cli_confirmation(tmp_path):
    assert main(["destroy-key","k","--store",str(tmp_path),"--execute","--confirm","wrong","--verify"])==2

def test_cli_dry_run(tmp_path,capsys):
    assert main(["destroy-key","k","--store",str(tmp_path)])==0
    assert "dry-run" in capsys.readouterr().out

def test_cli_lifecycle(tmp_path):
    store=str(tmp_path/"keys")
    assert main(["create-key","k","--store",store])==0
    assert main(["destroy-key","k","--store",store,"--execute","--confirm","k","--verify"])==0
