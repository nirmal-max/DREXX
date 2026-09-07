from slack_sanitizer.cli import main

def test_cli_dry_run(tmp_path,capsys):
    p=tmp_path/"x"; p.write_bytes(b"x")
    assert main([str(p)])==0
    assert "dry-run" in capsys.readouterr().out

def test_cli_confirmation(tmp_path):
    p=tmp_path/"x"; p.write_bytes(b"x")
    assert main([str(p),"--execute","--confirm","wrong"])==2

def test_cli_synthetic_execution(tmp_path):
    p=tmp_path/"x"; p.write_bytes(b"x"*100)
    assert main([str(p),"--execute","--confirm",str(p),"--synthetic-backend","--verify"])==0
