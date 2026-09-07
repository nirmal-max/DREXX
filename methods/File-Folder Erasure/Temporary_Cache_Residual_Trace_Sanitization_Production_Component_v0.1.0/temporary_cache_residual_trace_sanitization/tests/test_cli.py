from trace_sanitizer.cli import main

def test_cli_dry_run(tmp_path,capsys):
    d=tmp_path/"cache"; d.mkdir(); (d/"x").write_text("x")
    assert main([str(d)])==0
    assert "dry-run" in capsys.readouterr().out

def test_cli_confirmation(tmp_path):
    d=tmp_path/"cache"; d.mkdir()
    assert main([str(d),"--execute","--confirm","wrong"])==2

def test_cli_execute(tmp_path):
    d=tmp_path/"cache"; d.mkdir(); (d/"x").write_text("x")
    assert main([str(d),"--execute","--confirm",str(d),"--verify"])==0
