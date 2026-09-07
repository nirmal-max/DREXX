from metadata_sanitizer.cli import main

def test_dry_run(tmp_path,capsys):
    p=tmp_path/"x"; p.write_text("x")
    assert main([str(p)])==0
    assert "dry-run" in capsys.readouterr().out

def test_confirmation(tmp_path):
    p=tmp_path/"x"; p.write_text("x")
    assert main([str(p),"--execute","--confirm","wrong","--normalize-times"])==2

def test_execute(tmp_path):
    p=tmp_path/"x"; p.write_text("x")
    assert main([str(p),"--execute","--confirm",str(p),"--normalize-times"])==0
