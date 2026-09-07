import json
from pathlib import Path
from storage_aware.cli import main

def make_profile(path):
    d={"path":path,"transport":"nvme","media":"ssd","encrypted":True,
       "crypto_erase":True,"block_erase":True,"overwrite_sanitize":True,
       "ata_secure_erase":False,"scsi_sanitize":False,"vendor_sanitize":False,
       "removable":False,"device_size_bytes":100,"identity":"CLI-TEST"}
    return d

def test_cli_dry_run(tmp_path,capsys):
    path="/dev/test0"
    f=tmp_path/"profile.json"; f.write_text(json.dumps(make_profile(path)))
    assert main([str(f)])==0
    assert "dry-run" in capsys.readouterr().out

def test_cli_confirmation(tmp_path):
    path="/dev/test0"
    f=tmp_path/"profile.json"; f.write_text(json.dumps(make_profile(path)))
    assert main([str(f),"--execute","--confirm","wrong"])==2
