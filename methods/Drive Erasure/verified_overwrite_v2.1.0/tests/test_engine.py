import sys; sys.path.insert(0,"src")
from overwrite.adapter import execute_file
def test_virtual_disk(tmp_path):
 p=tmp_path/"disk.img"; p.write_bytes(b"X"*8192); r=execute_file(str(p),("zero",)); assert r[0]["write_sha256"]==r[0]["readback_sha256"]; assert p.read_bytes()==b"\0"*8192
