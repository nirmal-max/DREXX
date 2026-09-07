import sys; sys.path.insert(0,"src")
from overwrite.simulation import VirtualDisk
from overwrite.adapter import execute_file
def test_virtual_disk_full_verification(tmp_path):
 d=VirtualDisk(tmp_path/"disk.img",16384); r=execute_file(str(d.path),("zero",)); assert r[0]["write_sha256"]==r[0]["readback_sha256"] and d.verify_zero()
def test_corruption_is_detectable(tmp_path):
 d=VirtualDisk(tmp_path/"disk.img",4096); execute_file(str(d.path),("zero",)); d.corrupt(0); assert not d.verify_zero()
