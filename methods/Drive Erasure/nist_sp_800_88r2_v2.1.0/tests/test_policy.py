import sys
sys.path.insert(0,"src")
from nist.models import Device
from nist.policy import plan
def D(**kw):
    x=Device("/dev/test","HDD",size_bytes=100,capabilities={}); return Device(x.path,kw.get("media_type",x.media_type),size_bytes=kw.get("size_bytes",100),mounted=kw.get("mounted",False),system_disk=kw.get("system_disk",False),capabilities=kw.get("capabilities",{}))
def test_mount_block(): assert plan(D(mounted=True)).outcome=="BLOCKED"
def test_system_block(): assert plan(D(system_disk=True)).outcome=="BLOCKED"
