import sys; sys.path.insert(0,"src")
from ieee.models import Device
from ieee.policy import plan
def test_ready_special():
 d=Device("/dev/x","HDD",size_bytes=100,capabilities={"native_sanitize":True,"purge_qualified":True,"crypto_erase":True,"key_management_qualified":True,"nvme_sanitize":True,"block_erase":True,"ata_secure_erase":True,"ata_sanitize":True,"enhanced":True,"scsi_sanitize":True,"destruction_equipment_qualified":True,"qualified_media":["HDD"]})
 assert plan(d).outcome in ("PLANNED","BLOCKED")
