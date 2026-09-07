from .models import Plan,Device
MODULE='Device-Native Sanitize'
def validate(d):
    if d.mounted: return Plan(MODULE,"BLOCKED","NONE","NONE","Target is mounted; offline execution required.",warnings=("mounted_target",))
    if d.system_disk: return Plan(MODULE,"BLOCKED","NONE","NONE","Current system disk is protected.",warnings=("system_disk",))
    if d.size_bytes<0: return Plan(MODULE,"BLOCKED","NONE","NONE","Invalid capacity.")
    return None

def plan(d,requested="best"):
    bad=validate(d)
    if bad: return bad
    c=d.caps(); m=d.media_type.upper()
    if m=="NVME" and c.get("nvme_sanitize"): return Plan(MODULE,"PLANNED","NVME_SANITIZE","PURGE","NVMe Sanitize capability detected.",("nvme sanitize",),("sanitize-log",))
    if m in ("SATA","HDD","SSD") and c.get("ata_sanitize"): return Plan(MODULE,"PLANNED","ATA_SANITIZE","PURGE","ATA Sanitize capability detected.",("ATA Sanitize",),("device status",))
    if m in ("SAS","SCSI") and c.get("scsi_sanitize"): return Plan(MODULE,"PLANNED","SCSI_SANITIZE","PURGE","SCSI/SAS Sanitize capability detected.",("SCSI sanitize",),("sense/status",))
    return Plan(MODULE,"BLOCKED","NONE","NONE","No native sanitize capability advertised.")
