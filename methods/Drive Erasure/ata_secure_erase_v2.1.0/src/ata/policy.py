from .models import Plan,Device
MODULE='ATA Secure Erase'
def validate(d):
    if d.mounted: return Plan(MODULE,"BLOCKED","NONE","NONE","Target is mounted; offline execution required.",warnings=("mounted_target",))
    if d.system_disk: return Plan(MODULE,"BLOCKED","NONE","NONE","Current system disk is protected.",warnings=("system_disk",))
    if d.size_bytes<0: return Plan(MODULE,"BLOCKED","NONE","NONE","Invalid capacity.")
    return None

def plan(d,requested="best"):
    bad=validate(d)
    if bad: return bad
    if d.media_type.upper() not in ("SATA","HDD","SSD"): return Plan(MODULE,"BLOCKED","NONE","NONE","Target is not ATA/SATA.")
    c=d.caps()
    if not c.get("ata_secure_erase"): return Plan(MODULE,"BLOCKED","NONE","NONE","ATA Security Erase is not advertised.")
    if c.get("frozen"): return Plan(MODULE,"BLOCKED","NONE","NONE","ATA security is frozen; approved offline unfreeze procedure required.")
    if c.get("security_enabled"): return Plan(MODULE,"BLOCKED","NONE","NONE","Security is already enabled; do not guess or replace an unknown credential.")
    method="ATA_SECURITY_ERASE_ENHANCED" if c.get("enhanced") and requested!="standard" else "ATA_SECURITY_ERASE"
    return Plan(MODULE,"PLANNED",method,"PURGE","ATA Security Erase Unit selected.",("security-set-password","security-erase-unit","security-disable"),("re-identify","security-disabled"))
