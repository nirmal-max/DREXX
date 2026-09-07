from .models import Plan,Device
MODULE='Smart Sanitization'

def validate(d):
    if d.mounted: return Plan(MODULE,"BLOCKED","NONE","NONE","Target is mounted; offline execution required.",warnings=("mounted_target",))
    if d.system_disk: return Plan(MODULE,"BLOCKED","NONE","NONE","Current system disk is protected.",warnings=("system_disk",))
    if d.size_bytes<0: return Plan(MODULE,"BLOCKED","NONE","NONE","Invalid capacity.")
    return None

def plan(d,requested="best"):
    bad=validate(d)
    if bad: return bad
    c=d.caps()
    if c.get("native_sanitize"):
        return Plan(MODULE,"BLOCKED","NONE","NONE","Legacy native-sanitize backend is not an executable; use a qualified technology-specific backend.",warnings=("invalid_backend",))
    if d.media_type.upper()=="NVME" and c.get("nvme_sanitize"):
        return Plan(MODULE,"PLANNED","NVME_SANITIZE","PURGE","NVMe Sanitize is advertised.",("nvme sanitize",),("sanitize-log",))
    if d.media_type.upper() in ("SATA","HDD","SSD") and c.get("ata_secure_erase") and c.get("ata_backend_qualified"):
        return Plan(MODULE,"PLANNED","ATA_SECURE_ERASE","PURGE","Qualified ATA Security Erase backend is advertised.",("qualified ATA erase",),("qualified ATA verification",))
    if c.get("crypto_erase") and c.get("crypto_backend_qualified"):
        return Plan(MODULE,"PLANNED","CRYPTOGRAPHIC_ERASE","PURGE","Qualified cryptographic erase backend is advertised.",("key-destruction",),("key-provider attestation",))
    if d.media_type.upper() in ("HDD","USB","SD") and requested in ("best","overwrite") and c.get("overwrite_backend_qualified"):
        return Plan(MODULE,"PLANNED","VERIFIED_OVERWRITE","CLEAR","Qualified host-overwrite backend is advertised.",("qualified overwrite",),("read-back",))
    return Plan(MODULE,"BLOCKED","NONE","NONE","No qualified method advertised; refuse silent downgrade.")
