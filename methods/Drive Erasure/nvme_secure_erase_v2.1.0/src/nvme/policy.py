from .models import Plan,Device
MODULE='NVMe Secure Erase'
def validate(d):
    if d.mounted: return Plan(MODULE,"BLOCKED","NONE","NONE","Target is mounted; offline execution required.",warnings=("mounted_target",))
    if d.system_disk: return Plan(MODULE,"BLOCKED","NONE","NONE","Current system disk is protected.",warnings=("system_disk",))
    if d.size_bytes<0: return Plan(MODULE,"BLOCKED","NONE","NONE","Invalid capacity.")
    return None

def plan(d,requested="best"):
    bad=validate(d)
    if bad: return bad
    if d.media_type.upper()!="NVME": return Plan(MODULE,"BLOCKED","NONE","NONE","Target is not NVMe.")
    c=d.caps()
    if not c.get("nvme_sanitize"): return Plan(MODULE,"BLOCKED","NONE","NONE","NVMe Sanitize is not advertised.")
    action=requested if requested in ("block","crypto","overwrite") else ("block" if c.get("block_erase") else "crypto" if c.get("crypto_erase") else "overwrite" if c.get("overwrite") else "")
    if not action: return Plan(MODULE,"BLOCKED","NONE","NONE","No supported Sanitize action advertised.")
    code={"block":"0x02","overwrite":"0x03","crypto":"0x04"}[action]
    return Plan(MODULE,"PLANNED",f"NVME_SANITIZE_{action.upper()}","PURGE",f"NVMe Sanitize {action} selected from controller capability.",(f"nvme sanitize {{controller}} --sanact={code} --wait",),("sanitize-log completion","identity"))
