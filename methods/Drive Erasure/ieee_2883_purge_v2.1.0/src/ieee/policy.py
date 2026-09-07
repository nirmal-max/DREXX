from .models import Plan,Device
MODULE='IEEE 2883 Purge'
def validate(d):
    if d.mounted: return Plan(MODULE,"BLOCKED","NONE","NONE","Target is mounted; offline execution required.",warnings=("mounted_target",))
    if d.system_disk: return Plan(MODULE,"BLOCKED","NONE","NONE","Current system disk is protected.",warnings=("system_disk",))
    if d.size_bytes<0: return Plan(MODULE,"BLOCKED","NONE","NONE","Invalid capacity.")
    return None

def plan(d,requested="best"):
    bad=validate(d)
    if bad: return bad
    c=d.caps()
    if c.get("purge_qualified") and c.get("native_sanitize"): return Plan(MODULE,"PLANNED","DEVICE_NATIVE_SANITIZE","PURGE","Device-native technique is explicitly qualified for the target technology.",(),("native completion","technology-specific validation"))
    if c.get("crypto_erase") and c.get("key_management_qualified"): return Plan(MODULE,"PLANNED","CRYPTOGRAPHIC_ERASE","PURGE","Qualified cryptographic sanitization path is available.",(),("key destruction","key-provider attestation"))
    return Plan(MODULE,"BLOCKED","NONE","NONE","No technology-specific IEEE-qualified Purge technique is available.")
