from .models import Plan, Device

MODULE = "Verified Overwrite"
FLASH = {"SSD", "NVME", "FLASH", "EMMC", "UFS"}


def validate(d):
    if d.mounted:
        return Plan(MODULE, "BLOCKED", "NONE", "NONE", "Target is mounted; offline execution required.", warnings=("mounted_target",))
    if d.system_disk:
        return Plan(MODULE, "BLOCKED", "NONE", "NONE", "Current system disk is protected.", warnings=("system_disk",))
    if not isinstance(d.path, str) or not d.path:
        return Plan(MODULE, "BLOCKED", "NONE", "NONE", "Invalid target path.")
    if d.size_bytes < 0:
        return Plan(MODULE, "BLOCKED", "NONE", "NONE", "Invalid capacity.")
    return None


def plan(d, requested="best"):
    bad = validate(d)
    if bad:
        return bad
    allow_flash = isinstance(requested, dict) and requested.get("allow_flash", False)
    media = d.media_type.upper()
    if media in FLASH and not allow_flash:
        return Plan(MODULE, "BLOCKED", "NONE", "NONE", "Host overwrite is rejected for flash/wear-leveled media by default; use a device-native purge method.", warnings=("use-native-sanitize",))
    # NIST SP 800-88 Rev.2 does not require legacy multi-pass overwrite.
    # One complete overwrite pass followed by verification is the default here.
    return Plan(MODULE, "PLANNED", "HOST_OVERWRITE", "CLEAR", "Overwrite the addressable target once and verify every written chunk.", ("random",), ("chunk read-back", "final digest"))
