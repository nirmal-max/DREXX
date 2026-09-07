from .models import Plan, Device

MODULE = 'NIST SP 800-88 Rev.2'


def validate(d):
    if d.mounted:
        return Plan(MODULE, "BLOCKED", "NONE", "NONE", "Target is mounted; offline execution required.", warnings=("mounted_target",))
    if d.system_disk:
        return Plan(MODULE, "BLOCKED", "NONE", "NONE", "Current system disk is protected.", warnings=("system_disk",))
    if d.size_bytes < 0:
        return Plan(MODULE, "BLOCKED", "NONE", "NONE", "Invalid capacity.")
    return None


def plan(d, requested="best"):
    bad = validate(d)
    if bad:
        return bad

    c = d.caps()
    assurance = requested if requested in ("CLEAR", "PURGE", "DESTROY") else "PURGE"

    if assurance == "DESTROY":
        if not c.get("destruction_equipment_qualified"):
            return Plan(MODULE, "BLOCKED", "NONE", "NONE", "Destroy requires qualified destruction equipment.")
        return Plan(
            MODULE, "PLANNED", "MEDIA_DESTRUCTION", "DESTROY",
            "Physical destruction is selected by policy; exact equipment qualification is required.",
            (), ("equipment attestation", "post-destruction evidence")
        )

    if assurance == "PURGE" and c.get("nist_qualified") and c.get("native_sanitize"):
        return Plan(
            MODULE, "PLANNED", "DEVICE_NATIVE_SANITIZE", "PURGE",
            "Qualified device-native sanitization is available.",
            (), ("native completion", "device identity", "post-operation validation")
        )

    if assurance == "PURGE" and c.get("nist_qualified") and c.get("crypto_erase") and c.get("key_management_qualified"):
        return Plan(
            MODULE, "PLANNED", "CRYPTOGRAPHIC_ERASE", "PURGE",
            "Qualified cryptographic erase is available with qualified key management.",
            (), ("key-destruction attestation", "key-management evidence", "post-operation validation")
        )

    if assurance == "CLEAR":
        if not c.get("clear_qualified"):
            return Plan(MODULE, "BLOCKED", "NONE", "NONE", "Clear requires an organization-approved qualified technique.")
        return Plan(
            MODULE, "PLANNED", "VERIFIED_OVERWRITE", "CLEAR",
            "Organization-approved Clear technique selected.",
            (), ("full read-back", "device identity", "post-operation validation")
        )

    return Plan(MODULE, "BLOCKED", "NONE", "NONE", "NIST Rev.2 requires an applicable qualified technique; no silent fallback.")
