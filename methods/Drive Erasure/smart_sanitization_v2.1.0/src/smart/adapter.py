from __future__ import annotations


def _qualified_command(device, key):
    command = device.caps().get(key)
    if not isinstance(command, list) or not command:
        raise ValueError(f"qualified backend command is required: {key}")
    return [str(x) for x in command]


def build_command(device, method):
    if method == "NVME_SANITIZE":
        return ["nvme", "sanitize", device.path, "--sanact=0x02", "--wait"]
    if method == "ATA_SECURE_ERASE":
        return _qualified_command(device, "ata_secure_erase_command")
    if method == "CRYPTOGRAPHIC_ERASE":
        return _qualified_command(device, "crypto_erase_command")
    if method == "VERIFIED_OVERWRITE":
        return _qualified_command(device, "overwrite_command")
    raise ValueError(f"unsupported smart sanitization method: {method}")


def verification_command(device, method):
    if method == "NVME_SANITIZE":
        return ["nvme", "sanitize-log", device.path, "-o", "json"]
    if method == "ATA_SECURE_ERASE":
        return _qualified_command(device, "ata_verify_command")
    if method == "CRYPTOGRAPHIC_ERASE":
        return _qualified_command(device, "crypto_verify_command")
    if method == "VERIFIED_OVERWRITE":
        return _qualified_command(device, "overwrite_verify_command")
    raise ValueError(f"unsupported smart verification method: {method}")
