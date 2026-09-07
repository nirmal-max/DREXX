from __future__ import annotations


def build_command(device, method):
    """Build a qualified native purge command for a Device.

    IEEE 2883 is a policy/qualification layer; it must not invent a
    ``native-sanitize`` executable. The caller's capability record must
    explicitly attest that the selected native technique is qualified.
    """
    path = device.path
    media = device.media_type.upper()
    caps = device.caps()

    if not caps.get("purge_qualified"):
        raise ValueError("device is not marked as IEEE-qualified for purge")

    if method == "DEVICE_NATIVE_SANITIZE":
        action = caps.get("purge_action", "crypto").lower()
        if media == "NVME":
            actions = {"block": "2", "crypto": "4"}
            if action not in actions:
                raise ValueError("unsupported NVMe purge action")
            return ["nvme", "sanitize", path, f"--sanact={actions[action]}", "--wait"]
        if media in ("SATA", "ATA", "HDD", "SSD"):
            if action == "crypto":
                return ["hdparm", "--sanitize-crypto-scramble", path]
            if action == "block":
                return ["hdparm", "--sanitize-block-erase", path]
            raise ValueError("unsupported ATA purge action")
        if media in ("SAS", "SCSI"):
            if action == "crypto":
                return ["sg_sanitize", "--crypto", path]
            if action == "block":
                return ["sg_sanitize", "--block", path]
            raise ValueError("unsupported SCSI purge action")
        raise ValueError(f"unsupported media type: {media}")

    if method == "CRYPTOGRAPHIC_ERASE":
        command = caps.get("crypto_erase_command")
        if not isinstance(command, (list, tuple)) or not command:
            raise ValueError("qualified cryptographic erase command is required")
        if "{device}" not in command:
            raise ValueError("crypto_erase_command must contain {device}")
        return [str(x).replace("{device}", path) for x in command]

    raise ValueError(f"unsupported purge method: {method}")


def build_verification_command(device, method):
    media = device.media_type.upper()
    caps = device.caps()
    custom = caps.get("verification_command")
    if isinstance(custom, (list, tuple)) and custom:
        if "{device}" not in custom:
            raise ValueError("verification_command must contain {device}")
        return [str(x).replace("{device}", device.path) for x in custom]

    if method == "DEVICE_NATIVE_SANITIZE":
        if media == "NVME":
            return ["nvme", "sanitize-log", device.path]
        if media in ("SATA", "ATA", "HDD", "SSD"):
            return ["hdparm", "--sanitize-status", device.path]
        if media in ("SAS", "SCSI"):
            raise ValueError("SCSI purge requires an explicit qualified verification command")
    raise ValueError("no qualified verification command")
