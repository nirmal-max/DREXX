import os
import shutil


class AdapterError(RuntimeError):
    pass


def _require_qualified(device, method):
    caps = device.caps()
    if not caps.get("nist_qualified"):
        raise AdapterError("NIST execution requires explicit nist_qualified capability")
    if method in ("DEVICE_NATIVE_SANITIZE", "CRYPTOGRAPHIC_ERASE") and not caps.get("native_sanitize") and not caps.get("crypto_erase"):
        raise AdapterError("Selected native method is not qualified for this device")
    if method == "MEDIA_DESTRUCTION" and not caps.get("destruction_equipment_qualified"):
        raise AdapterError("Destruction equipment is not qualified")


def build_command(device, method):
    """Build a destructive command without executing it.

    The caller must supply a device path and explicit qualification metadata.
    Commands are deliberately returned as argv lists to avoid shell injection.
    """
    _require_qualified(device, method)
    path = device.path
    media = device.media_type.upper()

    if method == "DEVICE_NATIVE_SANITIZE":
        if media == "NVME":
            return ["nvme", "sanitize", path, "-a", "2"]
        if media in ("SATA", "ATA", "HDD", "SSD"):
            return ["hdparm", "--sanitize-block-erase", path]
        if media in ("SAS", "SCSI"):
            return ["sg_sanitize", "--block", path]
        raise AdapterError(f"Unsupported media type for native sanitize: {media}")

    if method == "CRYPTOGRAPHIC_ERASE":
        command = device.caps().get("crypto_erase_command")
        if not isinstance(command, list) or not command:
            raise AdapterError("Qualified cryptographic erase command is required")
        return command

    if method == "VERIFIED_OVERWRITE":
        # Organization-approved Clear implementation. The runner performs the
        # overwrite and verification only when explicit destructive execution
        # is enabled. Do not use this path for Purge assurance.
        if not shutil.which("dd"):
            raise AdapterError("dd is required for the approved Clear overwrite path")
        return ["dd", "if=/dev/zero", f"of={path}", "bs=4M", "status=progress", "conv=fsync"]

    if method == "MEDIA_DESTRUCTION":
        command = device.caps().get("destruction_command")
        if not isinstance(command, list) or not command:
            raise AdapterError("Qualified destruction command is required")
        return command

    raise AdapterError(f"Unsupported NIST method: {method}")


def execution_allowed():
    return os.environ.get("DREX_ALLOW_DESTRUCTIVE") == "1"
