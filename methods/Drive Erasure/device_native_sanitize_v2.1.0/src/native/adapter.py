from __future__ import annotations


def build_native_command(media_type: str, device: str, action: str):
    """Build a real device-native sanitization command."""
    if not isinstance(device, str) or not device or device.startswith("-"):
        raise ValueError("invalid device path")
    if not isinstance(action, str) or not action:
        raise ValueError("invalid sanitize action")

    m = media_type.upper()
    if m == "NVME":
        if action not in {"1", "2", "3", "4"}:
            raise ValueError("unsupported NVMe sanitize action")
        return ["nvme", "sanitize", device, f"--sanact={action}", "--wait"]

    if m in ("SATA", "HDD", "SSD"):
        mapping = {
            "block-erase": "--sanitize-block-erase",
            "overwrite": "--sanitize-overwrite",
            "crypto-erase": "--sanitize-crypto-scramble",
        }
        if action not in mapping:
            raise ValueError("unsupported ATA sanitize action")
        # hdparm requires explicit acknowledgement for ATA SANITIZE.
        if action == "overwrite":
            # A deterministic pattern is deliberately not invented here;
            # overwrite requires a caller-supplied pattern in a future API.
            raise ValueError("ATA sanitize overwrite requires an explicit pattern")
        return ["hdparm", "--yes-i-know-what-i-am-doing", mapping[action], device]

    if m in ("SAS", "SCSI"):
        mapping = {
            "block-erase": "--block",
            "overwrite": "--overwrite",
            "crypto-erase": "--crypto",
        }
        if action not in mapping:
            raise ValueError("unsupported SCSI sanitize action")
        # --quick removes the interactive reconsideration delay; DREX already
        # has an explicit arm gate before this function is reached.
        return ["sg_sanitize", mapping[action], "--quick", "--wait", device]

    raise ValueError("unsupported media")
