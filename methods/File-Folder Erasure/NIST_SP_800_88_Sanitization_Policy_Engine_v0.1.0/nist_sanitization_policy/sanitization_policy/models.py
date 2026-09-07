from __future__ import annotations
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Any


class MediaType(str, Enum):
    HDD = "hdd"
    SSD = "ssd"
    NVME = "nvme"
    USB_FLASH = "usb_flash"
    SD_CARD = "sd_card"
    OPTICAL = "optical"
    VIRTUAL = "virtual"
    UNKNOWN = "unknown"


class Assurance(str, Enum):
    CLEAR = "clear"
    PURGE = "purge"


class Scope(str, Enum):
    FILE = "file"
    FOLDER = "folder"
    LOGICAL_VOLUME = "logical_volume"
    NAMESPACE = "namespace"
    FULL_MEDIA = "full_media"


class Capability(str, Enum):
    CRYPTO_ERASE = "crypto_erase"
    NVME_SANITIZE = "nvme_sanitize"
    NVME_FORMAT_CRYPTO = "nvme_format_crypto"
    NVME_FORMAT_USER = "nvme_format_user"
    ATA_SECURE_ERASE = "ata_secure_erase"
    ATA_ENHANCED_SECURE_ERASE = "ata_enhanced_secure_erase"
    DEVICE_SANITIZE = "device_sanitize"
    VERIFIED_OVERWRITE = "verified_overwrite"
    READBACK = "readback"
    KEY_ZEROIZATION = "key_zeroization"


class SanitizationMethod(str, Enum):
    CRYPTOGRAPHIC_ERASE = "cryptographic_erase"
    NVME_SANITIZE_CRYPTO = "nvme_sanitize_crypto"
    NVME_SANITIZE_BLOCK = "nvme_sanitize_block"
    NVME_SANITIZE_OVERWRITE = "nvme_sanitize_overwrite"
    ATA_SECURE_ERASE = "ata_secure_erase"
    ATA_ENHANCED_SECURE_ERASE = "ata_enhanced_secure_erase"
    DEVICE_NATIVE_SANITIZE = "device_native_sanitize"
    VERIFIED_OVERWRITE = "verified_overwrite"
    MANUAL_REVIEW = "manual_review"


@dataclass(frozen=True)
class SanitizationRequest:
    media_type: MediaType
    assurance: Assurance
    scope: Scope
    capabilities: frozenset[Capability] = field(default_factory=frozenset)
    encrypted: bool = False
    key_management_verified: bool = False
    transport: str = "unknown"
    device_model: str | None = None
    controller_trusted: bool = False
    verification_available: bool = False
    device_locked: bool = False
    boot_media: bool = False
    notes: tuple[str, ...] = ()

    @staticmethod
    def from_dict(data: dict[str, Any]) -> "SanitizationRequest":
        return SanitizationRequest(
            media_type=MediaType(data["media_type"]),
            assurance=Assurance(data["assurance"]),
            scope=Scope(data["scope"]),
            capabilities=frozenset(Capability(x) for x in data.get("capabilities", [])),
            encrypted=bool(data.get("encrypted", False)),
            key_management_verified=bool(data.get("key_management_verified", False)),
            transport=str(data.get("transport", "unknown")),
            device_model=data.get("device_model"),
            controller_trusted=bool(data.get("controller_trusted", False)),
            verification_available=bool(data.get("verification_available", False)),
            device_locked=bool(data.get("device_locked", False)),
            boot_media=bool(data.get("boot_media", False)),
            notes=tuple(data.get("notes", [])),
        )


@dataclass(frozen=True)
class SanitizationDecision:
    method: SanitizationMethod
    assurance: Assurance
    confidence: str
    rationale: tuple[str, ...]
    warnings: tuple[str, ...]
    verification: tuple[str, ...]
    prerequisites: tuple[str, ...]
    rejected_methods: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        for key in ("rationale", "warnings", "verification", "prerequisites", "rejected_methods"):
            d[key] = list(d[key])
        return d
