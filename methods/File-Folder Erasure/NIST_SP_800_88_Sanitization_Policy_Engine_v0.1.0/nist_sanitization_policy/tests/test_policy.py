import json
from pathlib import Path
import pytest

from sanitization_policy import (
    Assurance, Capability, MediaType, Scope, SanitizationMethod,
    SanitizationRequest, evaluate
)


def req(**kw):
    base = dict(
        media_type=MediaType.HDD,
        assurance=Assurance.CLEAR,
        scope=Scope.FULL_MEDIA,
        capabilities=frozenset(),
    )
    base.update(kw)
    return SanitizationRequest(**base)


def test_encrypted_verified_key_prefers_ce():
    d = evaluate(req(
        media_type=MediaType.SSD,
        assurance=Assurance.PURGE,
        encrypted=True,
        key_management_verified=True,
        capabilities=frozenset({Capability.CRYPTO_ERASE, Capability.KEY_ZEROIZATION}),
    ))
    assert d.method == SanitizationMethod.CRYPTOGRAPHIC_ERASE
    assert d.confidence == "high"


def test_nvme_purge_uses_native_crypto_path():
    d = evaluate(req(
        media_type=MediaType.NVME,
        assurance=Assurance.PURGE,
        capabilities=frozenset({Capability.NVME_SANITIZE, Capability.NVME_FORMAT_CRYPTO}),
    ))
    assert d.method == SanitizationMethod.NVME_SANITIZE_CRYPTO
    assert "native" in " ".join(d.rationale).lower()


def test_nvme_clear_uses_native_path():
    d = evaluate(req(
        media_type=MediaType.NVME,
        assurance=Assurance.CLEAR,
        capabilities=frozenset({Capability.NVME_SANITIZE, Capability.NVME_FORMAT_USER}),
    ))
    assert d.method == SanitizationMethod.NVME_SANITIZE_BLOCK


def test_ata_enhanced_purge():
    d = evaluate(req(
        media_type=MediaType.SSD,
        assurance=Assurance.PURGE,
        capabilities=frozenset({Capability.ATA_SECURE_ERASE, Capability.ATA_ENHANCED_SECURE_ERASE}),
    ))
    assert d.method == SanitizationMethod.ATA_ENHANCED_SECURE_ERASE


def test_usb_bridge_warning():
    d = evaluate(req(
        media_type=MediaType.SSD,
        assurance=Assurance.PURGE,
        capabilities=frozenset({Capability.ATA_SECURE_ERASE}),
        transport="usb",
    ))
    assert d.method == SanitizationMethod.ATA_SECURE_ERASE
    assert any("USB" in x for x in d.warnings)


def test_flash_clear_can_fallback_to_overwrite_but_warns():
    d = evaluate(req(
        media_type=MediaType.USB_FLASH,
        assurance=Assurance.CLEAR,
        capabilities=frozenset({Capability.VERIFIED_OVERWRITE}),
    ))
    assert d.method == SanitizationMethod.VERIFIED_OVERWRITE
    assert any("flash" in x.lower() for x in d.warnings)


def test_purge_never_silently_downgrades_to_overwrite():
    d = evaluate(req(
        media_type=MediaType.SSD,
        assurance=Assurance.PURGE,
        capabilities=frozenset({Capability.VERIFIED_OVERWRITE}),
    ))
    assert d.method == SanitizationMethod.MANUAL_REVIEW
    assert any("downgrade" in x.lower() for x in d.warnings)


def test_unknown_no_capability_is_manual_review():
    d = evaluate(req(
        media_type=MediaType.UNKNOWN,
        assurance=Assurance.CLEAR,
    ))
    assert d.method == SanitizationMethod.MANUAL_REVIEW
    assert d.confidence == "low"


def test_boot_media_warning():
    d = evaluate(req(
        capabilities=frozenset({Capability.VERIFIED_OVERWRITE}),
        boot_media=True,
    ))
    assert any("boot media" in x.lower() for x in d.warnings)


def test_locked_device_warning():
    d = evaluate(req(
        capabilities=frozenset({Capability.VERIFIED_OVERWRITE}),
        device_locked=True,
    ))
    assert any("locked" in x.lower() for x in d.warnings)


def test_decision_serializes():
    d = evaluate(req(capabilities=frozenset({Capability.VERIFIED_OVERWRITE})))
    out = d.to_dict()
    assert out["method"] == "verified_overwrite"
    assert isinstance(out["verification"], list)
