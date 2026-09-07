from __future__ import annotations
from .models import (
    Assurance, Capability, MediaType, SanitizationMethod,
    SanitizationRequest, SanitizationDecision, Scope
)


def _verification(req: SanitizationRequest, method: SanitizationMethod) -> tuple[str, ...]:
    items = [
        "Record the device identity, selected method, operator, timestamp and outcome.",
        "Capture command/device status returned by the execution adapter.",
    ]
    if method == SanitizationMethod.CRYPTOGRAPHIC_ERASE:
        items.append("Verify key destruction/zeroization according to the approved key-management procedure before declaring success.")
    elif req.verification_available:
        items.append("Perform the verification procedure required by the selected organizational/technology standard.")
    else:
        items.append("No independent read-back capability was declared; execution must not be reported as independently verified.")
    return tuple(items)


def evaluate(req: SanitizationRequest) -> SanitizationDecision:
    rationale: list[str] = []
    warnings: list[str] = []
    prerequisites: list[str] = []
    rejected: list[str] = []

    if req.boot_media:
        warnings.append("Target is boot media; execution requires an offline/live environment or another approved execution context.")

    if req.device_locked:
        warnings.append("Device is reported locked; execution adapter must establish the required administrative/device state before sanitization.")

    device_scope = req.scope in (Scope.LOGICAL_VOLUME, Scope.NAMESPACE, Scope.FULL_MEDIA)
    if not device_scope and req.assurance == Assurance.PURGE:
        warnings.append("Device-native purge methods are not valid for file/folder scope; the policy engine will not broaden the target scope.")
        warnings.append("Escalate to an approved file-level sanitization procedure or organizational review.")
        rationale.append("The requested purge scope is narrower than the media/device scope supported by this policy engine.")
        return SanitizationDecision(
            SanitizationMethod.MANUAL_REVIEW, req.assurance, "low", tuple(rationale), tuple(warnings),
            _verification(req, SanitizationMethod.MANUAL_REVIEW), tuple(prerequisites), tuple(rejected)
        )

    if device_scope and req.encrypted and req.key_management_verified and (
        Capability.CRYPTO_ERASE in req.capabilities or Capability.KEY_ZEROIZATION in req.capabilities
    ):
        rationale.extend([
            "The target is encrypted and the applicable key-destruction path has been verified.",
            "Cryptographic erase is therefore the primary candidate for the requested assurance level.",
        ])
        prerequisites.append("Validate that the encryption implementation and key hierarchy meet the organization's approved cryptographic-erase criteria.")
        return SanitizationDecision(
            SanitizationMethod.CRYPTOGRAPHIC_ERASE, req.assurance, "high", tuple(rationale), tuple(warnings),
            _verification(req, SanitizationMethod.CRYPTOGRAPHIC_ERASE), tuple(prerequisites), tuple(rejected)
        )

    # NVMe native sanitize. Never label an operation crypto-erase unless the
    # controller explicitly advertises the crypto-erase capability.
    if device_scope and req.media_type == MediaType.NVME and Capability.NVME_SANITIZE in req.capabilities:
        prerequisites.append("Query controller sanitize capabilities and status immediately before execution.")
        if req.assurance == Assurance.PURGE:
            if Capability.NVME_FORMAT_CRYPTO in req.capabilities:
                method = SanitizationMethod.NVME_SANITIZE_CRYPTO
                rationale.append("NVMe native cryptographic sanitization capability is explicitly available for purge.")
            elif Capability.NVME_FORMAT_USER in req.capabilities:
                method = SanitizationMethod.NVME_SANITIZE_BLOCK
                rationale.append("NVMe native block erase capability is explicitly available for purge.")
            else:
                warnings.append("NVMe Sanitize is present, but no approved purge-capable action was declared.")
                warnings.append("The policy engine will not invent a cryptographic or purge method from generic NVMe Sanitize support.")
                rationale.append("The declared NVMe capabilities do not establish a specific purge-capable operation.")
                return SanitizationDecision(
                    SanitizationMethod.MANUAL_REVIEW, req.assurance, "low", tuple(rationale), tuple(warnings),
                    _verification(req, SanitizationMethod.MANUAL_REVIEW), tuple(prerequisites), tuple(rejected)
                )
        else:
            method = SanitizationMethod.NVME_SANITIZE_BLOCK if Capability.NVME_FORMAT_USER in req.capabilities else SanitizationMethod.NVME_SANITIZE_OVERWRITE
            rationale.append("NVMe native sanitization is available and is preferred over host-level file overwriting.")
        return SanitizationDecision(
            method, req.assurance, "high", tuple(rationale), tuple(warnings),
            _verification(req, method), tuple(prerequisites), tuple(rejected)
        )

    if device_scope and req.media_type in (MediaType.SSD, MediaType.HDD) and Capability.ATA_SECURE_ERASE in req.capabilities:
        if req.assurance == Assurance.PURGE and Capability.ATA_ENHANCED_SECURE_ERASE in req.capabilities:
            method = SanitizationMethod.ATA_ENHANCED_SECURE_ERASE
            rationale.append("ATA enhanced native erase is available and is preferred for the requested purge assurance.")
        else:
            method = SanitizationMethod.ATA_SECURE_ERASE
            rationale.append("ATA native erase is available and is preferred to host-level overwrite where the device implementation is approved.")
        prerequisites.extend([
            "Confirm ATA security state and that the command is supported by the device and transport.",
            "Do not assume ATA commands will pass through an arbitrary USB bridge.",
        ])
        if req.transport.lower() in {"usb", "usb_bridge"}:
            warnings.append("USB bridges can block or alter ATA security commands; direct device access is preferred.")
        return SanitizationDecision(
            method, req.assurance, "high", tuple(rationale), tuple(warnings),
            _verification(req, method), tuple(prerequisites), tuple(rejected)
        )

    if device_scope and Capability.DEVICE_SANITIZE in req.capabilities:
        rationale.append("A device-native sanitization capability is declared; use the vendor/technology-specific approved implementation.")
        prerequisites.append("Establish trust in the device sanitization implementation and record its capability/status evidence.")
        return SanitizationDecision(
            SanitizationMethod.DEVICE_NATIVE_SANITIZE, req.assurance, "medium-high", tuple(rationale), tuple(warnings),
            _verification(req, SanitizationMethod.DEVICE_NATIVE_SANITIZE), tuple(prerequisites), tuple(rejected)
        )

    if req.assurance == Assurance.CLEAR and Capability.VERIFIED_OVERWRITE in req.capabilities:
        if req.media_type in (MediaType.SSD, MediaType.NVME, MediaType.USB_FLASH, MediaType.SD_CARD):
            warnings.append("Host overwrite on flash/non-volatile solid-state media may not reach remapped or over-provisioned media; do not treat it as purge.")
        rationale.append("No suitable native mechanism was declared; verified host overwrite is available as a clear-level fallback.")
        prerequisites.append("Use an organizationally approved overwrite implementation and verify according to the governing procedure.")
        return SanitizationDecision(
            SanitizationMethod.VERIFIED_OVERWRITE, req.assurance, "medium", tuple(rationale), tuple(warnings),
            _verification(req, SanitizationMethod.VERIFIED_OVERWRITE), tuple(prerequisites), tuple(rejected)
        )

    warnings.append("No supported, sufficiently evidenced sanitization path was declared.")
    warnings.append("The policy engine will not silently downgrade a purge request to host overwrite.")
    if req.assurance == Assurance.PURGE:
        warnings.append("Escalate to an approved device-specific purge procedure or organizational review.")
    rationale.append("Available capabilities do not establish an appropriate method for the requested assurance.")
    return SanitizationDecision(
        SanitizationMethod.MANUAL_REVIEW, req.assurance, "low", tuple(rationale), tuple(warnings),
        _verification(req, SanitizationMethod.MANUAL_REVIEW), tuple(prerequisites), tuple(rejected)
    )
