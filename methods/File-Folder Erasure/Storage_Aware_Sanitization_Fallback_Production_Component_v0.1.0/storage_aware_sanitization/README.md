# Storage-Aware Sanitization & Fallback

Production-oriented policy and execution component for selecting the safest
technology-appropriate sanitization path for HDD, SATA SSD, NVMe, USB/removable,
encrypted and unknown storage.

## Core design

The component separates:

1. **Discovery** — identify transport/media and advertised sanitize capabilities.
2. **Policy** — select an appropriate sanitization technique.
3. **Plan** — produce the exact native command or logical fallback.
4. **Guardrails** — require explicit execution confirmation.
5. **Execution** — optional adapter invocation for supported native tools.
6. **Verification** — consume native completion/status and record evidence.
7. **Fallback** — refuse unsafe degradation instead of silently choosing a weaker method.

This is deliberately NOT a blind "try commands until one works" eraser.

## Policy hierarchy

Typical preference:

NVMe with Crypto Erase
    -> NVMe Sanitize Crypto Erase

NVMe with Block Erase
    -> NVMe Sanitize Block Erase

NVMe with Overwrite
    -> NVMe Sanitize Overwrite

ATA/SATA with supported device-native secure erase
    -> ATA Secure Erase / vendor-approved sanitize

Self-encrypting media with trustworthy key-management path
    -> Cryptographic Erasure

Suitable HDD without stronger native mechanism
    -> approved logical overwrite

Unsupported/ambiguous device
    -> REFUSE

The policy engine does not claim that generic file deletion or free-space wiping is
equivalent to whole-device purge.

## Native command adapters

The planner can generate commands for:
- nvme-cli `nvme sanitize` crypto erase / block erase / overwrite;
- nvme-cli format secure erase settings;
- hdparm ATA security erase;
- sg3_utils / SCSI sanitize (command plan interface);
- logical overwrite fallback.

The actual command runner is opt-in and only executes a plan after the exact target
confirmation is supplied. Tests never touch real block devices.

## Important

Native sanitization can destroy an entire device's user data. Do not point the executor
at a production device unless the device identity and authorization have been independently
verified.

NVMe `sanitize` and `format --ses` are device-level operations. nvme-cli documents crypto
erase as deletion of the encryption key and states that secure erase applies to user data
including data in deallocated LBAs/cache. See docs/RESEARCH.md.

## Test

    python -m pytest -q tests
