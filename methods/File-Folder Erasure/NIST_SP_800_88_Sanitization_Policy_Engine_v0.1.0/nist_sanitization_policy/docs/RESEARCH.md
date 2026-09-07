# Research summary — NIST SP 800-88 Rev. 2 policy layer

## 1. NIST

NIST SP 800-88 Rev. 2 was published in September 2025 and supersedes Rev. 1.
Its emphasis is a media-sanitization program rather than a fixed cookbook of
overwrite passes. NIST states that, except for cryptographic erase, sanitization
technique details are replaced by recommendations to comply with IEEE 2883,
NSA specifications, or an organizationally approved standard.

**Design consequence:** the engine must decide *which approved technology-specific
procedure should be invoked*, rather than pretending that one overwrite algorithm
is universally "NIST compliant".

## 2. IEEE 2883

IEEE 2883-2022 is an active standard for sanitizing logical and physical storage
and includes technology-specific requirements. IEEE also lists IEEE 2883.1-2025,
a recommended practice for using storage sanitization methods.

**Design consequence:** technology-specific adapters should live outside this
policy engine and carry their own evidence/approval metadata.

## 3. Microsoft SDelete

SDelete demonstrates a mature Windows implementation for secure file deletion and
free-space cleansing. Microsoft documents allocation-based free-space cleansing
and explicitly notes limitations around NTFS directory/free-name remnants.

**Design consequence:** free-space wiping and metadata handling cannot be reduced
to a generic "write zeros to a file" routine.

## 4. nvme-cli

The official open-source nvme-cli project exposes NVMe Sanitize actions:
block erase, overwrite, crypto erase, exit failure mode, and media-verification
state handling. It also supports status/result reporting.

**Design consequence:** the NVMe adapter should use controller-native sanitize
capabilities when available instead of treating NVMe like an HDD.

## 5. DriveWipe

DriveWipe is an open-source project advertising NIST SP 800-88 Rev. 2 /
IEEE 2883 alignment, device-native methods, verification, audit records, and
multiple platform interfaces.

**Design consequence:** its architecture is useful as a reference for separating
policy, device capability detection, execution, verification, reporting and UI.
Its source must still be independently reviewed for license, correctness,
security and project-specific requirements before reuse.

## 6. Eraser

Eraser is a long-running open-source Windows secure-erasure project. Its source
contains an erasure-method plugin abstraction and many historical overwrite
algorithms.

**Design consequence:** historical multi-pass algorithms should be treated as
reference/compatibility methods, not automatically promoted to current NIST
Rev. 2 recommendations.

## 7. Safety conclusion

The policy engine intentionally refuses to map:

PURGE -> host overwrite

when no supported native/cryptographic mechanism is established.

This is a deliberate safety property. A commercial product should never generate
a certificate that claims purge-level sanitization merely because a logical
overwrite completed successfully.
