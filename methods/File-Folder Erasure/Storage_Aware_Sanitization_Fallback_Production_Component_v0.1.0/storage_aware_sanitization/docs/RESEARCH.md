# Deep research — Storage-Aware Sanitization & Fallback

## NIST SP 800-88 Rev. 2

NIST SP 800-88 Rev. 2 is the current final revision (September 2025). NIST defines
sanitization as rendering access to target data on media infeasible for a given level
of effort. Rev. 2 shifted the detailed method/tool discussion toward IEEE 2883,
NSA specifications, or an organization-approved standard, while expanding guidance
for cryptographic erase and trust in vendor implementations.

Engineering consequence: this module is a policy/assurance layer. It should select
a technology-appropriate purge method and record the device/vendor evidence rather
than assuming that one overwrite algorithm works for all storage.

## NVMe / nvme-cli

The current nvme-cli documentation exposes NVMe Sanitize actions:
- start-block-erase
- start-overwrite
- start-crypto-erase

It also provides wait and media-verification related options. The documentation
states that Crypto Erase is a Sanitize Action and that the command returns success or
an error code. The NVMe format command additionally documents Secure Erase Settings:
User Data Erase and Cryptographic Erase. It states that secure erase applies to user
data regardless of location, including exposed LBA, cache and deallocated LBAs.

This is the preferred path when the controller advertises the required capability.

## ATA / SATA

The storage-aware policy recognizes ATA Secure Erase as a device-native path. The
actual production adapter must use a carefully reviewed ATA implementation and account
for frozen security state, enhanced erase capability, device identity and command
completion. The policy deliberately does not silently fall back to ordinary file
deletion.

## SCSI / SAS

SCSI sanitize is recognized as a separate native capability. A production adapter
should use sg3_utils or an equivalent reviewed implementation and collect sanitize
status/result information.

## nwipe

nwipe's SSD guide emphasizes vendor/model-specific support and recommends validating
sanitization results rather than blindly trusting a tool. It also distinguishes
manufacturer tools, hdparm, sg_utils and nvme-cli depending on interface/vendor.

Engineering consequence: capability discovery must include exact device identity,
firmware/vendor and advertised command support.

## Vendor tools

Vendor-specific tools may be required where generic standards are unavailable or
where the vendor documents a particular sanitize procedure. NIST Rev. 2 explicitly
emphasizes trust establishment in vendor implementations.

The policy therefore supports a "Vendor-Native Sanitization" state that requires a
validated adapter rather than inventing a generic command.

## HDD fallback

For HDD, if no stronger device-native purge is available, an organization may approve
a logical overwrite path. This module does NOT bundle the raw-disk writer here because
the higher-level Secure Drive Eraser should own that implementation and its verification.

If the policy does not explicitly approve that fallback, the result is REFUSE.

## SSD/NVMe and ordinary overwrite

Ordinary logical overwriting is not automatically equivalent to device purge on
flash media because of translation layers, over-provisioning and remapping. Therefore
SSD/NVMe should prefer native sanitize or cryptographic erase where available.

## USB/removable storage

USB is an interface, not a media technology. A USB enclosure may contain HDD, SATA SSD,
NVMe or another device, and the enclosure may or may not expose the native sanitize
command. The policy therefore refuses to infer capabilities from "USB" alone.

## Verification

The policy records:
- selected method;
- target;
- device identity;
- advertised capabilities;
- command plan;
- execution result;
- fallback chain.

For device-native purge, verification should include native completion/status and,
where the approved standard requires it, post-sanitize validation. A successful process
exit alone is not treated as proof of physical destruction.

## Software researched

1. NIST SP 800-88 Rev. 2.
2. nvme-cli.
3. nwipe.
4. hdparm / ATA Secure Erase ecosystem.
5. sg3_utils / SCSI sanitize ecosystem.
6. vendor-specific SSD sanitization tools as documented by nwipe and NIST's trust model.

No proprietary commercial source is copied.
