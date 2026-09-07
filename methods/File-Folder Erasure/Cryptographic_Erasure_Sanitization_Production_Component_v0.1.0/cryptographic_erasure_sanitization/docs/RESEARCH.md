# Deep research — Cryptographic Erasure

## NIST SP 800-88 Rev. 2

NIST defines cryptographic erase (CE) as a purge sanitization technique in which key
sanitization is applied to one or more keys that protect encrypted target data, making
recovery of decrypted data infeasible. NIST SP 800-88 Rev. 2 also adds guidance around
key types, ISO/IEC 19790-style zeroization, validation, and when externally managed
keys may be acceptable.

This is the foundation of this module: CE is a **key lifecycle operation**, not a
file overwrite operation.

## cryptsetup / LUKS2

Linux cryptsetup provides `erase` / `luksErase` to erase all LUKS keyslots. Its manual
states that this removes the volume key and makes the encrypted data permanently
irretrievable in the normal case, while also clearly warning that it does not wipe the
encrypted data area. The same documentation distinguishes removal of one keyslot from
destruction of all keyslots.

Design lesson: our module must report the distinction between destroying a key and
overwriting ciphertext.

## Apple Data Protection

Apple documents a key hierarchy for Data Protection. On supported Apple devices,
"Erase All Content and Settings" obliterates keys in effaceable storage and renders
user data cryptographically inaccessible. Modern Apple platforms also use per-file,
per-extent and volume key hierarchies.

Design lesson: CE can operate at different key hierarchy levels. Destroying one
wrapping key is not enough if another independently usable key remains.

## Microsoft BitLocker

Microsoft documents BitLocker recovery keys and their storage in Microsoft Entra ID,
AD DS and other recovery locations. This shows why enterprise CE must account for
externally managed recovery/key material rather than treating a local key deletion as
complete sanitization.

Design lesson: key inventory and custody are part of the assurance boundary.

## NVMe / self-encrypting storage

Modern self-encrypting devices can implement cryptographic erase at the controller
level. A software CE engine should therefore distinguish:
- application envelope-key destruction;
- filesystem/volume encryption-key destruction;
- controller-native crypto erase.

The higher-level storage-aware policy module should select the strongest appropriate
mechanism.

## Software researched

1. NIST SP 800-88 Rev. 2 — policy and CE definition.
2. cryptsetup/LUKS2 — open-source Linux keyslot/key-destruction implementation.
3. Apple Data Protection / Erase All Content and Settings — hardware-backed key hierarchy.
4. Microsoft BitLocker — enterprise recovery-key lifecycle.
5. NVMe sanitization concepts — controller-native crypto erase.

No proprietary source is copied into this component.

## Production assurance boundary

The bundled LocalKeyStore is a reference/test backend. It demonstrates the exact CE
mechanism and verification model but cannot provide HSM-grade guarantees about every
physical memory/storage copy of a key.

For a commercial deployment, implement KeyStore against:
- an enterprise HSM/KMS;
- authenticated key-destruction APIs;
- independent tamper-evident audit logs;
- key inventory and version tracking;
- backup/replica destruction;
- separation of duties;
- attested destruction where supported.

The policy engine should refuse to claim CE when the key hierarchy or all copies cannot
be established.
